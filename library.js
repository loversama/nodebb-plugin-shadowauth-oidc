'use strict';

((module) => {
    const User = require.main.require('./src/user');
    const Groups = require.main.require('./src/groups');
    const db = require.main.require('./src/database');
    const authenticationController = require.main.require('./src/controllers/authentication');
    const Settings = require.main.require('./src/settings');
    const nconf = require.main.require('nconf');
    const winston = require.main.require('winston');
    const passport = module.parent.require('passport');
    const jwt = require('jsonwebtoken');
    const async = require('async');
    const { PassportOIDC } = require('./src/passport-shadowauth-oidc');

    const constants = {
        name: 'shadowauth-oidc',
        callbackURL: '/auth/shadowauth-oidc/callback',
        pluginSettingsURL: '/admin/plugins/shadowauth-oidc',
        pluginSettings: new Settings('shadowauth-oidc', '1.0.0', {
            // Default settings
            clientId: '',
            clientSecret: '',
            emailClaim: 'email',
            discoveryBaseURL: '',
            authorizationEndpoint: '',
            tokenEndpoint: '',
            userInfoEndpoint: '',
            publicKey: '', // Add public key setting for JWT verification
        }, false, false),
    };

    const Oidc = {};

    /**
     * Sets up the router bindings for the settings page
     * @param params
     * @param callback
     */
    Oidc.init = function (params, callback) {
        winston.verbose('Setting up shadowauth OIDC bindings/routes');

        function render(req, res) {
            res.render('admin/plugins/shadowauth-oidc', {
                baseUrl: nconf.get('url'),
            });
        }

        params.router.get(constants.pluginSettingsURL, params.middleware.admin.buildHeader, render);
        params.router.get('/api/admin/plugins/shadowauth-oidc', render);

        // Add the API authentication route
        params.router.post('/api/auth/shadowauth-oidc', Oidc.apiAuthenticate);

        callback();
    };

    /**
     * Binds the passport strategy to the global passport object
     * @param strategies The global list of strategies
     * @param callback
     */
    Oidc.bindStrategy = function (strategies, callback) {
        winston.verbose('Setting up OpenID Connect');

        callback = callback || function () { };

        constants.pluginSettings.sync(function (err) {
            if (err) {
                return callback(err);
            }

            const settings = constants.pluginSettings.getWrapper();

            // If we are missing any settings
            if (!settings.clientId ||
                !settings.clientSecret ||
                !settings.emailClaim ||
                !settings.authorizationEndpoint ||
                !settings.tokenEndpoint ||
                !settings.userInfoEndpoint) {
                winston.info('OpenID Connect will not be available until it is configured!');
                return callback(null, strategies);
            }

            settings.callbackURL = nconf.get('url') + constants.callbackURL;

            // If you call this twice it will overwrite the first.
            passport.use(constants.name, new PassportOIDC(settings, (req, accessToken, refreshToken, profile, callback) => {
                const email = profile[settings.emailClaim || 'email'];
                const isAdmin = settings.rolesClaim ? (profile[settings.rolesClaim] === 'admin' || (profile[settings.rolesClaim] && profile[settings.rolesClaim].some && profile[settings.rolesClaim].some((value) => value === 'admin'))) : false;
                Oidc.login({
                    oAuthid: profile.sub,
                    username: profile.preferred_username || email.split('@')[0],
                    email: email,
                    rolesEnabled: settings.rolesClaim && settings.rolesClaim.length !== 0,
                    isAdmin: isAdmin,
                }, (err, user) => {
                    if (err) {
                        return callback(err);
                    }

                    authenticationController.onSuccessfulLogin(req, user.uid);
                    callback(null, user);
                });
            }));

            // If we are doing the update, strategies won't be the right object so
            if (strategies.push) {
                strategies.push({
                    name: constants.name,
                    url: '/auth/' + constants.name,
                    callbackURL: '/auth/' + constants.name + '/callback',
                    icon: 'fa-openid',
                    scope: ['openid', settings.emailClaim],
                });
            }

            callback(null, strategies);
        });
    };

    Oidc.login = function (payload, callback) {
        async.waterfall([
            // Lookup user by existing oauthid
            (next) => Oidc.getUidByOAuthid(payload.oAuthid, next),
            // Skip if we found the user in the previous step or create the user
            function (uid, next) {
                if (uid !== null) {
                    // Existing user
                    next(null, uid);
                } else {
                    // New User
                    if (!payload.email) {
                        return next(new Error('The email was missing from the user, we cannot log them in.'));
                    }

                    async.waterfall([
                        (next) => User.getUidByEmail(payload.email, next),
                        function (uid, next) {
                            if (!uid) {
                                User.create({
                                    username: payload.username,
                                    email: payload.email,
                                }, next);
                            } else {
                                next(null, uid); // Existing account -- merge
                            }
                        },
                        function (uid, next) {
                            // Save provider-specific information to the user
                            User.setUserField(uid, constants.name + 'Id', payload.oAuthid);
                            db.setObjectField(constants.name + 'Id:uid', payload.oAuthid, uid);

                            next(null, uid);
                        },
                    ], next);
                }
            },
            // Get the users membership status to admins
            (uid, next) => Groups.isMember(uid, 'administrators', (err, isMember) => {
                next(err, uid, isMember);
            }),
            // If the plugin is configured to use roles, add or remove them from the admin group (if necessary)
            (uid, isMember, next) => {
                if (payload.rolesEnabled) {
                    if (payload.isAdmin === true && !isMember) {
                        Groups.join('administrators', uid, (err) => {
                            next(err, uid);
                        });
                    } else if (payload.isAdmin === false && isMember) {
                        Groups.leave('administrators', uid, (err) => {
                            next(err, uid);
                        });
                    } else {
                        // Continue
                        next(null, uid);
                    }
                } else {
                    // Continue
                    next(null, uid);
                }
            },
        ], function (err, uid) {
            if (err) {
                return callback(err);
            }
            callback(null, {
                uid: uid,
            });
        });
    };

    Oidc.getUidByOAuthid = function (oAuthid, callback) {
        db.getObjectField(constants.name + 'Id:uid', oAuthid, (err, uid) => {
            if (err) {
                return callback(err);
            }
            callback(null, uid);
        });
    };

    Oidc.deleteUserData = function (data, callback) {
        async.waterfall([
            async.apply(User.getUserField, data.uid, constants.name + 'Id'),
            (oAuthIdToDelete, next) => {
                db.deleteObjectField(constants.name + 'Id:uid', oAuthIdToDelete, next);
            },
        ], (err) => {
            if (err) {
                winston.error('[sso-oauth] Could not remove OAuthId data for uid ' + data.uid + '. Error: ' + err);
                return callback(err);
            }

            callback(null, data);
        });
    };

    // If this filter is not there, the deleteUserData function will fail when getting the oauthId for deletion.
    Oidc.whitelistFields = function (params, callback) {
        params.whitelist.push(constants.name + 'Id');
        callback(null, params);
    };

    Oidc.bindMenuOption = function (header, callback) {
        winston.verbose('Binding menu option');
        header.authentication.push({
            route: constants.pluginSettingsURL.replace('/admin', ''), // They will add the /admin for us
            name: 'OpenID Connect',
        });

        callback(null, header);
    };

    Oidc.redirectLogout = function (payload, callback) {
        const settings = constants.pluginSettings.getWrapper();

        if (settings.logoutEndpoint) {
            winston.verbose('Changing logout to OpenID logout');
            let separator;
            if (settings.logoutEndpoint.indexOf('?') === -1) {
                separator = '?';
            } else {
                separator = '&';
            }
            payload.next = settings.logoutEndpoint + separator + 'client_id=' + settings.clientId;
        }

        return callback(null, payload);
    };

    /**
     * API Authentication Endpoint
     * Allows authentication via Keycloak token
     */
    Oidc.apiAuthenticate = function (req, res) {
        const keycloakToken = req.body.token;

        if (!keycloakToken) {
            return res.status(400).json({ error: 'Keycloak token is required' });
        }

        // Get plugin settings
        const settings = constants.pluginSettings.getWrapper();
        const publicKey = settings.publicKey;

        if (!publicKey) {
            return res.status(500).json({ error: 'Keycloak public key is not configured in plugin settings' });
        }

        // Verify the Keycloak token
        jwt.verify(keycloakToken, publicKey, { algorithms: ['RS256'] }, (err, decoded) => {
            if (err) {
                winston.error('Failed to verify Keycloak token:', err);
                return res.status(401).json({ error: 'Invalid Keycloak token' });
            }

            const profile = {
                sub: decoded.sub,
                email: decoded.email,
                preferred_username: decoded.preferred_username,
                // Include any other required fields
            };

            const payload = {
                oAuthid: profile.sub,
                username: profile.preferred_username || profile.email.split('@')[0],
                email: profile.email,
                rolesEnabled: false, // or true if you're using roles
                isAdmin: false, // Set based on your logic
            };

            Oidc.login(payload, (err, user) => {
                if (err) {
                    winston.error('Failed to login user:', err);
                    return res.status(500).json({ error: 'Failed to authenticate user' });
                }

                req.login({ uid: user.uid }, (err) => {
                    if (err) {
                        winston.error('Failed to establish session:', err);
                        return res.status(500).json({ error: 'Failed to establish session' });
                    }

                    // Generate CSRF token
                    const csrfToken = req.csrfToken();

                    // Set session cookie
                    res.cookie('express.sid', req.cookies['express.sid'], { httpOnly: true });

                    // Send session cookie and CSRF token
                    res.json({ csrf_token: csrfToken });
                });
            });
        });
    };

    module.exports = Oidc;
})(module);
