import * as OAuth2Strategy from 'passport-oauth2';

export interface PassportOIDCSettings {
    clientId: string;
    clientSecret: string;
    emailClaim: string;
    authorizationEndpoint: string;
    tokenEndpoint: string;
    userInfoEndpoint: string;
    callbackURL: string;
}

export class PassportOIDC extends OAuth2Strategy {
    public name = 'passport-oidc';

    constructor(
        private settings: PassportOIDCSettings,
        verifyFunction: OAuth2Strategy.VerifyFunctionWithRequest
    ) {
        super(
            {
                clientID: settings.clientId,
                clientSecret: settings.clientSecret,
                callbackURL: settings.callbackURL,
                authorizationURL: settings.authorizationEndpoint,
                tokenURL: settings.tokenEndpoint,
                scope: ['openid', settings.emailClaim],
                passReqToCallback: true,
            },
            verifyFunction
        );
    }

    // Just to remember these exist
    // tokenParams(options: any): object {
    //     return super.tokenParams(options);
    // }

    // Just to remember these exist
    // authorizationParams(options: any): object {
    //     return super.authorizationParams(options);
    // }

    userProfile(accessToken: string, done: (err?: Error | null, profile?: any) => void): void {
        if (!accessToken) {
            return done(new Error('Missing token, cannot call the userinfo endpoint without it.'));
        }

        (this as any)._oauth2.useAuthorizationHeaderforGET(true);
        this._oauth2.get(this.settings.userInfoEndpoint, accessToken, (err, body, res) => {
            if (err) {
                console.error('Failed to fetch user profile:', err);
                return done(new Error(`Failed to get user info. Exception was previously logged.`));
            }

            if (res.statusCode < 200 || res.statusCode > 299) {
                return done(new Error(`Unexpected response from userInfo. [${res.statusCode}] [${body}]`));
            }

            try {
                const profile = JSON.parse(body as string);
                done(null, profile);
            } catch (e) {
                console.error('Failed to parse user profile:', e);
                done(new Error(`Failed to parse the userinfo body. Exception was previously logged.`));
            }
        });
    }
}

export default PassportOIDC;
