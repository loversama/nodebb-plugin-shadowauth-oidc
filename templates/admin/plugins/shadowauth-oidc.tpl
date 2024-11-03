<div class="row">
	<div class="col-xs-12">
		<div class="panel panel-default">
			<div class="panel-heading">
				<h2 class="panel-title">OpenID Connect Configuration</h2>
			</div>
			<div class="panel-body">
				<p>
					Configure NodeBB to authenticate using an OpenID Connect identity provider.
				</p>
				<p>
					Check the GitHub project
					<a href="https://github.com/shadowauth/nodebb-plugin-shadowauth-oidc">README</a> for additional
					information.
				</p>
				<form class="mt-3" id="shadowauth-oidc-settings" role="form">
					<div class="mb-2">
						<label class="form-label" for="client_id">Client Id</label>
						<input class="form-control" data-trim="true" id="client_id" name="clientId" type="text">
					</div>
					<div class="mb-2">
						<label class="form-label" for="client_secret">Client Secret</label>
						<input class="form-control" data-trim="true" id="client_secret" name="clientSecret" type="text">
					</div>
					<div class="mb-2">
						<label class="form-label" for="discovery_base_url">Discovery URL</label>
						<input class="form-control" data-trim="true" id="discovery_base_url" name="discoveryBaseURL" type="text">
					</div>
					<div class="mb-2">
						<label class="form-label" for="authorization_endpoint">Authorization endpoint</label>
						<input class="form-control" data-trim="true" id="authorization_endpoint" name="authorizationEndpoint"
						       type="text">
					</div>
					<div class="mb-2">
						<label class="form-label" for="token_endpoint">Token endpoint</label>
						<input class="form-control" data-trim="true" id="token_endpoint" name="tokenEndpoint" type="text">
					</div>
					<div class="mb-2">
						<label class="form-label" for="user_info_endpoint">Userinfo endpoint</label>
						<input class="form-control" data-trim="true" id="user_info_endpoint" name="userInfoEndpoint" type="text">
					</div>
					<div class="mb-2">
						<label class="form-label" for="logout_endpoint">Logout endpoint</label>
						<input class="form-control" data-trim="true" id="logout_endpoint" name="logoutEndpoint" type="text">
					</div>
					<div class="mb-2">
						<label class="form-label" for="email_claim">Email claim</label>
						<input class="form-control" data-trim="true" id="email_claim" name="emailClaim" type="text" value="email">
					</div>
					<div class="mb-2">
						<label class="form-label" for="roles_claim">Roles claim</label>
						<input class="form-control" data-trim="true" id="roles_claim" name="rolesClaim" type="text">
					</div>
				<!-- New publicKey field with instructions -->
<div class="mb-2">
  <label class="form-label" for="public_key">Keycloak Public Key</label>
  <textarea class="form-control" data-trim="true" id="public_key" name="publicKey" rows="5" placeholder="Paste the PEM-formatted public key here, including the '-----BEGIN PUBLIC KEY-----' and '-----END PUBLIC KEY-----' lines."></textarea>
  <small class="form-text text-muted">
    Obtain the public key from your Keycloak admin console under Realm Settings &gt; Keys &gt; Public Key.
  </small>
</div>
				</form>
				<div class="d-flex mt-3 small">
					<div class="me-2" style="width: 32px;">
						<img src="https://shadowauth.io/img/favicon.png" alt="shadowauth" class="w-100">
					</div>
					<div>
						Maintained by <a href="https://shadowauth.io">shadowauth</a> <br>
						<a href="https://github.com/shadowauth/nodebb-plugin-shadowauth-oidc" target="_blank"
						   rel="noopener">
							https://github.com/shadowauth/nodebb-plugin-shadowauth-oidc
						</a>
					</div>
					<button class="btn btn-primary btn-sm fw-semibold ff-secondary text-center text-nowrap align-self-center ms-auto"
							id="shadowauth-oidc-save">Save</button>
				</div>
			</div>
		</div>
	</div>
</div>
