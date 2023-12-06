component
	singleton
	threadsafe
	accessors="true"
	extends  ="oAuth2.models.BaseProvider"
{

	property name="moduleSettings" inject="coldbox:ModuleSettings:oauth";

	/**
	 * onDIComplete
	 */
	function onDIComplete(){
		var providerSettings = moduleSettings.providers.facebook;

		variables.clientId            = providerSettings.clientId,
		variables.clientSecret        = providerSettings.clientSecret,
		variables.authEndpoint        = providerSettings.authEndpoint,
		variables.accessTokenEndpoint = providerSettings.accessTokenEndpoint,
		variables.redirectUri         = providerSettings.redirectUri
	}


	public string function buildAuthUrl( required array scope, required string state ){
		var authParams = {
			"client_id"     : variables.clientId,
			"redirect_uri " : variables.redirectUri,
			"state"         : arguments.state
		};
		return super.buildAuthUrl( sParams, false );
	}

	/**
	 * I make the HTTP request to obtain the access token.
	 *
	 * @code The code returned from the authentication request.
	 **/
	public struct function makeAccessTokenRequest( required String code ){
		var aFormFields = [];
		return super.makeAccessTokenRequest( arguments.code, aFormFields );
	}

}
