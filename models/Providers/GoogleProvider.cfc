component
	singleton
	threadsafe
	accessors="true"
	extends  ="oAuth.models.BaseProvider"
{

	property name="moduleSettings" inject="coldbox:ModuleSettings:oauth";

	/**
	 * onDIComplete
	 */
	function onDIComplete(){
		var providerSettings = moduleSettings.providers.google;

		variables.name                = "Google";
		variables.clientId            = providerSettings.clientId;
		variables.clientSecret        = providerSettings.clientSecret;
		variables.authEndpoint        = providerSettings.authEndpoint;
		variables.accessTokenEndpoint = providerSettings.accessTokenEndpoint;
		variables.redirectUri         = providerSettings.redirectUri;
	}

	public string function buildAuthUrl(
		required string access_type    = "online",
		required string state          = false,
		array scope                    = [ "openid profile" ],
		boolean include_granted_scopes = true,
		string login_hint              = "",
		string prompt                  = ""
	){
		var authParams = {
			"client_id"     : variables.clientId,
			"response_type" : "code",
			"scope"         : arrayToList( arguments.scope, " " ),
			"redirect_uri"  : variables.redirectUri,
			"state"         : arguments.state
		};
		if ( len( arguments.login_hint ) ) {
			structInsert( authParams, "login_hint", arguments.login_hint );
		}
		if ( len( arguments.prompt ) ) {
			structInsert( authParams, "prompt", arguments.prompt );
		}
		return super.buildAuthUrl( authParams, false );
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

	/**
	 * Get user by token
	 */
	function getUserByToken( token ){
		var hyper    = hyper.new();
		var response = hyper.post(
			"https://www.googleapis.com/plus/v1/people/me?prettyPrint=false",
			{
				headers : {
					"Accept-Type"   : "application/json",
					"Authorization" : "Bearer #arguments.token.access_token#"
				}
			}
		);
		var stuResponse = {};
		if ( response.isSuccess() ) {
			stuResponse = deserializeJSON( response.filecontent );
		} else {
			stuResponse.success = false;
			stuResponse.content = response.getStatusText();
		}
		return stuResponse;
	}

}
