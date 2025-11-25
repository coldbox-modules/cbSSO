component
	accessors="true"
	extends="BaseProvider"
	implements="cbsso.models.ISSOIntegrationProvider"
{

	property name="Name";
	property name="clientId";
	property name="clientSecret";
	property name="authEndpoint";
	property name="accessTokenEndpoint";
	property name="redirectUri";
	property name="scope";

	property name="oAuthService" inject="oAuthService@cbsso";
	property name="wirebox"      inject="wirebox";

	variables.Name                = "Google";
	variables.scope               = "openid profile email";
	variables.authEndpoint        = "https://accounts.google.com/o/oauth2/v2/auth";
	variables.accessTokenEndpoint = "https://oauth2.googleapis.com/token";
	variables.jkwsEndpoint        = "https://www.googleapis.com/oauth2/v3/certs";

	public string function getName(){
		return variables.name;
	}

	public string function startAuthenticationWorflow( required any event ){
		return oAuthService.buildAuthUrl(
			authEndpoint  = getAuthEndpoint(),
			client_id     = getClientId(),
			redirect_uri  = getRedirectUri( event ),
			response_type = "code",
			extraParams   = { "scope" : getScope() }
		);
	}

	public any function processAuthorizationEvent( required any event ){
		var authResponse = wirebox.getInstance( "SSOAuthorizationResponse@cbsso" );

		try {
			var rawData = { "authResponse" : event.getCollection() };

			if ( event.getValue( "error", "" ) != "" ) {
				return authResponse
					.setRawResponseData( rawData )
					.setWasSuccessful( false )
					.setErrorMessage( event.getValue( "error" ) );
			}

			var res = oAuthService.makeAccessTokenRequest(
				getClientId(),
				getClientSecret(),
				getRedirectUri(),
				getAccessTokenEndpoint(),
				event.getValue( "code" )
			);

			var accessData              = deserializeJSON( res.getData() );
			rawData[ "accessResponse" ] = accessData;

			var idTokenData            = oAuthService.decodeJWT( accessData.id_token, variables.jkwsEndpoint );
			rawData[ "parsedIdToken" ] = idTokenData;

			return authResponse
				.setRawResponseData( rawData )
				.setWasSuccessful( true )
				.setFirstName( idTokenData.given_name )
				.setLastName( idTokenData.family_name )
				.setEmail( idTokenData.email )
				.setUserId( idTokenData.sub )
		} catch ( any e ) {
			return authResponse.setWasSuccessful( false ).setErrorMessage( e.message );
		}
	}

}
