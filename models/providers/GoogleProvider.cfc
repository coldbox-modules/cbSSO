component
	accessors="true"
	implements  = "oAuth.models.ISSOIntegrationProvider"
{

	property name = "Name";
    property name = "clientId";
    property name = "clientSecret";
    property name = "authEndpoint";
    property name = "accessTokenEndpoint";
    property name = "redirectUri";

    property name="oAuthService" inject="oAuthService@oauth";
    property name="wirebox" inject="wirebox";

    public string function getName() {
        return variables.name;
    }

    public string function getIconURL(){
        return "";
    }

    public any function populateFromSettings( required struct settings ){
        variables.Name = settings.Name;
        variables.clientId = settings.clientId;
        variables.clientSecret = settings.clientSecret;
        variables.authEndpoint = settings.authEndpoint;
        variables.accessTokenEndpoint = settings.accessTokenEndpoint;
        variables.redirectUri = settings.redirectUri;

        return this;
    }

    public string function startAuthenticationWorflow( required any event ){
        return oAuthService.buildAuthUrl(
            authEndpoint = getAuthEndpoint(),
            client_id = getClientId(),
            redirect_uri = getRedirectUri(),
            response_type = "code",
            extraParams = {
                "scope": "openid profile email"
            }
        );
    }

    public any function processAuthorizationEvent( required any event ){
        var authResponse = wirebox.getInstance( "SSOAuthorizationResponse@oauth" );

        try {
            var rawData = {
                "authResponse": event.getCollection()
            };

            if( event.getValue( "error", "" ) != "" ){
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

            var accessData = deserializeJSON( res.getData() );
            rawData[ "accessResponse" ] = accessData;

            var idTokenData = parseIDToken( accessData.id_token );
            rawData[ "parsedIdToken" ] = idTokenData;

            return authResponse
                .setRawResponseData( rawData )
                .setWasSuccessful( true )
                .setFirstName( idTokenData.given_name )
                .setLastName( idTokenData.family_name )
                .setEmail( idTokenData.email )
                .setUserId( idTokenData.sub )
        }
        catch( any e ){
            return authResponse
                .setWasSuccessful( false )
                .setErrorMessage( e.message );
        }        
    }

    private struct function parseIDToken( required string idToken ){
        return deserializeJSON( charsetEncode( binaryDecode( listGetAt( idToken, 2, "." ), "base64" ), "utf-8" ) );
    }

}
