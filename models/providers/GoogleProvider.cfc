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
    property name = "scope";

    property name="oAuthService" inject="oAuthService@oauth";
    property name="wirebox" inject="wirebox";

    variables.Name = "Google";
    variables.scope = "openid profile email";
    variables.authEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
    variables.accessTokenEndpoint = "https://oauth2.googleapis.com/token";

    public string function getName() {
        return variables.name;
    }

    public string function getIconURL(){
        return "";
    }

    public string function getRedirectUri(){
        if( !isNull( variables.redirectUri ) ){
            return variables.redirectUri;
        }

        var protocol = cgi.HTTPS == "" ? "http://" : "https://";

        return "#protocol##cgi.HTTP_HOST#/oauth/auth/#variables.name.lcase()#";
    }

    public string function startAuthenticationWorflow( required any event ){
        return oAuthService.buildAuthUrl(
            authEndpoint = getAuthEndpoint(),
            client_id = getClientId(),
            redirect_uri = getRedirectUri(),
            response_type = "code",
            extraParams = {
                "scope": getScope()
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
