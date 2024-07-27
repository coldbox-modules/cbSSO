component
	accessors="true"
	implements  = "oAuth.models.ISSOIntegrationProvider"
{

	property name = "Name";
    property name = "clientId";
    property name = "clientSecret";
    property name = "authEndpoint";
    property name = "userInfoURL";
    property name = "accessTokenEndpoint";
    property name = "redirectUri";
    property name = "Scope";

    property name="oAuthService" inject="oAuthService@oauth";
    property name="wirebox" inject="wirebox";
    property name="hyper" inject="HyperBuilder@hyper";

    variables.name = "Facebook";
    variables.scope = "openid email";
    variables.authEndpoint = "https://facebook.com/dialog/oauth/";
    variables.accessTokenEndpoint = "https://graph.facebook.com/v11.0/oauth/access_token";

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
        var rawData = {
            "authResponse": {},
            "accessResponse": {},
            "userData": {}
        };
        authResponse.setRawResponseData( rawData );

        try {
            rawData[ "authResponse" ] = event.getCollection();

            if( event.getValue( "error", "" ) != "" ){
                return authResponse
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
        return deserializeJSON( charsetEncode( binaryDecode( listGetAt( idToken, 2, "." ), "base64URL" ), "utf-8" ) );
    }

}
