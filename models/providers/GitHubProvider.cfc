component
	accessors="true"
	implements  = "cbsso.models.ISSOIntegrationProvider"
{

	property name = "Name";
    property name = "clientId";
    property name = "clientSecret";
    property name = "authEndpoint";
    property name = "userInfoURL";
    property name = "accessTokenEndpoint";
    property name = "redirectUri";
    property name = "Scope";

    property name="oAuthService" inject="oAuthService@cbsso";
    property name="wirebox" inject="wirebox";
    property name="hyper" inject="HyperBuilder@hyper";

    variables.name = "GitHub";
    variables.scope = "user user:email";
    variables.userInfoURL = "https://api.github.com/user";
    variables.authEndpoint = "https://github.com/login/oauth/authorize";
    variables.accessTokenEndpoint = "https://github.com/login/oauth/access_token";

    public string function getName() {
        return variables.name;
    }

    public string function getRedirectUri(){
        if( !isNull( variables.redirectUri ) ){
            return variables.redirectUri;
        }

        var protocol = cgi.HTTPS == "" ? "http://" : "https://";

        return "#protocol##cgi.HTTP_HOST#/cbsso/auth/#variables.name.lcase()#";
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
        var authResponse = wirebox.getInstance( "SSOAuthorizationResponse@cbsso" );
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

            var accessData = parseAccessData( res.getData().toString() );
            rawData[ "accessResponse" ] = accessData;

            var userDataRes = hyper
                .setMethod( "GET" )
                .setUrl( variables.userInfoURL )
                .setHeaders( { "Authorization": "Bearer " & accessData.access_token } )
                .send();

            var userData = deserializeJSON( userDataRes.getData() );
            rawData[ "userData" ] = userData;
            
            return authResponse
                .setWasSuccessful( true )
                .setName( userData.name )
                .setEmail( userData.email )
                .setUserId( userData.id );
        }
        catch( any e ){
            return authResponse
                .setWasSuccessful( false )
                .setErrorMessage( e.message );
        }        
    }

    private struct function parseAccessData( required string accessData ){
        return listToArray( accessData, '&' )
            .reduce( ( acc, item ) => {
                var entry = listToArray( item, "=" );

                acc[ urlDecode( entry[ 1 ] ) ] = urlDecode( entry[ 2 ] );

                return acc;
            }, {} );
    }

}
