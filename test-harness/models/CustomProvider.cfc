component implements="oauth.models.ISSOIntegrationProvider" {
    property name="wirebox" inject="wirebox";

    public string function getName(){
        return "CustomProvider";
    }
    public string function getIconURL(){
        return "";
    }

    public string function startAuthenticationWorflow( required any event ){
        return "http://" & cgi.HTTP_HOST & "/main/fakeIdentityProvider";
    }

    public any function processAuthorizationEvent( required any event ){
        var authResponse = wirebox.getInstance( "SSOAuthorizationResponse@oauth" );

        return authResponse.setWasSuccessful( true );
    }
}