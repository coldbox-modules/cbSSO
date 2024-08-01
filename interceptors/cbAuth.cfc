component {
    property name="moduleSettings" inject="coldbox:moduleSettings:cbsso";
    
    public void function CBSSOAuthorization( event, data ){
        
        var authService = getInstance( "authenticationService@cbauth" );
        var userService = authService.getUserService();

        var user = userService.findBySSO( data.ssoAuthorizationEvent, data.provider );

        if( isNull( user ) ){
            user = userService.createFromSSO( data.ssoAuthorizationEvent, data.provider );
        }
        else {
            userService.updateFromSSO( user, data.ssoAuthorizationEvent, data.provider );
        }

        authService.login( user );

        relocate( moduleSettings.successRedirect );
    }
}