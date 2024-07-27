component {
    property name = "ProviderService" inject = "ProviderService@cbsso";
    property name="moduleSettings" inject="coldbox:moduleSettings:cbsso";

    public any function start( event, rc, prc ){
        var provider = ProviderService.get( event.getValue( "providerName", "" ) );

        if( isNull( provider ) ){
            // TODO add interception point to handle missing provider
            relocate( moduleSettings.errorRedirect );
        }

        relocate( url = provider.startAuthenticationWorflow( event ) );
    }

    public any function authorize( event, rc, prc ){
        var provider = ProviderService.get( event.getValue( "providerName", "" ) );

        if( isNull( provider ) ){
            // TODO add interception point to handle missing provider
            relocate( moduleSettings.errorRedirect );
        }

        var ssoAuthorizationEvent = provider.processAuthorizationEvent( event );

        announce( "CBSSOOnAuthorization", {
            "provider": provider,
            "ssoAuthorizationEvent": ssoAuthorizationEvent
        } );

        // TODO this should probably be a module setting
        relocate( moduleSettings.successRedirect );
    }

}