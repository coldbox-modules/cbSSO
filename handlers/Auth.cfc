component {
    property name = "ProviderService" inject = "ProviderService@cbsso";
    property name="moduleSettings" inject="coldbox:moduleSettings:cbsso";

    public any function start( event, rc, prc ){
        var provider = ProviderService.get( event.getValue( "providerName", "" ) );

        if( isNull( provider ) ){
            announce( "CBSSOMissingProvider", {
                "providerName": event.getValue( "providerName", "" )
            } );
            relocate( moduleSettings.errorRedirect );
        }

        relocate( url = provider.startAuthenticationWorflow( event ) );
    }

    public any function authorize( event, rc, prc ){
        var provider = ProviderService.get( event.getValue( "providerName", "" ) );

        if( isNull( provider ) ){
            announce( "CBSSOMissingProvider", {
                "providerName": event.getValue( "providerName", "" )
            } );

            relocate( moduleSettings.errorRedirect );
        }

        var ssoAuthorizationEvent = provider.processAuthorizationEvent( event );

        announce( "CBSSOAuthorization", {
            "provider": provider,
            "ssoAuthorizationEvent": ssoAuthorizationEvent
        } );
        
        relocate( moduleSettings.successRedirect );
    }

}