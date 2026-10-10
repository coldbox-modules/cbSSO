component {

	property name="ProviderService" inject="ProviderService@cbsso";
	property name="moduleSettings"  inject="coldbox:moduleSettings:cbsso";

	/**
	 * Resolves the requested provider into `prc.ssoProvider` for every action, or announces
	 * `CBSSOMissingProvider` and redirects to the configured error page when the name is
	 * not registered. `ProviderService.get()` throws on an unknown name, so the check has
	 * to happen before it.
	 */
	function preHandler( event, rc, prc, action, eventArguments ){
		var providerName = event.getValue( "providerName", "" );

		if ( variables.ProviderService.missing( providerName ) ) {
			announce( "CBSSOMissingProvider", { "providerName" : providerName } );

			relocate( variables.moduleSettings.errorRedirect );
			return;
		}

		prc.ssoProvider = variables.ProviderService.get( providerName );
	}

	function start( event, rc, prc ){
		// Fall back to the deprecated misspelled method for custom providers written against cbSSO <= 3.0
		if ( structKeyExists( prc.ssoProvider, "startAuthenticationWorkflow" ) ) {
			relocate( url = prc.ssoProvider.startAuthenticationWorkflow( event ) );
		} else {
			relocate( url = prc.ssoProvider.startAuthenticationWorflow( event ) );
		}
	}

	function authorize( event, rc, prc ){
		var ssoAuthorizationEvent = prc.ssoProvider.processAuthorizationEvent( event );

		announce(
			"CBSSOAuthorization",
			{
				"provider"              : prc.ssoProvider,
				"ssoAuthorizationEvent" : ssoAuthorizationEvent
			}
		);

		relocate( variables.moduleSettings.successRedirect );
	}

}
