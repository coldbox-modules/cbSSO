component {

	property name="moduleSettings" inject="coldbox:moduleSettings:cbsso";

	/**
	 * Logs the authenticated user in via cbAuth, creating or updating them from the SSO
	 * response, then redirects to the configured success page.
	 */
	public void function CBSSOAuthorization( event, data ){
		if ( !data.ssoAuthorizationEvent.wasSuccessful() ) {
			relocate( variables.moduleSettings.errorRedirect );
			return;
		}

		var authService = getInstance( "authenticationService@cbauth" );
		var userService = authService.getUserService();
		var user        = userService.findBySSO( data.ssoAuthorizationEvent, data.provider );

		if ( isNull( user ) ) {
			user = userService.createFromSSO( data.ssoAuthorizationEvent, data.provider );
		} else {
			userService.updateFromSSO(
				user,
				data.ssoAuthorizationEvent,
				data.provider
			);
		}

		authService.login( user );

		relocate( variables.moduleSettings.successRedirect );
	}

}
