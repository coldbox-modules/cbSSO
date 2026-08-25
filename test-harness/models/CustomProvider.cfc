component implements="cbsso.models.ISSOIntegrationProvider" {

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
		var authResponse = wirebox.getInstance( "SSOAuthorizationResponse@cbsso" );

		if ( event.getValue( "fakeFailure", false ) ) {
			return authResponse.setWasSuccessful( false ).setErrorMessage( "fake IdP failure" );
		}

		return authResponse
			.setWasSuccessful( true )
			.setEmail( "jdoe@example.com" )
			.setUserId( "user-456" );
	}

}
