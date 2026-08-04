component {

	public any function ssoError( event, rc, prc ){
		event.renderData( data = "SSO_ERROR" );
	}

	public any function ssoSuccess( event, rc, prc ){
		event.renderData( data = "SSO_SUCCESS" );
	}

	public any function fakeIdentityProvider(){
		relocate( url = "http://" & cgi.HTTP_HOST & "/cbsso/auth/customprovider?test=working" );
	}

}
