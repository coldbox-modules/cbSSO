/**
 * Auth Handler Spec
 */
component extends="coldbox.system.testing.BaseTestCase" {

	this.loadColdbox   = true;
	this.unLoadColdBox = false;

	function beforeAll(){
		super.beforeAll();
		setup();

		variables.announcedProviders      = [];
		variables.announcedAuthorizations = [];

		// Registered once for the bundle - interceptor registrations are not torn down per spec
		var interceptorService = getInstance( dsl = "coldbox:interceptorService" );

		interceptorService.listen( function( event, interceptData ){
			variables.announcedProviders.append( interceptData.providerName ?: "" );
		}, "CBSSOMissingProvider" );
		interceptorService.listen( function( event, interceptData ){
			variables.announcedAuthorizations.append( 1 );
		}, "CBSSOAuthorization" );
	}

	function afterAll(){
		super.afterAll();
	}

	function run( testResults, testBox ){
		describe( "Auth Handler", function(){
			beforeEach( function( currentSpec ){
				setup();
				moduleSettings                    = getInstance( dsl = "coldbox:moduleSettings:cbsso" );
				variables.announcedProviders      = [];
				variables.announcedAuthorizations = [];
			} );

			it( "announces CBSSOMissingProvider and redirects when start() gets an unknown provider", function(){
				var event = execute( route = "/cbsso/auth/notaprovider/start", renderResults = false );

				expect( variables.announcedProviders ).toBe( [ "notaprovider" ] );
				expect( event.getValue( "relocate_event", "__none__" ) ).toBe( moduleSettings.errorRedirect );
			} );

			it( "announces CBSSOMissingProvider and redirects when authorize() gets an unknown provider", function(){
				var event = execute( route = "/cbsso/auth/notaprovider", renderResults = false );

				expect( variables.announcedProviders ).toBe( [ "notaprovider" ] );
				expect( event.getValue( "relocate_event", "__none__" ) ).toBe( moduleSettings.errorRedirect );
			} );

			it( "resolves a registered provider and redirects start() into its workflow", function(){
				var event = execute( route = "/cbsso/auth/CustomProvider/start", renderResults = false );

				expect( variables.announcedProviders ).toBeEmpty();
				expect( event.getPrivateValue( "ssoProvider" ).getName() ).toBe( "CustomProvider" );
				expect( event.getValue( "relocate_URL", "" ) ).toInclude( "/main/fakeIdentityProvider" );
			} );

			it( "does not announce CBSSOAuthorization for a missing provider", function(){
				execute( route = "/cbsso/auth/notaprovider", renderResults = false );

				expect( variables.announcedAuthorizations ).toBeEmpty();
			} );
		} );
	}

}
