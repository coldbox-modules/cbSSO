/**
 * cbAuth Integration Interceptor Spec
 *
 * Driven through the Auth handler rather than announcing directly, so relocate() runs against
 * BaseTestCase's mock controller - which records relocate_* on the request context. Note that the
 * mock's relocate() throws, so these specs cannot distinguish a guarded early return from a
 * fall-through; in production location() aborts the request, which has the same effect.
 */
component extends="coldbox.system.testing.BaseTestCase" {

	this.loadColdbox   = true;
	this.unLoadColdBox = false;

	function beforeAll(){
		super.beforeAll();
		setup();
	}

	function afterAll(){
		// Session outlives the bundle - unLoadColdBox is false
		getInstance( "authenticationService@cbauth" ).logout();
		super.afterAll();
	}

	function run( testResults, testBox ){
		describe( "cbAuth Integration Interceptor", function(){
			beforeEach( function( currentSpec ){
				setup();
				moduleSettings = getInstance( dsl = "coldbox:moduleSettings:cbsso" );
				authService    = getInstance( "authenticationService@cbauth" );

				authService.logout();
			} );

			it( "logs a user in and redirects to successRedirect on a successful authorization", function(){
				var rc          = getRequestContext().getCollection();
				rc.providerName = "CustomProvider";

				var event = execute( event = "cbsso:Auth.authorize", renderResults = false );

				expect( authService.isLoggedIn() ).toBeTrue();
				expect( event.getValue( "relocate_event", "__none__" ) ).toBe( moduleSettings.successRedirect );
			} );

			it( "redirects to errorRedirect and logs nobody in on a failed authorization", function(){
				var rc          = getRequestContext().getCollection();
				rc.providerName = "CustomProvider";
				rc.fakeFailure  = true;

				var event = execute( event = "cbsso:Auth.authorize", renderResults = false );

				expect( authService.isLoggedIn() ).toBeFalse();
				expect( event.getValue( "relocate_event", "__none__" ) ).toBe( moduleSettings.errorRedirect );
			} );
		} );
	}

}
