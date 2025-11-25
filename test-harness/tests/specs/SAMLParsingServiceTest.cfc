/**
 * Disk Service Spec
 */
component extends="coldbox.system.testing.BaseTestCase" {

	this.loadColdbox   = true;
	// Unload Coldbox after this spec, since we are doing a shutdown of all disks
	this.unLoadColdBox = false;

	/*********************************** LIFE CYCLE Methods ***********************************/

	/**
	 * executes before all suites+specs in the run() method
	 */
	function beforeAll(){
		super.beforeAll();
		setup();
	}

	/**
	 * executes after all suites+specs in the run() method
	 */
	function afterAll(){
		super.afterAll();
	}

	/*********************************** BDD SUITES ***********************************/

	function run( testResults, testBox ){
		// all your suites go here.
		describe( "SAMLParsingService", function(){
			beforeEach( function( currentSpec ){
				setup();
				service = getInstance( "SAMLParsingService@cbsso" );
			} );

			it( "can be created", function(){
				expect( service ).toBeComponent();
			} );

			it( "should extract user info from a valid SAML response", function(){
				var rawSAMLResponse = fileRead( expandPath( "../resources/validSAMLResponse.xml" ) );
				var result         = service.extractUserInfo( rawSAMLResponse );

				expect( result.success ).toBeTrue();
				expect( result.firstName ).toBe( "Jacob" );
				expect( result.lastName ).toBe( "Beers" );
				expect( result.email ).toBe( "jbeers@ortussolutions.com" );			
			} );

			it( "should return an error message from the xml", function(){
				var rawSAMLResponse = fileRead( expandPath( "../resources/errorSAMLResponse.xml" ) );
				var result         = service.extractUserInfo( rawSAMLResponse );

				expect( result.success ).toBeFalse();
				expect( result.errorMessage ).toBe( "Invalid Content" );
			} );

			it( "should return an error response if it can't parse the xml", function(){
				var result         = service.extractUserInfo( "<data></data>" );

				expect( result.success ).toBeFalse();
				expect( result.errorMessage ).toStartWith( "Invalid SAML Response - could not extract error message." );
			} );
		});
	}

}
