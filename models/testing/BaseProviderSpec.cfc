/**
 * Disk Service Spec
 */
component extends="cbPlaywright.models.ColdBoxPlaywrightTestCase" {

	this.loadColdbox   = true;
	// Unload Coldbox after this spec, since we are doing a shutdown of all disks
	this.unLoadColdBox = true;
	this.autowire      = true;

	variables.provider = "";

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

	// function   run( testResults, testBox ){
	// all your suites go here.
	// describe( "Google Specs", function(){
	// 	beforeEach( function( currentSpec ){
	// 		provider = getProvider( providerName = "google" );
	// 	} );

	// 	story( "The disk should be created and started by the service", function(){
	// 		it( "is started by the service", function(){
	// 			expect( provider ).toBeComponent();
	// 		} );
	// 	} );

	// 	story( "I can authenticate with the provider", function(){
	// 		it( "can build the auth url", function(){
	// 			expect( provider.buildAuthUrl() ).toBe(
	// 				"https://accounts.google.com/o/oauth2/v2/auth?client_id=***REMOVED***&access_type=offline&state=false&redirect_uri=http://localhost:8080/auth&scope=openid profile&response_type=code"
	// 			);
	// 		} );

	// 		it( "can build the request token url", function(){
	// 			var code = "any-token";
	// 			var tokenResponse = provider.makeAccessTokenRequest( code );

	// 			expect( tokenResponse.content.getRequest().getBody() ).toInclude( code );
	// 		} );
	// 	} );
	// } );
	// }

	/**
	 * ------------------------------------------------------------
	 * Test Helpers
	 * ------------------------------------------------------------
	 */

	function getProvider(){
		return getInstance( "ProviderService@oAuth" ).get( variables.providerName );
	}

	function getProvidersList(){
		return getInstance( "ProviderService@oAuth" ).names();
	}

}
