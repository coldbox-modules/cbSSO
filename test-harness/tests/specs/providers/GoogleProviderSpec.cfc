/**
 * Disk Service Spec
 */
component extends="cbSSO.models.testing.BaseProviderSpec" {

	this.loadColdbox   = true;
	// Unload Coldbox after this spec, since we are doing a shutdown of all disks
	this.unLoadColdBox = true;

	variables.providerName = "GOogle";

	/*********************************** LIFE CYCLE Methods ***********************************/

	/**
	 * executes before all suites+specs in the run() method
	 */
	function beforeAll(){
		super.beforeAll();
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
		describe( "Google Specs", function(){
			beforeEach( function( currentSpec ){
				provider  = getProvider();
				var hyper = getInstance( "HyperRequest@hyper" );
			} );

			story( "The disk should be created and started by the service", function(){
				it( "is started by the service", function(){
					expect( provider ).toBeComponent();
				} );
			} );

			story( "I can authenticate with the provider", function(){
				it( "can build the auth url", function(){
					var authUrl = provider.buildAuthUrl();
					var browser = launchInteractiveBrowser( variables.playwright.firefox() );
					var page    = browser.newPage();
					navigate( page, authUrl );
					waitForLoadState( page );
					page.pause();
					var oauthMessage = page.getByText( "The OAuth client was not found." );

					expect( oauthMessage.isVisible() ).toBeTrue();
				} );

				it( "can build the request token url", function(){
					var code          = "any-token";
					var tokenResponse = provider.makeAccessTokenRequest( code );

					expect( tokenResponse.content.getRequest().getBody() ).toInclude( code );
				} );
			} );
		} );
	}

}
