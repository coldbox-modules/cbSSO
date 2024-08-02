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
		describe( "Provider Service", function(){
			beforeEach( function( currentSpec ){
				setup();
				service = getInstance( "ProviderService@cbsso" );
			} );

			it( "can be created", function(){
				expect( service ).toBeComponent();
			} );

			// xstory( "I want to get disk records for registered disks", function(){
			// 	given( "a valid disk name", function(){
			// 		then( "I will get the disk record", function(){
			// 			service.register( provider: "Google" );
			// 			expect( service.getProviderRecord( "Google" ) ).toBeStruct();
			// 		} );
			// 	} );
			// 	given( "an invalid disk name", function(){
			// 		then( "It will throw an InvalidDiskException ", function(){
			// 			expect( function(){
			// 				service.getProviderRecord( "LinkedIn" );
			// 			} ).toThrow( "InvalidProviderException" );
			// 		} );
			// 	} );
			// } );

			// xstory( "I want to retrieve providers via the get() operation", function(){
			// 	given( "a provider that has not been created yet", function(){
			// 		then( "it should build it, register it and return it", function(){
			// 			service.register( provider: "Google" );
			// 			var oProvider = service.get( "Google" );
			// 			expect( oProvider ).toBeComponent();
			// 			expect( oProvider.getProviderName() ).toBe( "Google" );
			// 		} );
			// 	} );

			// 	given( "a previously built provider", function(){
			// 		then( "it should return the same provider", function(){
			// 			service.register( provider: "Google" );
			// 			var oProvider = service.get( "Google" );
			// 			expect( service.get( "Google" ).getIdentifier() ).toBe( oProvider.getIdentifier() );
			// 		} );
			// 	} );

			// 	given( "an invalid and unregistered provider", function(){
			// 		then( "it should throw a InvalidProviderException", function(){
			// 			expect( function(){
			// 				service.get( "LinkedIn" );
			// 			} ).toThrow( "InvalidProviderException" );
			// 		} );
			// 	} );
			// } );
		} );
	}

}
