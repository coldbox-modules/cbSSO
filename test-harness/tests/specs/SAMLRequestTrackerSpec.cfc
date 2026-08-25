component extends="coldbox.system.testing.BaseTestCase" {

	this.loadColdbox   = true;
	this.unLoadColdBox = false;

	function run( testResults, testBox ){
		describe( "SAMLRequestTracker", function(){
			beforeEach( function(){
				setup();
				variables.tracker   = getInstance( "SAMLRequestTracker@cbsso" );
				variables.requestId = "test-" & createUUID();
			} );

			afterEach( function(){
				variables.tracker.consume( variables.requestId );
			} );

			it( "stores a request ID in CacheBox", function(){
				variables.tracker.remember( variables.requestId );

				expect( variables.tracker.isPending( variables.requestId ) ).toBeTrue();
			} );

			it( "consumes a request ID only once", function(){
				variables.tracker.remember( variables.requestId );

				expect( variables.tracker.consume( variables.requestId ) ).toBeTrue();
				expect( variables.tracker.consume( variables.requestId ) ).toBeFalse();
				expect( variables.tracker.isPending( variables.requestId ) ).toBeFalse();
			} );
		} );
	}

}
