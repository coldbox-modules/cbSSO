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

			it( "namespaces the cache key by application", function(){
				// a distributed cache is shared by every application pointed at it, so an unnamespaced key
				// lets one application's AuthnRequest ID read as pending in another
				variables.tracker.remember( variables.requestId );

				var applicationName = getApplicationMetadata().name;
				var cache           = getInstance( "cachebox" ).getCache(
					getInstance( dsl = "coldbox:setting:samlRequestCacheName@cbsso" )
				);

				expect( cache.lookupQuiet( "cbsso:#applicationName#:saml-request:#variables.requestId#" ) ).toBeTrue();
				expect( cache.lookupQuiet( "cbsso:saml-request:#variables.requestId#" ) ).toBeFalse(
					"an unnamespaced key would collide with every other application on a shared cache"
				);
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
