component extends="coldbox.system.testing.BaseTestCase" {

	this.loadColdbox   = true;
	this.unLoadColdBox = false;

	function run( testResults, testBox ){
		describe( "MicrosoftSAMLProvider", function(){
			beforeEach( function(){
				setup();
				variables.provider  = prepareMock( getInstance( "MicrosoftSAMLProvider@cbsso" ) );
				variables.validator = createStub().$( "cacheCerts" );
				variables.logger    = createStub().$( "warn" );

				// A non-null generator skips OpenSAML initialisation, leaving only the certificate handling
				variables.provider.$property( propertyName = "AuthNRequestGenerator", mock = createStub() );
				variables.provider.$property( propertyName = "responseValidator", mock = variables.validator );
				variables.provider.$property( propertyName = "log", mock = variables.logger );
				variables.provider.setFederationMetadataURL( "https://idp.example.com/federationmetadata.xml" );
				makePublic( variables.provider, "initializeOpenSAMLLib" );
			} );

			describe( "processAuthorizationEvent", function(){
				it( "reports a failed login when the IdP metadata cannot be fetched", function(){
					variables.provider.$(
						method         = "initializeOpenSAMLLib",
						throwException = true,
						throwType      = "MicrosoftSAMLProvider.CertificateCachingError",
						throwMessage   = "metadata unreachable"
					);

					var response = variables.provider.processAuthorizationEvent( createStub().$( "getValue", "" ) );

					expect( response.wasSuccessful() ).toBeFalse();
					expect( response.getErrorMessage() ).toBe( "metadata unreachable" );
				} );
			} );

			describe( "signing certificates", function(){
				it( "fetches them once and reuses them while they are fresh", function(){
					variables.provider.initializeOpenSAMLLib();
					variables.provider.initializeOpenSAMLLib();

					expect( variables.validator.$count( "cacheCerts" ) ).toBe( 1 );
				} );

				it( "re-reads the metadata once the refresh interval has passed", function(){
					variables.provider.initializeOpenSAMLLib();
					variables.provider.$property(
						propertyName = "certificatesRefreshAfter",
						mock         = dateAdd( "n", -1, now() )
					);

					variables.provider.initializeOpenSAMLLib();

					expect( variables.validator.$count( "cacheCerts" ) ).toBe( 2 );
				} );

				it( "honours a configured refresh interval", function(){
					variables.provider.setCertificateRefreshMinutes( 1440 );

					variables.provider.initializeOpenSAMLLib();

					var refreshAfter = variables.provider.$getProperty( "certificatesRefreshAfter" );
					expect( dateDiff( "n", now(), refreshAfter ) ).toBeBetween( 1430, 1440 );
				} );

				it( "keeps the held certificates when a refresh fails, and retries sooner", function(){
					variables.provider.initializeOpenSAMLLib();
					variables.provider.$property(
						propertyName = "certificatesRefreshAfter",
						mock         = dateAdd( "n", -1, now() )
					);
					variables.validator.$(
						method         = "cacheCerts",
						throwException = true,
						throwMessage   = "metadata unreachable"
					);

					expect( () => variables.provider.initializeOpenSAMLLib() ).notToThrow();

					var refreshAfter = variables.provider.$getProperty( "certificatesRefreshAfter" );
					expect( dateDiff( "n", now(), refreshAfter ) ).toBeBetween( 3, 5 );
					expect( variables.logger.$count( "warn" ) ).toBe( 1 );
				} );

				it( "fails when the first fetch fails, since there is nothing to verify with", function(){
					variables.validator.$(
						method         = "cacheCerts",
						throwException = true,
						throwType      = "MetadataFetchError",
						throwMessage   = "metadata unreachable"
					);

					expect( () => variables.provider.initializeOpenSAMLLib() ).toThrow( "MetadataFetchError" );
				} );

				it( "fetches again when the metadata URL changes", function(){
					variables.provider.initializeOpenSAMLLib();
					variables.provider.setFederationMetadataURL( "https://idp.example.com/other.xml" );

					variables.provider.initializeOpenSAMLLib();

					expect( variables.validator.$count( "cacheCerts" ) ).toBe( 2 );
				} );
			} );
		} );
	}

}
