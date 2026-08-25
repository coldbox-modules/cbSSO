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

			it( "reports a successful status", function(){
				var rawSAMLResponse = fileRead( expandPath( "/tests/resources/validSAMLResponse.xml" ) );
				var result          = service.extractStatus( rawSAMLResponse );

				expect( result.success ).toBeTrue();
				expect( result.errorMessage ).toBe( "" );
			} );

			it( "should extract user info from a valid SAML response", function(){
				var result = service.extractIdentity( assertionFrom( "validSAMLResponse.xml" ) );

				expect( result.firstName ).toBe( "Jacob" );
				expect( result.lastName ).toBe( "Beers" );
				expect( result.email ).toBe( "jbeers@ortussolutions.com" );
			} );

			it( "returns every asserted attribute, not only the ones with a typed field", function(){
				var result = service.extractIdentity( assertionFrom( "validSAMLResponse.xml" ) );

				expect( result.claims ).toBeStruct();
				expect( result.claims ).toHaveKey( "http://schemas.microsoft.com/identity/claims/tenantid" );
				expect( result.claims[ "http://schemas.microsoft.com/identity/claims/displayname" ] ).toBe( [ "Jacob Beers" ] );
			} );

			it( "keeps every value of a multi-valued claim", function(){
				var result = service.extractIdentity( assertionFrom( "validSAMLResponse.xml" ) );

				// Entra sends three authentication methods here, each pretty-printed onto its own line
				expect( result.claims[ "http://schemas.microsoft.com/claims/authnmethodsreferences" ] ).toBe( [
					"http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password",
					"http://schemas.microsoft.com/claims/multipleauthn",
					"http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/unspecified"
				] );
			} );

			it( "extracts the subject NameID and its format", function(){
				var result = service.extractIdentity( assertionFrom( "validSAMLResponse.xml" ) );

				expect( result.nameId ).toBe( "pO+tkeMWqlmQJ6WmA1k2HOVlYfBGf0CnHApnDU9cGTk=" );
				expect( result.nameIdFormat ).toBe( "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" );
			} );

			it( "extracts from an assertion whose elements are namespace-prefixed", function(){
				var result = service.extractIdentity( assertionFrom( "prefixedSAMLResponse.xml" ) );

				expect( result.firstName ).toBe( "Ada" );
				expect( result.lastName ).toBe( "Lovelace" );
				expect( result.email ).toBe( "ada.lovelace@example.com" );
				expect( result.userId ).toBe( "0c8f4a52-1b7d-4e39-9f6a-3d2c5b8e7a14" );
				expect( result.nameId ).toBe( "V3JpdHRlbkJ5T3J0dXNTb2x1dGlvbnM9" );
				expect( result.nameIdFormat ).toBe( "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" );
				expect( result.claims[ "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups" ] ).toBe( [ "Analysts", "Engineering" ] );
				expect( result.claims[ "https://example.com/claims/employeenumber" ] ).toBe( [ "A1B2C3" ] );
			} );

			it( "reads only the assertion it was handed, not the response that carried it", function(){
				var rawSAMLResponse = fileRead( expandPath( "/tests/resources/forgedClaimSAMLResponse.xml" ) );

				expect( rawSAMLResponse ).toInclude(
					"attacker@evil.example",
					"the fixture has to carry the forged claim for this to prove anything"
				);

				var result = service.extractIdentity( assertionFrom( "forgedClaimSAMLResponse.xml" ) );

				expect( result.email ).toBe( "ada.lovelace@example.com" );
				expect( result.userId ).toBe( "0c8f4a52-1b7d-4e39-9f6a-3d2c5b8e7a14" );
				expect( result.nameId ).toBe( "V3JpdHRlbkJ5T3J0dXNTb2x1dGlvbnM9" );
				expect( result.claims[ "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" ] ).toBe( [ "ada.lovelace@example.com" ] );
				expect( result.claims ).notToHaveKey( "https://example.com/claims/forgedclaim" );
				expect( serializeJSON( result ) ).notToInclude( "attacker@evil.example" );
				expect( serializeJSON( result ) ).notToInclude( "Zm9yZ2VkTmFtZUlkPT0=" );
			} );

			it( "accepts an assertion asserting no display-name claims, which SAML never required", function(){
				var assertionXML = assertionFrom( "prefixedSAMLResponse.xml" )
					.replace(
						"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
						"https://example.com/claims/notagivenname"
					)
					.replace(
						"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
						"https://example.com/claims/notasurname"
					);
				var result = service.extractIdentity( assertionXML );

				expect( result.firstName ).toBe( "" );
				expect( result.lastName ).toBe( "" );
				expect( result.userId ).toBe( "0c8f4a52-1b7d-4e39-9f6a-3d2c5b8e7a14" );
				expect( result.claims ).toHaveKey( "https://example.com/claims/notasurname" );
			} );

			it( "identifies the subject by its NameID when no object identifier is asserted", function(){
				var assertionXML = assertionFrom( "prefixedSAMLResponse.xml" ).replace(
					"http://schemas.microsoft.com/identity/claims/objectidentifier",
					"https://example.com/claims/notanobjectidentifier"
				);
				var result = service.extractIdentity( assertionXML );

				expect( result.userId ).toBe( "V3JpdHRlbkJ5T3J0dXNTb2x1dGlvbnM9" );
				expect( result.nameIdFormat ).toBe( "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" );
			} );

			it( "refuses to identify the subject by a transient NameID", function(){
				var assertionXML = assertionFrom( "validSAMLResponse.xml" ).replace(
					"http://schemas.microsoft.com/identity/claims/objectidentifier",
					"https://example.com/claims/notanobjectidentifier"
				);

				expect( function(){
					service.extractIdentity( assertionXML );
				} ).toThrow( type = "SAMLParsingService.NoSubjectIdentifier", regex = "transient" );
			} );

			it( "refuses an assertion in which nothing identifies the subject", function(){
				// Renaming the element leaves a Subject holding only its bearer SubjectConfirmation, which
				// is all the Web Browser SSO profile requires of one
				var assertionXML = assertionFrom( "prefixedSAMLResponse.xml" )
					.replace( "NameID", "Unidentified", "all" )
					.replace(
						"http://schemas.microsoft.com/identity/claims/objectidentifier",
						"https://example.com/claims/notanobjectidentifier"
					);

				expect( function(){
					service.extractIdentity( assertionXML );
				} ).toThrow( type = "SAMLParsingService.NoSubjectIdentifier", regex = "carries no NameID" );
			} );

			it( "reads the email from a NameID whose format says it is one", function(){
				var assertionXML = assertionFrom( "prefixedSAMLResponse.xml" )
					.replace(
						"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
						"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
					)
					.replace( "V3JpdHRlbkJ5T3J0dXNTb2x1dGlvbnM9", "ada@example.com" )
					.replace(
						"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
						"https://example.com/claims/notanemail"
					);
				var result = service.extractIdentity( assertionXML );

				expect( result.email ).toBe( "ada@example.com" );
			} );

			it( "should return an error message from the xml", function(){
				var rawSAMLResponse = fileRead( expandPath( "/tests/resources/errorSAMLResponse.xml" ) );
				var result          = service.extractStatus( rawSAMLResponse );

				expect( result.success ).toBeFalse();
				expect( result.errorMessage ).toBe( "Invalid Content" );
			} );

			it( "should return an error response if it can't parse the xml", function(){
				var result = service.extractStatus( "<data></data>" );

				expect( result.success ).toBeFalse();
				expect( result.errorMessage ).toStartWith(
					"Invalid SAML Response - could not extract error message."
				);
			} );

			it( "reports a document that is not XML at all as a failure", function(){
				var result = service.extractStatus( "not xml" );

				expect( result.success ).toBeFalse();
				expect( result.errorMessage ).toStartWith( "Invalid SAML Response - could not be read" );
			} );

			it( "does not resolve an external entity that reads a local file", function(){
				var canaryPath = getTempDirectory() & "samlparsingservicetest-xxe-" & createUUID() & ".txt";
				var canary     = "XXE_CANARY_" & createUUID();
				fileWrite( canaryPath, canary );

				try {
					var rawSAMLResponse = "<?xml version=""1.0""?>
						<!DOCTYPE samlp:Response [ <!ENTITY xxe SYSTEM ""file://#canaryPath#""> ]>
						<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"">
							<samlp:Status>
								<samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester""/>
								<samlp:StatusMessage>&xxe;</samlp:StatusMessage>
							</samlp:Status>
						</samlp:Response>";

					var result = service.extractStatus( rawSAMLResponse );

					expect( result.success ).toBeFalse();
					expect( result.errorMessage ).notToInclude(
						canary,
						"the local file's contents reached the caller through an external entity"
					);
				} finally {
					if ( fileExists( canaryPath ) ) {
						fileDelete( canaryPath );
					}
				}
			} );

			it( "refuses a DOCTYPE even when its only entity is a harmless internal one", function(){
				// The declaration itself is refused - not any particular entity it carries
				var rawSAMLResponse = "<?xml version=""1.0""?>
					<!DOCTYPE samlp:Response [ <!ENTITY harmless ""inline value""> ]>
					<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"">
						<samlp:Status>
							<samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/>
						</samlp:Status>
					</samlp:Response>";

				expect( service.extractStatus( rawSAMLResponse ).success ).toBeFalse();
			} );

			it( "does not treat a non-XML string as a path to fetch", function(){
				var canaryPath = getTempDirectory() & "samlparsingservicetest-path-" & createUUID() & ".txt";
				var canary     = "PATH_CANARY_" & createUUID();
				fileWrite( canaryPath, canary );

				try {
					var result = service.extractStatus( canaryPath );

					expect( result.success ).toBeFalse();
					expect( result.errorMessage ).notToInclude(
						canary,
						"a bare path string was read off disk instead of being rejected as not-XML"
					);
				} finally {
					if ( fileExists( canaryPath ) ) {
						fileDelete( canaryPath );
					}
				}
			} );

			it( "still reports the IdP's StatusMessage on a legitimate Entra failure", function(){
				var rawSAMLResponse = "<?xml version=""1.0""?>
					<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"">
						<samlp:Status>
							<samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester""/>
							<samlp:StatusMessage>AADSTS50105: The signed in user is not assigned to a role for the application.</samlp:StatusMessage>
						</samlp:Status>
					</samlp:Response>";

				var result = service.extractStatus( rawSAMLResponse );

				expect( result.success ).toBeFalse();
				expect( result.errorMessage ).toInclude( "AADSTS50105" );
			} );

			it( "still extracts identity from a normal serialized assertion", function(){
				// extractIdentity() shares parseSAML() and, unlike extractStatus(), does not catch -
				// a regression here throws instead of quietly returning a flag
				var result = service.extractIdentity( assertionFrom( "validSAMLResponse.xml" ) );

				expect( result.email ).toBe( "jbeers@ortussolutions.com" );
				expect( result.userId ).toBe( "x" );
			} );
		} );
	}

	/**
	 * The Assertion element on its own, as the validator hands it back once its signature has verified -
	 * anything else in the fixture is deliberately out of reach of the identity extraction.
	 */
	private string function assertionFrom( required string fixture ){
		var responseXML = fileRead( expandPath( "/tests/resources/#arguments.fixture#" ) );
		var match       = reFindNoCase(
			"<([a-z0-9]+:)?Assertion[\s>][\s\S]*</([a-z0-9]+:)?Assertion>",
			responseXML,
			1,
			true
		);

		if ( !match.pos[ 1 ] ) {
			throw(
				type    = "SAMLParsingServiceTest.NoAssertionInFixture",
				message = "#arguments.fixture# carries no Assertion element."
			);
		}

		return mid( responseXML, match.pos[ 1 ], match.len[ 1 ] );
	}

}
