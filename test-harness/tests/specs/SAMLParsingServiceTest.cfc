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
				var rawSAMLResponse = fileRead( expandPath( "/tests/resources/validSAMLResponse.xml" ) );
				var result          = service.extractUserInfo( rawSAMLResponse );

				expect( result.success ).toBeTrue();
				expect( result.firstName ).toBe( "Jacob" );
				expect( result.lastName ).toBe( "Beers" );
				expect( result.email ).toBe( "jbeers@ortussolutions.com" );
			} );

			it( "returns every asserted attribute, not only the ones with a typed field", function(){
				var rawSAMLResponse = fileRead( expandPath( "/tests/resources/validSAMLResponse.xml" ) );
				var result          = service.extractUserInfo( rawSAMLResponse );

				expect( result.claims ).toBeStruct();
				expect( result.claims ).toHaveKey( "http://schemas.microsoft.com/identity/claims/tenantid" );
				expect( result.claims[ "http://schemas.microsoft.com/identity/claims/displayname" ] ).toBe( [ "Jacob Beers" ] );
			} );

			it( "keeps every value of a multi-valued claim", function(){
				var rawSAMLResponse = fileRead( expandPath( "/tests/resources/validSAMLResponse.xml" ) );
				var result          = service.extractUserInfo( rawSAMLResponse );

				// Entra sends three authentication methods here, each pretty-printed onto its own line
				expect( result.claims[ "http://schemas.microsoft.com/claims/authnmethodsreferences" ] ).toBe( [
					"http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password",
					"http://schemas.microsoft.com/claims/multipleauthn",
					"http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/unspecified"
				] );
			} );

			it( "extracts the subject NameID and its format", function(){
				var rawSAMLResponse = fileRead( expandPath( "/tests/resources/validSAMLResponse.xml" ) );
				var result          = service.extractUserInfo( rawSAMLResponse );

				expect( result.nameId ).toBe( "pO+tkeMWqlmQJ6WmA1k2HOVlYfBGf0CnHApnDU9cGTk=" );
				expect( result.nameIdFormat ).toBe( "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" );
			} );

			it( "extracts from an assertion whose elements are namespace-prefixed", function(){
				var rawSAMLResponse = fileRead( expandPath( "/tests/resources/prefixedSAMLResponse.xml" ) );
				var result          = service.extractUserInfo( rawSAMLResponse );

				expect( result.success ).toBeTrue();
				expect( result.firstName ).toBe( "Ada" );
				expect( result.lastName ).toBe( "Lovelace" );
				expect( result.email ).toBe( "ada.lovelace@example.com" );
				expect( result.userId ).toBe( "0c8f4a52-1b7d-4e39-9f6a-3d2c5b8e7a14" );
				expect( result.nameId ).toBe( "V3JpdHRlbkJ5T3J0dXNTb2x1dGlvbnM9" );
				expect( result.nameIdFormat ).toBe( "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" );
				expect( result.claims[ "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups" ] ).toBe( [ "Analysts", "Engineering" ] );
				expect( result.claims[ "https://example.com/claims/employeenumber" ] ).toBe( [ "A1B2C3" ] );
			} );

			it( "accepts an assertion asserting no display-name claims, which SAML never required", function(){
				var rawSAMLResponse = fileRead( expandPath( "/tests/resources/prefixedSAMLResponse.xml" ) )
					.replace(
						"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
						"https://example.com/claims/notagivenname"
					)
					.replace(
						"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
						"https://example.com/claims/notasurname"
					);
				var result = service.extractUserInfo( rawSAMLResponse );

				expect( result.success ).toBeTrue();
				expect( result.firstName ).toBe( "" );
				expect( result.lastName ).toBe( "" );
				expect( result.userId ).toBe( "0c8f4a52-1b7d-4e39-9f6a-3d2c5b8e7a14" );
				expect( result.claims ).toHaveKey( "https://example.com/claims/notasurname" );
			} );

			it( "identifies the subject by its NameID when no object identifier is asserted", function(){
				var rawSAMLResponse = fileRead( expandPath( "/tests/resources/prefixedSAMLResponse.xml" ) ).replace(
					"http://schemas.microsoft.com/identity/claims/objectidentifier",
					"https://example.com/claims/notanobjectidentifier"
				);
				var result = service.extractUserInfo( rawSAMLResponse );

				expect( result.success ).toBeTrue();
				expect( result.userId ).toBe( "V3JpdHRlbkJ5T3J0dXNTb2x1dGlvbnM9" );
				expect( result.nameIdFormat ).toBe( "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" );
			} );

			it( "refuses to identify the subject by a transient NameID", function(){
				var rawSAMLResponse = fileRead( expandPath( "/tests/resources/validSAMLResponse.xml" ) ).replace(
					"http://schemas.microsoft.com/identity/claims/objectidentifier",
					"https://example.com/claims/notanobjectidentifier"
				);
				var result = service.extractUserInfo( rawSAMLResponse );

				expect( result.success ).toBeFalse();
				expect( result.errorMessage ).toInclude( "identifies no subject" );
				expect( result.errorMessage ).toInclude( "transient" );
			} );

			it( "reports what was asserted even when nothing in it identifies the subject", function(){
				// Renaming the element leaves a Subject holding only its bearer SubjectConfirmation, which
				// is all the Web Browser SSO profile requires of one
				var rawSAMLResponse = fileRead( expandPath( "/tests/resources/prefixedSAMLResponse.xml" ) )
					.replace( "NameID", "Unidentified", "all" )
					.replace(
						"http://schemas.microsoft.com/identity/claims/objectidentifier",
						"https://example.com/claims/notanobjectidentifier"
					);
				var result = service.extractUserInfo( rawSAMLResponse );

				expect( result.success ).toBeFalse();
				expect( result.errorMessage ).toInclude( "carries no NameID" );
				expect( result.claims ).toHaveKey( "https://example.com/claims/notanobjectidentifier" );
			} );

			it( "reads the email from a NameID whose format says it is one", function(){
				var rawSAMLResponse = fileRead( expandPath( "/tests/resources/prefixedSAMLResponse.xml" ) )
					.replace(
						"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
						"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
					)
					.replace( "V3JpdHRlbkJ5T3J0dXNTb2x1dGlvbnM9", "ada@example.com" )
					.replace(
						"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
						"https://example.com/claims/notanemail"
					);
				var result = service.extractUserInfo( rawSAMLResponse );

				expect( result.success ).toBeTrue();
				expect( result.email ).toBe( "ada@example.com" );
			} );

			it( "should return an error message from the xml", function(){
				var rawSAMLResponse = fileRead( expandPath( "/tests/resources/errorSAMLResponse.xml" ) );
				var result          = service.extractUserInfo( rawSAMLResponse );

				expect( result.success ).toBeFalse();
				expect( result.errorMessage ).toBe( "Invalid Content" );
			} );

			it( "should return an error response if it can't parse the xml", function(){
				var result = service.extractUserInfo( "<data></data>" );

				expect( result.success ).toBeFalse();
				expect( result.errorMessage ).toStartWith(
					"Invalid SAML Response - could not extract error message."
				);
			} );
		} );
	}

}
