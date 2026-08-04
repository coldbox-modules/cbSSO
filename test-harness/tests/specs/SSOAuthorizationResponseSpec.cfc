/**
 * SSOAuthorizationResponse Spec
 */
component extends="coldbox.system.testing.BaseTestCase" {

	this.loadColdbox   = true;
	this.unLoadColdBox = false;

	function beforeAll(){
		super.beforeAll();
		setup();
	}

	function afterAll(){
		super.afterAll();
	}

	function run( testResults, testBox ){
		describe( "SSO Authorization Response", function(){
			beforeEach( function( currentSpec ){
				setup();
				response = getInstance( "SSOAuthorizationResponse@cbsso" );
			} );

			it( "can be created", function(){
				expect( response ).toBeComponent();
			} );

			it( "reports an unpopulated response as unsuccessful under both spellings", function(){
				expect( response.wasSuccessful() ).toBeFalse();
				expect( response.getWasSuccessful() ).toBeFalse();
			} );

			it( "does not throw on any getter when only the failure fields are populated", function(){
				response.setWasSuccessful( false ).setErrorMessage( "IdP rejected the assertion" );

				expect( response.wasSuccessful() ).toBeFalse();
				expect( response.getWasSuccessful() ).toBeFalse();
				expect( response.getErrorMessage() ).toBe( "IdP rejected the assertion" );
				expect( response.getRawResponseData() ).toBe( {} );
				expect( response.getSessionId() ).toBe( "" );
				expect( response.getUserId() ).toBe( "" );
				expect( response.getEmail() ).toBe( "" );
				expect( response.getName() ).toBe( "" );
				expect( response.getFirstName() ).toBe( "" );
				expect( response.getLastName() ).toBe( "" );
				expect( response.getClaims() ).toBe( {} );
				expect( response.getClaim( "urn:oid:0.9.2342.19200300.100.1.1" ) ).toBe( "" );
				expect( response.getNameId() ).toBe( "" );
				expect( response.getNameIdFormat() ).toBe( "" );
			} );

			it( "returns the caller's default for a claim the IdP did not assert", function(){
				response.setClaims( { "email" : "jdoe@example.com" } );

				expect( response.getClaim( "employeeNumber", "unknown" ) ).toBe( "unknown" );
			} );

			it( "holds every claim as an array, whatever the provider handed it", function(){
				response.setClaims( {
					"email"  : "jdoe@example.com",
					"groups" : [ "Analysts", "Engineering" ]
				} );

				expect( response.getClaims() ).toBe( {
					"email"  : [ "jdoe@example.com" ],
					"groups" : [ "Analysts", "Engineering" ]
				} );
			} );

			it( "returns the first value of a multi-valued claim", function(){
				response.setClaims( { "groups" : [ "Analysts", "Engineering" ] } );

				expect( response.getClaim( "groups" ) ).toBe( "Analysts" );
				expect( response.getClaims()[ "groups" ] ).toHaveLength( 2 );
			} );

			it( "reads a claim back under any casing, since the IdP chooses the name", function(){
				response.setClaims( { "employeeNumber" : "A1B2C3" } );

				expect( response.getClaim( "EMPLOYEENUMBER" ) ).toBe( "A1B2C3" );
			} );

			it( "stringifies simple values, so a claim always reads as a string", function(){
				response.setClaims( { "emailVerified" : true, "authTime" : 1767225600 } );

				expect( response.getClaim( "emailVerified" ) ).toBe( "true" );
				expect( response.getClaim( "authTime" ) ).toBe( "1767225600" );
			} );

			it( "leaves out a claim whose value is not simple - a nested object in an id token", function(){
				response.setClaims( {
					"email"   : "jdoe@example.com",
					"address" : { "locality" : "Houston" }
				} );

				expect( response.getClaims() ).notToHaveKey( "address" );
				expect( response.getClaim( "address" ) ).toBe( "" );
				expect( response.getClaims() ).toHaveKey( "email" );
			} );

			it( "reads back the NameID and its format", function(){
				response
					.setNameId( "V3JpdHRlbkJ5T3J0dXNTb2x1dGlvbnM9" )
					.setNameIdFormat( "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" );

				expect( response.getNameId() ).toBe( "V3JpdHRlbkJ5T3J0dXNTb2x1dGlvbnM9" );
				expect( response.getNameIdFormat() ).toBe( "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" );
			} );

			it( "reads back a Name set without any FirstName - as GitHubProvider does", function(){
				response.setWasSuccessful( true ).setName( "John Doe" );

				expect( response.getName() ).toBe( "John Doe" );
				expect( response.getFirstName() ).toBe( "" );
			} );

			it( "falls back to FirstName + LastName when only those are set - as MicrosoftSAMLProvider does", function(){
				response
					.setWasSuccessful( true )
					.setFirstName( "John" )
					.setLastName( "Doe" );

				expect( response.getName() ).toBe( "John Doe" );
			} );

			it( "returns populated values when the authorization succeeded", function(){
				response
					.setWasSuccessful( true )
					.setSessionId( "session-123" )
					.setUserId( "user-456" )
					.setEmail( "jdoe@example.com" )
					.setName( "John Doe" )
					.setFirstName( "John" )
					.setLastName( "Doe" )
					.setRawResponseData( { "foo" : "bar" } );

				expect( response.wasSuccessful() ).toBeTrue();
				expect( response.getSessionId() ).toBe( "session-123" );
				expect( response.getUserId() ).toBe( "user-456" );
				expect( response.getEmail() ).toBe( "jdoe@example.com" );
				expect( response.getName() ).toBe( "John Doe" );
				expect( response.getFirstName() ).toBe( "John" );
				expect( response.getLastName() ).toBe( "Doe" );
				expect( response.getRawResponseData() ).toBe( { "foo" : "bar" } );
				expect( response.getErrorMessage() ).toBe( "" );
			} );
		} );
	}

}
