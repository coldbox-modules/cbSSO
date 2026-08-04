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
