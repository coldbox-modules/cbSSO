component
	accessors ="true"
	extends   ="BaseProvider"
	implements="cbsso.models.ISSOIntegrationProvider"
{

	property name="Name";
	property name="clientId";
	property name="clientSecret";
	property name="authEndpoint";
	property name="redirectUri";
	property name="federationMetadataURL";
	property name="expectedIssuer";

	property name="wirebox" inject="wirebox";
	property name="AuthNRequestGenerator";
	property name="responseValidator";
	property name="SAMLParsingService" inject="SAMLParsingService@cbsso";

	variables.name                  = "Entra";
	variables.federationMetadataURL = "";

	public string function getName(){
		return variables.name;
	}

	public any function setFederationMetadataURL( required string federationMetadataURL ){
		variables.federationMetadataURL = federationMetadataURL;

		initializeOpenSAMLLib();

		responseValidator.cacheCerts( variables.federationMetadataURL );

		return this;
	}

	public string function startAuthenticationWorflow( required any event ){
		var encoded = encodeForURL( deflateAndBase64Enocde( getRawSAMLRequest() ) );

		return "#variables.authEndpoint#?SAMLRequest=#encoded#";
	}

	public any function processAuthorizationEvent( required any event ){
		var authResponse = wirebox.getInstance( "SSOAuthorizationResponse@cbsso" );

		initializeOpenSAMLLib();

		try {
			var decoded = binaryDecode( event.getValue( "SAMLResponse" ), "base64" );
			var data    = charsetEncode( decoded, "utf-8" );
			var status  = SAMLParsingService.extractStatus( data );

			authResponse.setRawResponseData( data );

			if ( !status.success ) {
				return authResponse
					.setWasSuccessful( false )
					.setRawResponseData( data )
					.setErrorMessage( status.errorMessage );
			}

			try {
				var assertionXML = variables.responseValidator.parseAndValidateAssertion(
					javacast( "string", data ),
					variables.expectedIssuer
				);
			} catch ( any e ) {
				// A validation failure is our verdict on the response, not the IdP's, so the exception is
				// what explains it - the IdP's own account of a rejection was already returned above.
				return authResponse
					.setWasSuccessful( false )
					.setRawResponseData( data )
					.setErrorMessage( e.message );
			}

			// Read from the assertion the validator returned, never from `data`: that assertion is the one
			// element whose signature verified, so nothing else in the response can supply a claim or a
			// NameID and have it treated as identity.
			var identity = SAMLParsingService.extractIdentity( assertionXML );

			// Set only here, not on the failure returns above: an assertion whose signature did not verify
			// has asserted nothing, and a consumer reading a claim off it would be trusting the sender.
			return authResponse
				.setWasSuccessful( true )
				.setFirstName( identity.firstName )
				.setLastName( identity.lastName )
				.setEmail( identity.email )
				.setUserId( identity.userId )
				.setClaims( identity.claims )
				.setNameId( identity.nameId )
				.setNameIdFormat( identity.nameIdFormat )
				.setRawResponseData( data );
		} catch ( any e ) {
			return authResponse.setWasSuccessful( false ).setErrorMessage( e.message );
		}
	}

	private string function getRawSAMLRequest(){
		var id = "id" & createUUID();

		initializeOpenSAMLLib();

		return AuthNRequestGenerator.generateAuthNRequest( variables.clientId, id );
	}

	private string function deflateAndBase64Enocde( required string inputString ){
		var output     = createObject( "java", "java.nio.ByteBuffer" ).allocate( 1024 ).array();
		var Deflater   = createObject( "java", "java.util.zip.Deflater" );
		var compresser = Deflater.init( Deflater[ "DEFAULT_COMPRESSION" ], true );
		compresser.setStrategy( compresser[ "DEFAULT_STRATEGY" ] );
		compresser.setInput( javacast( "string", inputString ).getBytes( "UTF-8" ) );
		compresser.finish();
		var compressedDataLength = compresser.deflate( output );
		compresser.end();

		output = javacast( "byte[]", arraySlice( output, 1, compressedDataLength ) );
		return binaryEncode( output, "base64" );
	}

	private void function initializeOpenSAMLLib(){
		if ( !isNull( variables.AuthNRequestGenerator ) ) {
			return;
		}

		variables.AuthNRequestGenerator = createObject( "java", "cbsso.opensaml.AuthNRequestGenerator" );
		variables.responseValidator     = createObject( "java", "cbsso.opensaml.AuthResponseValidator" );

		variables.AuthNRequestGenerator.initOpenSAML();
		responseValidator.cacheCerts( variables.federationMetadataURL );
	}

}
