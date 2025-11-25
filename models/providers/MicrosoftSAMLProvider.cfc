component
	accessors="true"
	extends="BaseProvider"
	implements="cbsso.models.ISSOIntegrationProvider"
{

	property name="Name";
	property name="clientId";
	property name="clientSecret";
	property name="authEndpoint";
	property name="redirectUri";
	property name="federationMetadataURL";
	property name="expectedIssuer";

	property name="wirebox"               inject="wirebox";
	property name="AuthNRequestGenerator" inject="javaloader:cbsso.opensaml.AuthNRequestGenerator";
	property name="responseValidator"     inject="javaloader:cbsso.opensaml.AuthResponseValidator";
	property name="SAMLParsingService"     inject="SAMLParsingService@cbsso";

	variables.name = "Microsoft Entra";

	public function onDIComplete(){
		variables.AuthNRequestGenerator.initOpenSAML();
	}

	public string function getName(){
		return variables.name;
	}

	public any function setFederationMetadataURL( required string federationMetadataURL ){
		variables.federationMetadataURL = federationMetadataURL;

		responseValidator.cacheCerts( variables.federationMetadataURL );

		return this;
	}

	public string function startAuthenticationWorflow( required any event ){
		var encoded = encodeForURL( deflateAndBase64Enocde( getRawSAMLRequest() ) );

		return "#variables.authEndpoint#?SAMLRequest=#encoded#";
	}

	public any function processAuthorizationEvent( required any event ){
		var authResponse = wirebox.getInstance( "SSOAuthorizationResponse@cbsso" );

		try {
			var decoded = binaryDecode( event.getValue( "SAMLResponse" ), "base64" );
			var data    = charsetEncode( decoded, "utf-8" );
			var samlData = SAMLParsingService.extractUserInfo( data );

			authResponse.setRawResponseData( data );

			try {
				variables.AuthNRequestGenerator.initOpenSAML();
				variables.responseValidator.parseAndValidate(
					javacast( "string", data ),
					variables.expectedIssuer
				);
			} catch ( any e ) {
				return authResponse
					.setWasSuccessful( false )
					.setRawResponseData( data )
					.setErrorMessage( extractErrorMessage( xmlData ) )
			}


			if ( !samlData.success ) {
				return authResponse
					.setWasSuccessful( false )
					.setRawResponseData( data )
					.setErrorMessage( samlData.errorMessage );
			}

			return authResponse
				.setWasSuccessful( true )
				.setFirstName( samlData.firstName )
				.setLastName( samlData.lastName )
				.setEmail( samlData.email )
				.setUserId( samlData.userId )
				.setRawResponseData( data );
		} catch ( any e ) {
			return authResponse.setWasSuccessful( false ).setErrorMessage( e.message );
		}
	}

	private string function getRawSAMLRequest(){
		var id = "id" & createUUID();

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

	private boolean function detectSuccess( required xmlDoc ){
		return xmlSearch(
			xmlDoc,
			"//samlp:StatusCode[@Value='urn:oasis:names:tc:SAML:2.0:status:Success']"
		).len() == 1;
	}

	private boolean function extractErrorMessage( required xmlDoc ){
		return xmlSearch( xmlDoc, "//samlp:StatusMessage" )[ 1 ].xmlchildren[ 1 ].xmltext;
	}

	private string function extractFirstName( required xmlDoc ){
		return xmlSearch(
			xmlDoc,
			"//Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname']"
		)[ 1 ].xmlchildren[ 1 ].xmltext;
	}

	private string function extractLastName( required xmlDoc ){
		return xmlSearch(
			xmlDoc,
			"//Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname']"
		)[ 1 ].xmlchildren[ 1 ].xmltext;
	}

	private string function extractEmail( required xmlDoc ){
		return xmlSearch(
			xmlDoc,
			"//Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']"
		)[ 1 ].xmlchildren[ 1 ].xmltext;
	}

	private string function extractUserId( required xmlDoc ){
		return xmlSearch(
			xmlDoc,
			"//Attribute[@Name='http://schemas.microsoft.com/identity/claims/objectidentifier']"
		)[ 1 ].xmlchildren[ 1 ].xmltext;
	}

}
