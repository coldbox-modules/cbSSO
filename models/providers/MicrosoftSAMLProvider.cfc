component accessors="true" implements="cbsso.models.ISSOIntegrationProvider" {

	property name="Name";
	property name="clientId";
	property name="clientSecret";
	property name="authEndpoint";
	property name="redirectUri";
	property name="federationMetadataURL";
	property name="expectedIssuer";
	
	property name="wirebox" inject="wirebox";
	property name="AuthNRequestGenerator" inject="javaloader:cbsso.opensaml.AuthNRequestGenerator";
	property name="responseValidator" inject="javaloader:cbsso.opensaml.AuthResponseValidator";

	variables.name = "Microsoft Entra";

	public function onDIComplete(){
		variables.AuthNRequestGenerator.initOpenSAML();
	}

	public string function getName(){
		return variables.name;
	}

	public string function getRedirectUri(){
		if ( !isNull( variables.redirectUri ) ) {
			return variables.redirectUri;
		}

		var protocol = cgi.HTTPS == "" ? "http://" : "https://";

		return "#protocol##cgi.HTTP_HOST#/cbsso/auth/#variables.name.lcase()#";
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
			var xmlData = xmlParse( data.reREplace( "xmlns="".+?""", "", "all" ) );

			authResponse.setRawResponseData( data );

			try{
				variables.AuthNRequestGenerator.initOpenSAML();
				variables.responseValidator.parseAndValidate( javaCast( "string", data ), variables.expectedIssuer );
			}
			catch( any e ){
				return authResponse
					.setWasSuccessful( false )
					.setRawResponseData( data )
					.setErrorMessage( extractErrorMessage( xmlData ) )
			}
			
			
			if ( !detectSuccess( xmlData ) ) {
				return authResponse
					.setWasSuccessful( false )
					.setRawResponseData( data )
					.setErrorMessage( extractErrorMessage( xmlData ) );
			}

			return authResponse
				.setWasSuccessful( true )
				.setFirstName( extractFirstName( xmlData ) )
				.setLastName( extractLastName( xmlData ) )
				.setEmail( extractEmail( xmlData ) )
				.setUserId( extractUserId( xmlData ) )
				.setRawResponseData( data );
		} catch ( any e ) {
			return authResponse.setWasSuccessful( false ).setErrorMessage( e.message );
		}
	}

	private string function getRawSAMLRequest(){
		var id = "id" & createUUID();

		return AuthNRequestGenerator
			.generateAuthNRequest( variables.clientId, id );
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
			"samlp:Response//samlp:StatusCode[@Value='urn:oasis:names:tc:SAML:2.0:status:Success']"
		).len() == 1;
	}

	private boolean function extractErrorMessage( required xmlDoc ){
		return xmlSearch( xmlDoc, "samlp:Response//samlp:StatusMessage" )[ 1 ].xmlchildren[ 1 ].xmltext;
	}

	private string function extractFirstName( required xmlDoc ){
		return xmlSearch(
			xmlDoc,
			"samlp:Response//Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname']"
		)[ 1 ].xmlchildren[ 1 ].xmltext;
	}

	private string function extractLastName( required xmlDoc ){
		return xmlSearch(
			xmlDoc,
			"samlp:Response//Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname']"
		)[ 1 ].xmlchildren[ 1 ].xmltext;
	}

	private string function extractEmail( required xmlDoc ){
		return xmlSearch(
			xmlDoc,
			"samlp:Response//Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name']"
		)[ 1 ].xmlchildren[ 1 ].xmltext;
	}

	private string function extractUserId( required xmlDoc ){
		return xmlSearch(
			xmlDoc,
			"samlp:Response//Attribute[@Name='http://schemas.microsoft.com/identity/claims/objectidentifier']"
		)[ 1 ].xmlchildren[ 1 ].xmltext;
	}

}
