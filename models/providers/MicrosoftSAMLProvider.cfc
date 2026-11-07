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

	property name="wirebox"    inject="wirebox";
	property name="javaLoader" inject="loader@cbjavaloader";
	property name="AuthNRequestGenerator";
	property name="responseValidator";
	property name="SAMLParsingService" inject="SAMLParsingService@cbsso";
	property name="SAMLRequestTracker" inject="SAMLRequestTracker@cbsso";

	variables.name                    = "Entra";
	variables.federationMetadataURL   = "";
	variables.maxDecodedResponseChars = 1048576;
	variables.certificatesCached      = false;

	public string function getName(){
		return variables.name;
	}

	/**
	 * Stores the URL and nothing more. It used to initialise OpenSAML and fetch the IdP's metadata here,
	 * but every setter on a provider runs inside ProviderService.registerProviders(), i.e. inside the
	 * module's onLoad() - so that turned application boot into "load a 17MB jar and make an outbound HTTPS
	 * call per configured provider", and any failure in either took the whole application down before it
	 * could serve a request. Both now happen on first use, via initializeOpenSAMLLib().
	 */
	public any function setFederationMetadataURL( required string federationMetadataURL ){
		variables.federationMetadataURL = arguments.federationMetadataURL;
		variables.certificatesCached    = false;

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

			// extractStatus below parses attacker-supplied XML before the hardened Java validator sees it,
			// so an unbounded document is a cheap denial of service.
			if ( len( data ) > variables.maxDecodedResponseChars ) {
				throw(
					type    = "MicrosoftSAMLProvider.ResponseTooLarge",
					message = "SAMLResponse decoded to #len( data )# characters, exceeding the #variables.maxDecodedResponseChars# character limit"
				);
			}

			var status = SAMLParsingService.extractStatus( data );

			authResponse.setRawResponseData( data );

			if ( !status.success ) {
				return authResponse
					.setWasSuccessful( false )
					.setRawResponseData( data )
					.setErrorMessage( status.errorMessage );
			}

			var responseInResponseTo = variables.responseValidator.getResponseInResponseTo(
				javacast( "string", data )
			);
			var assertionXML = "";
			var identity     = {};

			try {
				if ( !SAMLRequestTracker.isPending( responseInResponseTo ) ) {
					throw(
						type    = "MicrosoftSAMLProvider.UnknownAuthNRequest",
						message = "SAML Response does not match a pending authentication request"
					);
				}

				// clientId is the SP Entity ID the AuthnRequest was issued under, so it is the Audience the
				// IdP must have named; getRedirectUri() is the ACS URL, so it is the expected Recipient.
				// The final argument binds both the Response and the accepted bearer confirmation to this
				// outstanding AuthnRequest.
				//
				// Needs the classloader context for verification specifically: SignatureValidator.validate
				// resolves crypto providers through the thread context classloader, which on BoxLang is not
				// the one the OpenSAML classes came from. Marshalling alone does not need it -
				// getRawSAMLRequest() and getResponseInResponseTo() go through the same OpenSAML registry
				// unwrapped and work - so do not widen this to "any OpenSAML call".
				assertionXML = runWithClassLoader( function(){
					return variables.responseValidator.parseAndValidateAssertion(
						javacast( "string", data ),
						javacast( "string", variables.expectedIssuer ),
						javacast( "string", variables.clientId ),
						javacast( "string", getRedirectUri( event ) ),
						javacast( "string", responseInResponseTo )
					);
				} );

				// Do not consume a pending request until every validation step succeeds. The atomic consume
				// prevents two concurrent deliveries of the same valid response from both succeeding.
				identity = SAMLParsingService.extractIdentity( assertionXML );
				if ( !SAMLRequestTracker.consume( responseInResponseTo ) ) {
					throw(
						type    = "MicrosoftSAMLProvider.ReplayedAuthNRequest",
						message = "SAML Response matched an authentication request that was already consumed"
					);
				}
			} catch ( any e ) {
				// A validation failure is our verdict on the response, not the IdP's, so the exception is
				// what explains it - the IdP's own account of a rejection was already returned above.
				return authResponse
					.setWasSuccessful( false )
					.setRawResponseData( data )
					.setErrorMessage( e.message );
			}

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

		SAMLRequestTracker.remember( id );

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

	/**
	 * Resolved through cbjavaloader rather than createObject( "java", ... ): ModuleConfig hands the bundled
	 * jar to cbjavaloader's URLClassLoader, which createObject does not consult - it searches the server
	 * classpath and reports "has not been located in the [java] resolver".
	 *
	 * Two readiness conditions, guarded separately. The library is initialised once for the life of the
	 * application, but the certificates come from an outbound fetch that can fail on its own, so guarding
	 * both on the generator meant one transient metadata failure - which happens after the generator is
	 * published - left this provider short-circuiting on every later call with a validator holding no
	 * certificates, and no way back short of an application restart.
	 */
	private void function initializeOpenSAMLLib(){
		if ( isNull( variables.AuthNRequestGenerator ) ) {
			runWithClassLoader( function(){
				var generator = wirebox.getInstance( "javaloader:cbsso.opensaml.AuthNRequestGenerator" );
				var validator = wirebox.getInstance( "javaloader:cbsso.opensaml.AuthResponseValidator" );

				generator.initOpenSAML();

				// Published only once initOpenSAML() has returned. Assigning beforehand would let a failed
				// initialisation leave a provider whose guard above short-circuits, so it could never
				// initialise again for the life of the application.
				variables.AuthNRequestGenerator = generator;
				variables.responseValidator     = validator;
			} );
		}

		if ( variables.certificatesCached ) {
			return;
		}

		// Reached lazily now rather than from setFederationMetadataURL(), so an unset URL arrives here
		// instead of never getting this far. Named rather than left to fail inside cacheCerts, where an
		// empty URL surfaces as an opaque fetch error on the user's first sign-in.
		if ( !len( trim( variables.federationMetadataURL ) ) ) {
			throw(
				type    = "MicrosoftSAMLProvider.MissingConfiguration",
				message = "federationMetadataURL is required but not set",
				detail  = "Set it on the provider definition; it is the source of the signing certificates."
			);
		}

		variables.responseValidator.cacheCerts( variables.federationMetadataURL );

		variables.certificatesCached = true;
	}

	/**
	 * OpenSAML's InitializationService discovers its providers through ServiceLoader, which reads the
	 * *thread context* classloader. On BoxLang that is not cbjavaloader's URLClassLoader, so discovery finds
	 * nothing and initialisation fails; Adobe ColdFusion resolves it without help. Swapped only for the
	 * duration of the call, and restored in a finally so a failure cannot leak the wrong loader into the
	 * request thread.
	 */
	private any function runWithClassLoader( required function callback ){
		if ( !structKeyExists( server, "BoxLang" ) ) {
			return callback();
		}

		var currentThread       = createObject( "java", "java.lang.Thread" ).currentThread();
		var originalClassLoader = currentThread.getContextClassLoader();

		try {
			currentThread.setContextClassLoader( variables.javaLoader.getURLClassLoader() );
			return callback();
		} finally {
			currentThread.setContextClassLoader( originalClassLoader );
		}
	}

}
