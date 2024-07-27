component
	accessors="true"
	implements  = "oAuth.models.ISSOIntegrationProvider"
{
	property name = "Name";
    property name = "clientId";
    property name = "clientSecret";
    property name = "authEndpoint";
    property name = "redirectUri";

    property name="wirebox" inject="wirebox";

    variables.name = "Microsoft Entra";

    public string function getName() {
        return variables.name;
    }

    public string function getIconURL(){
        return "";
    }

    public string function getRedirectUri(){
        if( !isNull( variables.redirectUri ) ){
            return variables.redirectUri;
        }

        var protocol = cgi.HTTPS == "" ? "http://" : "https://";

        return "#protocol##cgi.HTTP_HOST#/oauth/auth/#variables.name.lcase()#";
    }
    
    public any function populateFromSettings( required struct settings ){
        variables.Name = settings.Name;
        variables.clientId = settings.clientId;
        variables.clientSecret = settings.clientSecret;
        variables.authEndpoint = settings.authEndpoint;
        variables.redirectUri = settings.redirectUri;

        return this;
    }

    public string function startAuthenticationWorflow( required any event ){
        var encoded = encodeForURL( deflateAndBase64Enocde( getRawSAMLRequest() ) );

        return "#variables.authEndpoint#?SAMLRequest=#encoded#";
    }

    public any function processAuthorizationEvent( required any event ){
        var authResponse = wirebox.getInstance( "SSOAuthorizationResponse@oauth" );

        try {
            var decoded = binaryDecode( event.getValue( "SAMLResponse" ), "base64" );
            var data = charsetEncode( decoded, "utf-8" );
            writeDUmp( data );
            abort;
            var xmlData = xmlParse( data.reREplace( 'xmlns=".+?"', '', "all" ) );
            authResponse.setRawResponseData( data );

            if( !detectSuccess( xmlData ) ){
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
        }
        catch( any e ){
            return authResponse
                .setWasSuccessful( false )
                .setErrorMessage( e.message );
        }
    }

    private string function getRawSAMLRequest(){
        var id = "id" & createUUID();
        return '<samlp:AuthnRequest
        xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
        ID="#id#"
        Version="2.0" IssueInstant="#now().datetimeFormat( "yyyy-mm-dd'T'HH:nn:ss.lZ" )#"
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
        <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">#variables.clientId#</Issuer>
      </samlp:AuthnRequest>';
    }

    private string function deflateAndBase64Enocde( required string inputString ){
        var output = createObject( "java", "java.nio.ByteBuffer" ).allocate( 1024 ).array();
        var Deflater = createObject( "java", "java.util.zip.Deflater" );
        var compresser = Deflater.init( Deflater[ "DEFAULT_COMPRESSION"], true);
        compresser.setStrategy( compresser[ "DEFAULT_STRATEGY" ] );
        compresser.setInput(javaCast( "string", inputString).getBytes( "UTF-8" ));
        compresser.finish();
        var compressedDataLength = compresser.deflate(output);
        compresser.end();

        output = javaCast( "byte[]", ArraySlice( output, 1, compressedDataLength ) );
        return binaryEncode( output, "base64" );
    }

    private boolean function detectSuccess( required xmlDoc ){
        return xmlSearch( xmlDoc, "samlp:Response//samlp:StatusCode[@Value='urn:oasis:names:tc:SAML:2.0:status:Success']" ).len() == 1;
    }

    private boolean function extractErrorMessage( required xmlDoc ){
        return xmlSearch( xmlDoc, "samlp:Response//samlp:StatusMessage" )[1].xmlchildren[1].xmltext;
    }

    private string function extractFirstName( required xmlDoc ){
        return xmlSearch( xmlDoc, "samlp:Response//Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname']" )[1].xmlchildren[1].xmltext;
    }

    private string function extractLastName( required xmlDoc ){
        return xmlSearch( xmlDoc, "samlp:Response//Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname']" )[1].xmlchildren[1].xmltext;
    }

    private string function extractEmail( required xmlDoc ){
        return xmlSearch( xmlDoc, "samlp:Response//Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name']" )[1].xmlchildren[1].xmltext;
    }

    private string function extractUserId( required xmlDoc ){
        return xmlSearch( xmlDoc, "samlp:Response//Attribute[@Name='http://schemas.microsoft.com/identity/claims/objectidentifier']" )[1].xmlchildren[1].xmltext;
    }

}
