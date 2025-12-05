component singleton {

	public struct function extractUserInfo( required string rawSAMLResponse ){
		var data = {
			"success"      : false,
			"errorMessage" : "",
			"error"        : "",
			"firstName"    : "",
			"lastName"     : "",
			"email"        : "",
			"userId"       : ""
		};
		var xmlData = xmlParse( rawSAMLResponse.reReplace( "xmlns="".+?""", "", "all" ) );

		try {
			data.success = detectSuccess( xmlData );

			if ( !data.success ) {
				data.errorMessage = extractErrorMessage( xmlData );
				return data;
			}

			try {
				data.firstName = extractFirstName( xmlData );
				data.lastName  = extractLastName( xmlData );
				data.email     = extractEmail( xmlData );
				data.userId    = extractUserId( xmlData );

				return data;
			} catch ( any e ) {
				data.success      = false;
				data.errorMessage = "Failed to extract user information: " & e.message;
				data.error        = e;
				return data;
			}
		} catch ( any e ) {
			data.success      = false;
			data.errorMessage = "Failed to extract user information: " & e.message;
			data.error        = e;
		}

		return data;
	}

	private boolean function detectSuccess( required xmlDoc ){
		return xmlSearch( xmlDoc, "//samlp:StatusCode[@Value='urn:oasis:names:tc:SAML:2.0:status:Success']" ).len() == 1;
	}

	private string function extractErrorMessage( required xmlDoc ){
		try {
			return xmlSearch( xmlDoc, "//samlp:StatusMessage" )[ 1 ].xmlchildren[ 1 ].xmltext;
		} catch ( any e ) {
			try {
				var nodes = xmlSearch( xmlDoc, "//*" );
				for ( var node in nodes ) {
					if ( node.xmlname.toLowerCase().contains( "statusmessage" ) ) {
						return node.xmltext;
					}
				}
			} catch ( any ex ) {
				// do nothing
			}
			return "Invalid SAML Response - could not extract error message.";
		}
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
