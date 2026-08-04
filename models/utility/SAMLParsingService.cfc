component singleton {

	/**
	 * The WS-Federation and Microsoft claim URIs the typed fields are derived from. Every other attribute
	 * the IdP asserted is reachable through `claims`, under the name the IdP used.
	 */
	variables.claimNames = {
		"givenName"        : "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
		"surname"          : "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
		"name"             : "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
		"emailAddress"     : "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		"objectIdentifier" : "http://schemas.microsoft.com/identity/claims/objectidentifier"
	};

	public struct function extractUserInfo( required string rawSAMLResponse ){
		var data = {
			"success"      : false,
			"errorMessage" : "",
			"error"        : "",
			"firstName"    : "",
			"lastName"     : "",
			"email"        : "",
			"userId"       : "",
			"nameId"       : "",
			"nameIdFormat" : "",
			"claims"       : {}
		};
		var xmlData = xmlParse( rawSAMLResponse.reReplace( "xmlns="".+?""", "", "all" ) );

		try {
			data.success = detectSuccess( xmlData );

			if ( !data.success ) {
				data.errorMessage = extractErrorMessage( xmlData );
				return data;
			}

			try {
				var subject = extractSubjectNameId( xmlData );

				// Populated before the required claims are read, so a response that fails on a missing
				// one still reports what the IdP actually asserted.
				data.claims       = extractClaims( xmlData );
				data.nameId       = subject.value;
				data.nameIdFormat = subject.format;

				data.firstName = requiredClaim( data.claims, variables.claimNames.givenName );
				data.lastName  = requiredClaim( data.claims, variables.claimNames.surname );
				data.email     = extractEmail( data.claims );
				data.userId    = requiredClaim( data.claims, variables.claimNames.objectIdentifier );

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

	/**
	 * Matched on local-name() rather than the `samlp:` prefix. extractUserInfo() strips only the default
	 * namespace declaration, so `xmlns:samlp` survives on the document - but BoxLang's xmlSearch does not
	 * resolve a prefixed XPath against a prefix declared in the document, so `//samlp:StatusCode` finds
	 * nothing there and a valid, signed, successful assertion is reported as a failure. local-name() is
	 * the form that behaves the same on every engine.
	 */
	private boolean function detectSuccess( required xmlDoc ){
		return xmlSearch(
			xmlDoc,
			"//*[local-name()='StatusCode' and @Value='urn:oasis:names:tc:SAML:2.0:status:Success']"
		).len() == 1;
	}

	private string function extractErrorMessage( required xmlDoc ){
		try {
			return xmlSearch( xmlDoc, "//*[local-name()='StatusMessage']" )[ 1 ].xmlchildren[ 1 ].xmltext;
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

	/**
	 * Every asserted attribute, keyed by its `Name` and always holding an array - a claim may carry more
	 * than one AttributeValue (Entra group and role claims routinely do), and an IdP may split one claim
	 * across repeated Attribute elements.
	 */
	private struct function extractClaims( required xmlDoc ){
		var claims = {};

		for ( var node in xmlSearch( xmlDoc, "//*[local-name()='Attribute'][@Name]" ) ) {
			var name = trim( node.xmlAttributes.Name );

			if ( !len( name ) ) {
				continue;
			}

			if ( !claims.keyExists( name ) ) {
				claims[ name ] = [];
			}

			for ( var valueNode in node.xmlChildren ) {
				if ( listLast( valueNode.xmlName, ":" ) == "AttributeValue" ) {
					claims[ name ].append( trim( valueNode.xmlText ) );
				}
			}
		}

		return claims;
	}

	/**
	 * The Format matters as much as the value: Entra's default is a pairwise identifier scoped to the app
	 * registration, stable within that registration and meaningless outside it. A consumer cannot tell a
	 * portable identifier from a scoped one without it.
	 */
	private struct function extractSubjectNameId( required xmlDoc ){
		var nodes = xmlSearch( xmlDoc, "//*[local-name()='Subject']/*[local-name()='NameID']" );

		if ( !nodes.len() ) {
			return { "value" : "", "format" : "" };
		}

		var attributes = nodes[ 1 ].xmlAttributes;

		return {
			"value"  : trim( nodes[ 1 ].xmlText ),
			"format" : attributes.keyExists( "Format" ) ? trim( attributes.Format ) : ""
		};
	}

	/**
	 * Falls back to the `name` claim, which carries the UPN when no email claim is mapped.
	 */
	private string function extractEmail( required struct claims ){
		var email = claimValue( claims, variables.claimNames.emailAddress );

		return len( email ) ? email : claimValue( claims, variables.claimNames.name );
	}

	private string function claimValue( required struct claims, required string name ){
		return claims.keyExists( name ) && claims[ name ].len() ? claims[ name ][ 1 ] : "";
	}

	/**
	 * Still throws when the claim is absent, so an assertion missing one of the values the typed fields
	 * are built from fails exactly as it did before the claim set was exposed. Whether a missing
	 * display-name claim should fail a login at all is a separate question from reaching the claims.
	 */
	private string function requiredClaim( required struct claims, required string name ){
		if ( !claims.keyExists( name ) ) {
			throw(
				type    = "SAMLParsingService.MissingClaim",
				message = "The assertion contains no '#name#' claim."
			);
		}

		return claimValue( claims, name );
	}

}
