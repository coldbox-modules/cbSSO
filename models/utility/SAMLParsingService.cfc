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

	variables.nameIdFormats = {
		"transient"    : "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
		"emailAddress" : "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
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

				// Populated before the subject is resolved, so a response that fails to identify one
				// still reports what the IdP actually asserted.
				data.claims       = extractClaims( xmlData );
				data.nameId       = subject.value;
				data.nameIdFormat = subject.format;

				data.firstName = claimValue( data.claims, variables.claimNames.givenName );
				data.lastName  = claimValue( data.claims, variables.claimNames.surname );
				data.email     = extractEmail( data.claims, subject );
				data.userId    = extractUserId( data.claims, subject );

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
	 * Falls back to the `name` claim, which carries the UPN when no email claim is mapped, and then to the
	 * NameID when its Format says the value is an email address - the format an IdP that federates on email
	 * rather than on attributes will use.
	 */
	private string function extractEmail( required struct claims, required struct subject ){
		var email = claimValue( claims, variables.claimNames.emailAddress );

		if ( !len( email ) ) {
			email = claimValue( claims, variables.claimNames.name );
		}

		if ( !len( email ) && subject.format == variables.nameIdFormats.emailAddress ) {
			email = subject.value;
		}

		return email;
	}

	/**
	 * SAML 2.0 requires none of the attributes the typed fields are read from. An AttributeStatement is
	 * optional throughout Core, and the Web Browser SSO profile (Profiles 4.1.4.2) asks only for a Subject
	 * carrying a bearer SubjectConfirmation. The names read here are WS-Federation and Microsoft URIs that
	 * only an Entra-shaped IdP asserts, so treating one as mandatory rejects a conformant assertion from
	 * ADFS, Shibboleth or Okta over a display name.
	 *
	 * What a consumer cannot do without is something to identify the subject by, so that is the only thing
	 * this refuses on. The object identifier is preferred because it is stable across app registrations,
	 * and the NameID stands in when it is absent - unless it is transient, which the specification defines
	 * as valid for a single session, so keying identity to it would enrol the same person again on every
	 * login. Whether the value it does return is portable is the caller's to judge from `nameIdFormat`.
	 */
	private string function extractUserId( required struct claims, required struct subject ){
		var objectIdentifier = claimValue( claims, variables.claimNames.objectIdentifier );

		if ( len( objectIdentifier ) ) {
			return objectIdentifier;
		}

		if ( len( subject.value ) && subject.format != variables.nameIdFormats.transient ) {
			return subject.value;
		}

		var reason = len( subject.value ) ? "its NameID is transient" : "it carries no NameID";

		throw(
			type    = "SAMLParsingService.NoSubjectIdentifier",
			message = "The assertion identifies no subject: it asserts no '#variables.claimNames.objectIdentifier#' claim, and #reason#."
		);
	}

	private string function claimValue( required struct claims, required string name ){
		return claims.keyExists( name ) && claims[ name ].len() ? claims[ name ][ 1 ] : "";
	}

}
