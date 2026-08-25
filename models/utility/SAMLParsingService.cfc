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

	/**
	 * Read from the unvalidated Response on purpose: when the IdP itself rejected the login there is no
	 * assertion to validate, and the StatusMessage the IdP wrote is the only account of why. Nothing here
	 * is identity - a status says whether to carry on, never who signed in.
	 */
	public struct function extractStatus( required string rawSAMLResponse ){
		try {
			var xmlData = parseSAML( arguments.rawSAMLResponse );

			if ( detectSuccess( xmlData ) ) {
				return { "success" : true, "errorMessage" : "" };
			}

			return {
				"success"      : false,
				"errorMessage" : extractErrorMessage( xmlData )
			};
		} catch ( any e ) {
			return {
				"success"      : false,
				"errorMessage" : "Invalid SAML Response - could not be read: #e.message#"
			};
		}
	}

	/**
	 * Takes the assertion whose signature verified, not the Response that carried it, and reads nothing it
	 * was not handed. Given a whole Response this would match attribute and NameID nodes anywhere in the
	 * document, including unsigned ones a sender can add at will - so identity would no longer be bound to
	 * what the IdP signed.
	 *
	 * Throws rather than reporting a flag: there is no partial identity worth returning, and every caller
	 * is already inside a try/catch because validation throws.
	 */
	public struct function extractIdentity( required string assertionXML ){
		var xmlData = parseSAML( arguments.assertionXML );
		var claims  = extractClaims( xmlData );
		var subject = extractSubjectNameId( xmlData );

		return {
			"firstName"    : claimValue( claims, variables.claimNames.givenName ),
			"lastName"     : claimValue( claims, variables.claimNames.surname ),
			"email"        : extractEmail( claims, subject ),
			"userId"       : extractUserId( claims, subject ),
			"nameId"       : subject.value,
			"nameIdFormat" : subject.format,
			"claims"       : claims
		};
	}

	/**
	 * extractStatus() reaches this with the raw response, before any signature has been verified, on an
	 * endpoint that needs no authentication - so the parser is hardened here rather than trusted.
	 *
	 * BoxLang's xmlParse resolves external general and parameter entities and permits DOCTYPE: XML.java's
	 * newDocumentBuilder() sets disallow-doctype-decl to false and never sets FEATURE_SECURE_PROCESSING or
	 * either external-entity feature, and passing `{ allowExternalEntities : false }` does nothing because
	 * XMLParse declares a single argument. Refusing the declaration is what closes every entity vector at
	 * once - reading container files out of band, driving outbound requests, and holding a request thread
	 * open on an unroutable address. A SAML response has no legitimate use for a DOCTYPE.
	 *
	 * The leading-"<" check is a second primitive, not the same one: xmlParse treats input that does not
	 * begin with "<" as a path or URL and fetches it.
	 */
	private any function parseSAML( required string samlXML ){
		var document = trim( arguments.samlXML );

		if ( !document.startsWith( "<" ) ) {
			throw( type = "SAMLParsingService.UnsafeDocument", message = "SAML document is not XML" );
		}

		if ( findNoCase( "<!DOCTYPE", document ) ) {
			throw(
				type    = "SAMLParsingService.UnsafeDocument",
				message = "SAML document declares a DOCTYPE, which is not permitted"
			);
		}

		return xmlParse( document.reReplace( "xmlns="".+?""", "", "all" ) );
	}

	/**
	 * Matched on local-name() rather than the `samlp:` prefix. parseSAML() strips only the default namespace
	 * declaration, so `xmlns:samlp` survives on the document - but BoxLang's xmlSearch does not resolve a
	 * prefixed XPath against a prefix declared in the document, so `//samlp:StatusCode` finds nothing there
	 * and a valid, signed, successful assertion is reported as a failure. local-name() is the form that
	 * behaves the same on every engine.
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
