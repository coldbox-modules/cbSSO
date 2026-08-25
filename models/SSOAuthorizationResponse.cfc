component implements="cbsso.models.ISSOAuthorizationResponse" accessors=true {

	property name="wasSuccessful";
	property name="SessionId";
	property name="UserId";
	property name="Email";
	property name="Name";
	property name="FirstName";
	property name="LastName";
	property name="RawResponseData";
	property name="ErrorMessage";
	property name="Claims";
	property name="NameId";
	property name="NameIdFormat";

	/**
	 * Seeds every property, so a response that only ever had its failure fields populated still
	 * reads back cleanly. `wasSuccessful` is deliberately absent - see wasSuccessful().
	 */
	function init(){
		variables.SessionId       = "";
		variables.UserId          = "";
		variables.Email           = "";
		variables.Name            = "";
		variables.FirstName       = "";
		variables.LastName        = "";
		variables.ErrorMessage    = "";
		variables.RawResponseData = {};
		variables.Claims          = {};
		variables.NameId          = "";
		variables.NameIdFormat    = "";

		return this;
	}

	public boolean function wasSuccessful(){
		return successFlag();
	}

	/**
	 * `accessors=true` generates this from the property, and the generated version hands back the
	 * same-named method when nothing has been set. Overridden so both spellings are safe.
	 */
	public boolean function getWasSuccessful(){
		return successFlag();
	}

	/**
	 * The `wasSuccessful` property and method share a name, so `variables.wasSuccessful` is the
	 * method itself until `setWasSuccessful()` replaces it with a boolean - which is also why this
	 * lives under a name of its own, and why `init()` cannot seed the property.
	 */
	private boolean function successFlag(){
		var value = variables.wasSuccessful;
		return isBoolean( value ) && value;
	}

	public string function getSessionId(){
		return variables.SessionId;
	}

	public string function getUserId(){
		return variables.UserId;
	}

	public string function getEmail(){
		return variables.Email;
	}

	public string function getName(){
		// SAML providers populate FirstName/LastName and never Name, oAuth providers do the reverse
		return len( variables.Name ) ? variables.Name : trim( variables.FirstName & " " & variables.LastName );
	}

	public string function getFirstName(){
		return variables.FirstName;
	}

	public string function getLastName(){
		return variables.LastName;
	}

	public any function getRawResponseData(){
		return variables.RawResponseData;
	}

	public string function getErrorMessage(){
		return variables.ErrorMessage;
	}

	/**
	 * Everything the IdP asserted, keyed by the name it used - the WS-Federation claim URIs for SAML, the
	 * id token or user info keys for oAuth. The typed getters above cover what every provider has in
	 * common; this is where anything else lives, so reaching a group, role or employee-number claim does
	 * not need a getter of its own.
	 */
	public struct function getClaims(){
		return variables.Claims;
	}

	/**
	 * The first value of a claim, which is what a caller wants in all but the multi-valued case. Struct
	 * keys are case-insensitive, so the name does not have to match the IdP's casing.
	 */
	public string function getClaim( required string name, string defaultValue = "" ){
		if ( !variables.Claims.keyExists( arguments.name ) || !variables.Claims[ arguments.name ].len() ) {
			return arguments.defaultValue;
		}

		return variables.Claims[ arguments.name ][ 1 ];
	}

	/**
	 * Normalised here rather than in each provider, so `getClaims()` reads the same way whatever produced
	 * it: every claim holds an array, because a SAML attribute and an oAuth claim can both be
	 * multi-valued. Values that are not simple - a nested object in an id token - are left out, and stay
	 * reachable on `getRawResponseData()`.
	 */
	public any function setClaims( required struct claims ){
		var normalised = {};

		for ( var name in arguments.claims ) {
			var value = arguments.claims[ name ];

			if ( isSimpleValue( value ) ) {
				normalised[ name ] = [ toString( value ) ];
				continue;
			}

			if ( !isArray( value ) ) {
				continue;
			}

			normalised[ name ] = [];

			for ( var entry in value ) {
				if ( isSimpleValue( entry ) ) {
					normalised[ name ].append( toString( entry ) );
				}
			}
		}

		variables.Claims = normalised;

		return this;
	}

	/**
	 * The Subject's NameID, which SAML always carries and no claim can substitute for. Empty for oAuth
	 * providers, and for a SAML assertion that identifies its subject by attribute alone.
	 */
	public string function getNameId(){
		return variables.NameId;
	}

	/**
	 * The NameID's Format. Read it before treating a NameID as an identifier: Entra's default is a
	 * pairwise value scoped to one app registration, so the same person arrives under a different NameID
	 * at a second registration in the same tenant.
	 */
	public string function getNameIdFormat(){
		return variables.NameIdFormat;
	}

}
