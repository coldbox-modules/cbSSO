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

}
