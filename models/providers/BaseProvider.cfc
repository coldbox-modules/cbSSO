component {

	public string function getRedirectUri( required any event ){
		if (
			structKeyExists( variables, "redirectURI" )
			&& !isNull( variables.redirectURI )
			&& len( variables.redirectURI )
		) {
			return variables.redirectURI;
		}

		return "#event.getHTMLBaseURL()#cbsso/auth/#variables.name.lcase()#";
	}

	/**
	 * @deprecated Misspelled alias kept for backward compatibility. Use startAuthenticationWorkflow() instead. Will be removed in the next major release.
	 */
	public string function startAuthenticationWorflow( required any event ){
		return startAuthenticationWorkflow( arguments.event );
	}

}
