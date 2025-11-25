component {
    public string function getRedirectUri( required any event ){
        if (
            structKeyExists( variables, "redirectURI" )
            && !isNull( variables.redirectURI )
            && len( variables.redirectURI )
        ) {
			return variables.redirectURI;
		}

		var event = requestService.getContext();

        return "#event.getHTMLBaseURL()#cbsso/auth/#variables.name.lcase()#";
	}
}