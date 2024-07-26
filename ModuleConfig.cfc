/**
 * Copyright Since 2005 ColdBox Framework by Luis Majano and Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 */
component {

	// Module Properties
	this.title       = "oAuth";
	this.author      = "Ortus Solutions";
	this.webURL      = "https://www.ortussolutions.com";
	this.description = "@MODULE_DESCRIPTION@";
	this.version     = "@build.version@+@build.number@";

	// Model Namespace
	this.modelNamespace = "oAuth";
	this.autoMapModels = true;
	// CF Mapping
	this.cfmapping = "oauth";
	this.entryPoint = "/oauth";

	// Dependencies
	this.dependencies = [ "hyper"];

	routes = [
		{ pattern: "/auth/:providerName/start", handler: "Auth", action: "start" },
		{ pattern: "/auth/:providerName", handler: "Auth", action: "authorize" }
	];

	/**
	 * Configure Module
	 */
	function configure(){
		settings = {
			errorRedirect: "/",
			successRedirect: "/",
			providers : [
				// Your google login API credentials
				"google": {
					clientId            : getSystemSetting( key = "GOOGLE_CLIENT_ID", defaultValue = "" ),
					clientSecret        : getSystemSetting( key = "GOOGLE_CLIENT_SECRET", defaultValue = "" ),
					authEndpoint        : "https://accounts.google.com/o/oauth2/v2/auth",
					accessTokenEndpoint : "https://www.googleapis.com/oauth2/v4/token",
					redirectUri         : getSystemSetting( key = "GOOGLE_REDIRECT_URI", defaultValue = "" )
				},
				// Your facebook login API credentials
				"facebook": {
					clientId            : getSystemSetting( key = "FACEBOOK_CLIENT_ID", defaultValue = "" ),
					clientSecret        : getSystemSetting( key = "FACEBOOK_CLIENT_SECRET", defaultValue = "" ),
					authEndpoint        : "https://www.facebook.com/v2.10/dialog/oauth",
					accessTokenEndpoint : "https://graph.facebook.com/v2.10/oauth/access_token",
					redirectUri         : getSystemSetting( key = "FACEBOOK_REDIRECT_URI", defaultValue = "" )
				}
			]
		};
	};


	/**
	 * Fired when the module is registered and activated.
	 */
	function onLoad(){
		// Register all app disks
		wirebox.getInstance( "ProviderService@oAuth" ).registerProviders();
	}

	/**
	 * Fired when the module is unregistered and unloaded
	 */
	function onUnload(){
	}

}
