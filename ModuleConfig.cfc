/**
 * Copyright Since 2005 ColdBox Framework by Luis Majano and Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 */
component {

	// Module Properties
	this.title       = "cbSSO";
	this.author      = "Ortus Solutions";
	this.webURL      = "https://www.ortussolutions.com";
	this.description = "@MODULE_DESCRIPTION@";
	this.version     = "@build.version@+@build.number@";

	// Model Namespace
	this.modelNamespace = "cbsso";
	this.autoMapModels  = true;
	// CF Mapping
	this.cfmapping      = "cbSSO";
	this.entryPoint     = "/cbsso";

	// Dependencies
	this.dependencies = [ "hyper", "jwtcfml", "cbjavaloader" ];

	routes = [
		{
			pattern : "/auth/:providerName/start",
			handler : "Auth",
			action  : "start"
		},
		{
			pattern : "/auth/:providerName",
			handler : "Auth",
			action  : "authorize"
		}
	];

	/**
	 * Configure Module
	 */
	function configure(){
		settings = {
			enableCBAuthIntegration : false,
			errorRedirect           : "",
			successRedirect         : "",
			providers               : [
				 // Your google login API credentials
				// "google": {
				// 	clientId            : getSystemSetting( key = "GOOGLE_CLIENT_ID", defaultValue = "" ),
				// 	clientSecret        : getSystemSetting( key = "GOOGLE_CLIENT_SECRET", defaultValue = "" ),
				// 	authEndpoint        : "https://accounts.google.com/o/oauth2/v2/auth",
				// 	accessTokenEndpoint : "https://www.googleapis.com/oauth2/v4/token",
				// 	redirectUri         : getSystemSetting( key = "GOOGLE_REDIRECT_URI", defaultValue = "" )
				// }
			]
		};

		interceptorSettings = { customInterceptionPoints : [ "CBSSOMissingProvider", "CBSSOAuthorization" ] };
	};


	/**
	 * Fired when the module is registered and activated.
	 */
	function onLoad(){
		// Register all app disks
		wirebox.getInstance( "ProviderService@cbsso" ).registerProviders();

		if ( settings.enableCBAuthIntegration ) {
			controller
				.getInterceptorService()
				.registerInterceptor(
					interceptorClass      = "cbsso.interceptors.cbAuth",
					interceptorProperties = settings,
					interceptorName       = "cbsso@global"
				);
		}

		wireBox.getInstance( "loader@cbjavaloader" ).appendPaths( modulePath & "/lib" );
	}

	/**
	 * Fired when the module is unregistered and unloaded
	 */
	function onUnload(){
	}

}
