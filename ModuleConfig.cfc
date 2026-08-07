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
	this.dependencies = [ "hyper", "jwtcfml" ];

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
			// Leave blank to create the module's bounded default cache. Set this to the name of an existing
			// CacheBox cache to use a distributed provider such as Redis or a database-backed cache.
			samlRequestCacheName    : "",
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
		ensureSAMLRequestCache();

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
	}

	/**
	 * Fired when the module is unregistered and unloaded
	 */
	function onUnload(){
	}

	private void function ensureSAMLRequestCache(){
		var configuredCacheName = settings.samlRequestCacheName;

		if ( !len( trim( configuredCacheName ) ) ) {
			configuredCacheName           = "cbssoSAMLRequests";
			settings.samlRequestCacheName = configuredCacheName;

			if ( !cachebox.cacheExists( configuredCacheName ) ) {
				cachebox.createCache(
					name       = configuredCacheName,
					provider   = "coldbox.system.cache.providers.CacheBoxProvider",
					properties = {
						objectDefaultTimeout           : 10,
						objectDefaultLastAccessTimeout : 0,
						useLastAccessTimeouts          : false,
						reapFrequency                  : 1,
						freeMemoryPercentageThreshold  : 0,
						evictionPolicy                 : "LRU",
						evictCount                     : 1,
						maxObjects                     : 10000,
						objectStore                    : "ConcurrentStore"
					}
				);
			}
		} else if ( !cachebox.cacheExists( configuredCacheName ) ) {
			throw(
				type    = "cbSSO.SAMLRequestCacheNotFound",
				message = "The configured SAML request cache '#configuredCacheName#' is not registered with CacheBox.",
				detail  = "Register the cache in config/CacheBox.cfc or clear samlRequestCacheName to use the default cbSSO cache."
			);
		}
	}

}
