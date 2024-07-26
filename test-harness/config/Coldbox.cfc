component {

	// Configure ColdBox Application
	function configure(){
		// coldbox directives
		coldbox = {
			// Application Setup
			appName                 : "Module Tester",
			// Development Settings
			reinitPassword          : "",
			handlersIndexAutoReload : true,
			modulesExternalLocation : [],
			// Implicit Events
			defaultEvent            : "",
			requestStartHandler     : "",
			requestEndHandler       : "",
			applicationStartHandler : "",
			applicationEndHandler   : "",
			sessionStartHandler     : "",
			sessionEndHandler       : "",
			missingTemplateHandler  : "",
			// Error/Exception Handling
			exceptionHandler        : "",
			onInvalidEvent          : "",
			customErrorTemplate     : "/coldbox/system/exceptions/Whoops.cfm",
			// Application Aspects
			handlerCaching          : false,
			eventCaching            : false
		};

		moduleSettings = {
			"oauth" : {
				"providers" : [
					{
						name: "google",
						type: "GoogleProvider@oauth",
						clientId            : getJavaSystem().getProperty( "GOOGLE_CLIENT_ID" ),
						clientSecret        : getJavaSystem().getProperty( "GOOGLE_CLIENT_SECRET" ),
						authEndpoint        : getJavaSystem().getProperty( "GOOGLE_AUTH_ENDPOINT" ),
						accessTokenEndpoint        : getJavaSystem().getProperty( "GOOGLE_ACCESS_TOKEN" ),
						redirectUri         : getJavaSystem().getProperty( "GOOGLE_REDIRECT_URI" )
					},
					{
						name: "entra",
						type: "SAMLProvider@oauth",
						clientId            : getJavaSystem().getProperty( "MS_ENTRA_CLIENT_ID" ),
						clientSecret        : getJavaSystem().getProperty( "MS_ENTRA_CLIENT_SECRET" ),
						authEndpoint        : getJavaSystem().getProperty( "MS_ENTRA_SIGN_ON_ENDPOINT" ),
						redirectUri         : getJavaSystem().getProperty( "MS_ENTRA_REDIRECT_URI" )
					}
				]
			}
		};

		// environment settings, create a detectEnvironment() method to detect it yourself.
		// create a function with the name of the environment so it can be executed if that environment is detected
		// the value of the environment is a list of regex patterns to match the cgi.http_host.
		environments = { development : "localhost,127\.0\.0\.1" };

		// Module Directives
		modules = {
			// An array of modules names to load, empty means all of them
			include : [],
			// An array of modules names to NOT load, empty means none
			exclude : []
		};

		// Register interceptors as an array, we need order
		interceptors = [];

		// LogBox DSL
		logBox = {
			// Define Appenders
			appenders : {
				myConsole : { class : "ConsoleAppender" },
				files     : {
					class      : "RollingFileAppender",
					properties : { filename : "tester", filePath : "/#appMapping#/logs" }
				}
			},
			// Root Logger
			root : { levelmax : "DEBUG", appenders : "*" },
			// Implicit Level Categories
			info : [ "coldbox.system" ]
		};
	}

	/**
	 * Load the Module you are testing
	 */
	function afterAspectsLoad( event, interceptData, rc, prc ){
		controller
			.getModuleService()
			.registerAndActivateModule( moduleName = request.MODULE_NAME, invocationPath = "moduleroot" );
	}

}
