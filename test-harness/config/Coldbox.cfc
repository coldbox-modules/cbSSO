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
			"cbsso" : {
				"providers" : [
					{
						type: "GitHubProvider@cbsso",
						clientId            : getJavaSystem().getProperty( "GITHUB_CLIENT_ID" ),
						clientSecret        : getJavaSystem().getProperty( "GITHUB_CLIENT_SECRET" )
					}
				]
			}
		};

		moduleSettings = {
			cbauth = {
				// This is the path to your user object that contains the credential 
				// validation methods
				userServiceClass = "models.UserService"
			},
			"cbsecurity": {
				authentication : {
					// The WireBox ID of the authentication service to use which must adhere to the cbsecurity.interfaces.IAuthService interface.
					"provider"        : "authenticationService@cbauth",
					// WireBox ID of the user service to use when leveraging user authentication, we default this to whatever is set
					// by cbauth or basic authentication. (Optional)
					"userService"     : "cbauth.userServiceclass",
					// The name of the variable to use to store an authenticated user in prc scope on all incoming authenticated requests
					"prcUserVariable" : "oCurrentUser"
				}
			},
			"cbsso" : {
				"enableCBAuthIntegration": true,
				"providers" : [
					{
						type: "CustomProvider"
					},
					{
						// name: "google",
						type: "GoogleProvider@cbsso",
						clientId            : getJavaSystem().getProperty( "GOOGLE_CLIENT_ID" ),
						clientSecret        : getJavaSystem().getProperty( "GOOGLE_CLIENT_SECRET" )
					},
					{
						type: "GitHubProvider@cbsso",
						clientId            : getJavaSystem().getProperty( "GITHUB_CLIENT_ID" ),
						clientSecret        : getJavaSystem().getProperty( "GITHUB_CLIENT_SECRET" )
					},
					{
						type: "FacebookProvider@cbsso",
						clientId            : getJavaSystem().getProperty( "FACEBOOK_CLIENT_ID" ),
						clientSecret        : getJavaSystem().getProperty( "FACEBOOK_CLIENT_SECRET" )
					},
					{
						name: "entra",
						type: "MicrosoftSAMLProvider@cbsso",
						clientId            : getJavaSystem().getProperty( "MS_ENTRA_CLIENT_ID" ),
						clientSecret        : getJavaSystem().getProperty( "MS_ENTRA_CLIENT_SECRET" ),
						authEndpoint        : getJavaSystem().getProperty( "MS_ENTRA_SIGN_ON_ENDPOINT" )
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
