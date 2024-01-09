component accessors="true" singleton threadsafe {

	property name="moduleSettings" inject="coldbox:moduleSettings:oAuth";
	property name="moduleConfig"   inject="coldbox:moduleConfig:oAuth";
	property name="wirebox"        inject="wirebox";
	property name="log"            inject="logbox:logger:{this}";


	property name="providers" type="struct";


	/**
	 * Constructor
	 */
	function init(){
		// Init the providers
		variables.providers = {};
		return this;
	}

	ProviderService function registerProviders(){
		variables.moduleSettings.providers.each( function( providerName, providerDefinition ){
			param name="arguments.providerDefinition.properties" default="#structNew()#";
			register( provider: arguments.providerName );
		} );
		return this;
	}

	ProviderService function register(
		required provider,
		struct properties = {},
		boolean override  = false
	){
		// If it doesn't exist or we are overriding, register it
		if ( !variables.providers.keyExists( arguments.provider ) || arguments.override ) {
			variables.providers[ arguments.provider ] = {
				"name"         : arguments.provider,
				"registeredOn" : now(),
				"provider"     : javacast( "null", "" ),
				"createdOn"    : ""
			};
			log.info( "- Registered (#arguments.provider#:#arguments.provider#) provider." );
		} else {
			log.warn( "- Ignored registration for (#arguments.provider#) provider as it was already registered." );
		}

		return this;
	}

	function get( required name ){
		var providerRecord = getProviderRecord( arguments.name );

		// Lazy load the disk instance
		if ( isNull( providerRecord.provider ) ) {
			lock name="oauth-createProvider-#arguments.name#" type="exclusive" timeout="10" throwOnTimeout="true" {
				if ( isNull( providerRecord.provider ) ) {
					log.debug( "Provider (#arguments.name#) not built, building it now." );
					providerRecord.provider  = buildProvider( provider: providerRecord.name );
					providerRecord.createdOn = now();
				}
			}
		}

		return providerRecord.provider;
	}

	struct function getProviderRecord( required name ){
		// Check if the provider is registered, else throw exception
		if ( missing( arguments.name ) ) {
			throw(
				message: "The provider you requested (#arguments.name#) has not been registered.",
				type   : "InvalidProviderException"
			)
		}
		return variables.providers[ arguments.name ];
	}

	private function buildProvider( required provider ){
		// is this core?
		if ( getRegisteredCoreProviders().keyExists( arguments.provider ) ) {
			arguments.provider = variables.registeredCoreProviders[ arguments.provider ];
		}
		writeDump( var = "arguments.provider: " & arguments.provider );
		abort;
		// Build it out
		return variables.wirebox.getInstance( arguments.provider );
	}

	/**
	 * Get's the struct of registered disk providers lazily
	 */
	private function getRegisteredCoreProviders(){
		if ( isNull( variables.registeredCoreProviders ) ) {
			// Providers Path
			variables.providersPath           = variables.moduleConfig.modelsPhysicalPath & "/Providers";
			// Register core disk providers
			variables.registeredCoreProviders = directoryList(
				variables.providersPath,
				false,
				"name",
				"*.cfc"
			)
				// Purge extension
				.map( function( item ){
					return listFirst( item, "." );
				} )
				// Build out wirebox mapping
				.reduce( function( result, item ){
					arguments.result[ arguments.item.replaceNoCase( "Provider", "" ) ] = "#arguments.item#@oAuth";
					return arguments.result;
				}, {} );
		}

		return variables.registeredCoreProviders;
	}

	boolean function has( required name ){
		return variables.providers.keyExists( arguments.name );
	}

	boolean function missing( required name ){
		return !this.has( arguments.name );
	}

	array function names(){
		var names = variables.providers.keyArray();
		// Dumb ACF 2016 Member function
		names.sort( "textNocase" );
		return names;
	}

}
