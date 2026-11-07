component accessors="true" singleton threadsafe {

	property name="moduleSettings" inject="coldbox:moduleSettings:cbsso";
	property name="moduleConfig"   inject="coldbox:moduleConfig:cbsso";
	property name="wirebox"        inject="wirebox";
	property name="log"            inject="logbox:logger:{this}";


	property name="providers" type="struct";

	variables.providers = {};

	/**
	 * One provider failing to build no longer aborts the rest, or the module's onLoad(), or the application
	 * boot that onLoad() runs inside. A definition can fail for reasons wholly outside this module -
	 * an unreachable IdP, a missing jar, a provider type that is not installed - and losing every other
	 * provider plus the whole application to it is out of all proportion. The failure is logged and that
	 * provider is left unregistered, so missing() reports it and Auth redirects to errorRedirect.
	 */
	ProviderService function registerProviders(){
		variables.moduleSettings.providers.each( function( providerDefinition ){
			try {
				var provider = wirebox.getInstance( providerDefinition.type );

				for ( var setting in providerDefinition ) {
					if ( !structKeyExists( provider, "set#setting#" ) ) {
						continue;
					}

					invoke(
						provider,
						"set#setting#",
						[ providerDefinition[ setting ] ]
					);
				}

				providers[ provider.getName() ] = provider;
			} catch ( any e ) {
				log.error(
					"Could not register SSO provider [#providerDefinition.name ?: providerDefinition.type ?: "unnamed"#] - it will be unavailable until the next successful registration",
					{ "error" : e.message, "detail" : e.detail ?: "" }
				);
			}
		} );
		return this;
	}

	public array function getRenderableProviderData(){
		return variables.providers
			.keyArray()
			.map( ( name ) => {
				var provider = variables.providers[ name ];
				return {
					"name" : provider.getName(),
					"url"  : "/cbsso/auth/#provider.getName()#/start"
				};
			} );
	}

	public any function getAllProviders(){
		return variables.providers
			.valueArray()
			.map( ( providerRecord ) => {
				if ( isNull( providerRecord.provider ) ) {
					providerRecord.provider  = buildProvider( provider: providerRecord.name );
					providerRecord.createdOn = now();
				}

				return providerRecord.provider;
			} );
	}

	function get( required name ){
		return variables.providers[ name ];
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
		// Build it out
		return variables.wirebox.getInstance( arguments.provider );
	}

	/**
	 * Get's the struct of registered disk providers lazily
	 */
	private function getRegisteredCoreProviders(){
		if ( isNull( variables.registeredCoreProviders ) ) {
			// Providers Path
			variables.providersPath           = variables.moduleConfig.modelsPhysicalPath & "/providers";
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
					arguments.result[ arguments.item.replaceNoCase( "Provider", "" ) ] = "#arguments.item#@cbsso";
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
