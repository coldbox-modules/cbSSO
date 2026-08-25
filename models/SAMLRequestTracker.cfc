component singleton {

	property name="cachebox"  inject="cachebox";
	property name="cacheName" inject="coldbox:setting:samlRequestCacheName@cbsso";

	variables.requestTTLMinutes = 10;
	variables.cacheKeyPrefix    = "cbsso:saml-request:";

	public void function onDIComplete(){
		variables.requestCache = variables.cachebox.getCache( variables.cacheName );
	}

	public void function remember( required string requestId ){
		variables.requestCache.setQuiet(
			cacheKey( arguments.requestId ),
			true,
			variables.requestTTLMinutes
		);
	}

	public boolean function isPending( required string requestId ){
		return variables.requestCache.lookupQuiet( cacheKey( arguments.requestId ) );
	}

	/**
	 * Atomically consumes a request ID through the cache provider. A false result means the request expired
	 * or was already consumed. This makes the operation safe across application nodes when the configured
	 * CacheBox provider is distributed.
	 */
	public boolean function consume( required string requestId ){
		return variables.requestCache.clearQuiet( cacheKey( arguments.requestId ) );
	}

	private string function cacheKey( required string requestId ){
		return variables.cacheKeyPrefix & arguments.requestId;
	}

}
