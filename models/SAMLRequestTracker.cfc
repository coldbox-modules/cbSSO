component singleton {

	property name="cachebox"  inject="cachebox";
	property name="cacheName" inject="coldbox:setting:samlRequestCacheName@cbsso";

	variables.requestTTLMinutes = 10;
	variables.cacheKeyPrefix    = "cbsso:saml-request:";

	public void function onDIComplete(){
		variables.requestCache   = variables.cachebox.getCache( variables.cacheName );
		variables.cacheKeyPrefix = buildCacheKeyPrefix();
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

	/**
	 * Namespaced by application. A distributed cache - which is what `samlRequestCacheName` is for, and
	 * what the documentation asks for behind a load balancer - is shared by every application pointed at
	 * it, and CacheBox regions in separate applications resolve to one keyspace there. Two applications
	 * on one Redis region therefore accepted each other's request IDs as pending.
	 *
	 * That is not a way in on its own: the response still has to carry an assertion satisfying this
	 * provider's expected issuer, audience and recipient. It is the difference between "this application
	 * issued this AuthnRequest" and "some application sharing this cache did", which is the whole point
	 * of tracking them.
	 *
	 * The application name rather than a ColdBox setting, because several applications commonly share one
	 * ColdBox configuration - a multi-tenant deployment serving the same code under a different
	 * `this.name` per tenant is the case that surfaced this - and `AppName` would be identical across
	 * every one of them.
	 */
	private string function buildCacheKeyPrefix(){
		var applicationName = getApplicationMetadata().name ?: "";

		if ( !len( trim( applicationName ) ) ) {
			return "cbsso:saml-request:";
		}

		return "cbsso:" & trim( applicationName ) & ":saml-request:";
	}

}
