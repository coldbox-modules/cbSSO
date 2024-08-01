     component accessors="true" {

	property name="hyper" inject="HyperBuilder@hyper";
	property name="jwt"   inject="jwt@jwtcfml";


	public string function buildAuthUrl(
		required string authEndpoint,
		required string client_id,
		required string redirect_uri,
		required string response_type,
		string state       = "",
		struct extraParams = {}
	){
		var params = {
			"client_id"     : client_id,
			"redirect_uri"  : redirect_uri,
			"response_type" : response_type
		};

		params.append( extraParams );

		if ( state != "" ) {
			params[ "state" ] = state;
		}

		return authEndpoint & "?" & structToQueryString( params );
	}

	public struct function decodeJWT( required string idToken, required string jwksURL ){
		var keys = getJWTKeys( jwksURL );

		for ( var key in keys ) {
			try {
				return jwt.decode( idToken, key, "RS256" );
			} catch ( any e ) {
				// pass
			}
		}

		throw( "Invalid JWT Token", "InvalidJWT" );
	}



	/**
	 * I make the HTTP request to obtain the access token.
	 *
	 * @code       The code returned from the authentication request.
	 * @formfields An optional array of structs for the provider requirements to add new form fields.
	 * @headers    An optional array of structs to add custom headers to the request if required.
	 **/
	public any function makeAccessTokenRequest(
		required string client_id,
		required string client_secret,
		required string redirect_uri,
		required string accessTokenEndpoint,
		required string code
	){
		return hyper
			.new()
			.setMethod( "POST" )
			.setUrl( accessTokenEndpoint )
			.setHeaders( { "Content-Type" : "application/x-www-form-urlencoded" } )
			.setBody(
				structToQueryString( {
					"client_id"     : client_id,
					"client_secret" : client_secret,
					"redirect_uri"  : redirect_uri,
					"grant_type"    : "authorization_code",
					"code"          : code
				} )
			)
			.send();
	}

	public any function getProfileInformation( required string profileURL, required string token ){
		return hyper
			.new()
			.setMethod( "POST" )
			.setUrl( profileURL )
			.withHeaders( { "Authorization" : "Bearer #token#" } )
			.send();
	}

	/**
	 * I make the HTTP request to refresh the access token.
	 *
	 * @refresh_token The refresh_token returned from the accessTokenRequest request.
	 **/
	public any function refreshAccessTokenRequest(
		required string clientId,
		required string clientSecret,
		required stirng accessTokenEndpoint,
		required string refresh_token
	){
		return hyper
			.new()
			.setMethod( "POST" )
			.setUrl( accessTokenEndpoint )
			.withHeaders( { "Content-Type" : "application/x-www-form-urlencoded" } )
			.setBody( {
				client_id     : clientId,
				client_secret : clientSecret,
				refresh_token : refresh_token,
				grant_type    : "refresh_token"
			} )
			.asFormFields()
			.send();
	}

	/**
	 * Create a query string from an struct
	 *
	 * @paramsStruct the struct I want to conver
	 */
	private string function structToQueryString( required struct args ){
		if ( !args.count() ) {
			return "";
		}

		var params   = [];
		var intCount = 1;

		for ( var key in args ) {
			// params.append( key.lcase() & "=" & encodeForURL( trim( arguments.args[ key ] ) ) );
			params.append( key.lcase() & "=" & trim( arguments.args[ key ] ) );
		}

		return arrayToList( params, "&" );
	}

	private array function getJWTKeys( required string jwksURL ){
		return hyper
			.new()
			.setUrl( jwksURL )
			.send()
			.json()
			.keys;
	}

}
