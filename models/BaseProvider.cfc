/**
 *
 * The base model to set up an oauth provider
 *
 * */
component accessors="true" {

	property name="hyper" inject="HyperBuilder@hyper";

	/**
	 * Constructor
	 */
	function init(){
		return this;
	}


	/**
	 * getAuthUrl
	 */
	function buildAuthUrl( struct params = {}, boolean state = false ){
		var queryString = structToQueryString(
			iIf(
				params.isEmpty(),
				getCodeParams( arguments.state ),
				arguments.params
			)
		);
		return variables.authEndpoint & queryString;
	}


	/**
	 * I make the HTTP request to obtain the access token.
	 *
	 * @code       The code returned from the authentication request.
	 * @formfields An optional array of structs for the provider requirements to add new form fields.
	 * @headers    An optional array of structs to add custom headers to the request if required.
	 **/
	public struct function makeAccessTokenRequest(
		required string code,
		array bodyFields = [],
		array headers    = []
	){
		var hyper          = hyper.new();
		var stuResponse    = {};
		var requestHeaders = {};

		if ( arrayLen( arguments.headers ) ) {
			for ( var item in arguments.headers ) {
				requestHeaders.append( { item[ "name" ]  : item[ "value" ] } );
			}
		}

		var requestParams = {
			client_id     : variables.clientId,
			client_secret : variables.clientSecret,
			code          : arguments.code,
			redirect_uri  : variables.redirectUri,
			grant_type    : "authorization_code"
		};

		var response = hyper
			.setMethod( "POST" )
			.setUrl( variables.accessTokenEndpoint )
			.withHeaders( headers )
			.setBody( requestParams )
			.asFormFields()
			.send();

		if ( response.isSuccess() ) {
			stuResponse.success = true;
			stuResponse.content = response.getBody();
		} else {
			stuResponse.success = false;
			stuResponse.content = response.getStatusText();
		}

		return stuResponse;
	}

	/**
	 * I make the HTTP request to refresh the access token.
	 *
	 * @refresh_token The refresh_token returned from the accessTokenRequest request.
	 **/
	public struct function refreshAccessTokenRequest(
		required string refresh_token,
		array formfields = [],
		array headers    = []
	){
		var hyper          = hyper.new();
		var stuResponse    = {};
		var requestHeaders = { "Content-Type" : "application/x-www-form-urlencoded" };

		if ( arrayLen( arguments.headers ) ) {
			for ( var item in arguments.headers ) {
				requestHeaders.append( { item[ "name" ]  : item[ "value" ] } );
			}
		}

		var requestParams = {
			client_id     : variables.clientId,
			client_secret : variables.clientSecret,
			refresh_token : arguments.refresh_token,
			grant_type    : "refresh_token"
		};

		var response = hyper
			.setMethod( "POST" )
			.setUrl( variables.accessTokenEndpoint )
			.withHeaders( headers )
			.setBody( requestParams )
			.asFormFields()
			.send();

		if ( response.isSuccess() ) {
			stuResponse.success = true;
			stuResponse.content = response.getBody();
		} else {
			stuResponse.success = false;
			stuResponse.content = response.getStatusText();
		}

		return stuResponse;
	}


	/**
	 * getCodeParams
	 *
	 * Will return an struct of the needed params to create the auth url
	 */
	function getCodeRequestParams( string state = "" ){
		var params = {
			"client_id"     : variables.clientId,
			"redirect_uri"  : variables.redirectURI,
			"scope"         : variables.scopes.toList( variables.scopeSeparator ),
			"response_type" : variables.responseType
		};
		if ( !variables.stateless ) {
			params[ "state" ] = arguments.state;
		}
		return params;
	}

	function getTokenRequestParams( required String code ){
		return {
			"client_id"     : variables.clientId,
			"client_secret" : variables.clientSecret,
			"code"          : arguments.code,
			"redirect_uri"  : variables.redirectURI
		};
	}

	/**
	 * Create a query string from an struct
	 *
	 * @paramsStruct the struct I want to conver
	 */
	function structToQueryString( required struct args ){
		var queryStr = "?";

		if ( structCount( arguments.args ) ) {
			var intCount = 1;

			for ( var key in arguments.args ) {
				if ( listLen( queryStr ) && intCount > 1 ) {
					queryStr &= "&";
				}

				queryStr &= lCase( key ) & "=" & trim( arguments.args[ key ] );
				intCount++;
			}
		}

		return queryStr;
	}

}
