component {

    /**
    //  * This function is used to tell cbSSO which user is associated with an ssoAuthorizationResponse. 
    //  * 
    //  * @param ssoAuthorizationResponse An instance of ISSOAuthorizationResponse that was successful
    //  * @param provider The configured provider used for this SSO event
    //  *
    //  * @return An cbAuth.models.IUser instance or null
    //  */
    // public any function findBySSO( required any ssoAuthorizationResponse, required any provider );

    // /**
    //  * Create a new user based off of information from the ISSOAuthorizationResponse.
    //  * 
    //  * @param ssoAuthorizationResponse An instance of ISSOAuthorizationResponse that was successful
    //  * @param provider The configured provider used for this SSO event
    //  *
    //  * @return An cbAuth.models.IUser instance
    //  */
    // public any function createFromSSO( required any ssoAuthorizationResponse, required any provider );

    // /**
    //  * Create a new user based off of information from the ISSOAuthorizationResponse.
    //  * 
    //  * @param ssoAuthorizationResponse An instance of ISSOAuthorizationResponse that was successful
    //  * @param provider The configured provider used for this SSO event
    //  *
    //  * @return An cbAuth.models.IUser instance
    //  */
    // public void function updateFromSSO( required any user, required any ssoAuthorizationResponse, required any provider );

    public any function findBySSO( required any ssoAuthorizationResponse, required any provider ){
        return;
    }

    public any function createFromSSO( required any ssoEvent, required any provider ){
        var a = new User();

        a.setEmail( ssoEvent.getEmail() )
            .setId( ssoEvent.getUserId() );

        return a;
    }

    public any function updateFromSSO( required any user, required any ssoEvent, required any provider ){

    }

    /**
	 * Verify if the incoming username/password are valid credentials.
	 *
	 * @username The username
	 * @password The password
	 */
	boolean function isValidCredentials( required username, required password ){
        return false;
    }

	/**
	 * Retrieve a user by username
	 *
	 * @return User that implements IAuthUser
	 */
	function retrieveUserByUsername( required username ){
        var a = new User();
        a.setEmail( "fake" );
        return a;
    }

	/**
	 * Retrieve a user by unique identifier
	 *
	 * @id The unique identifier
	 *
	 * @return User that implements IAuthUser
	 */
	function retrieveUserById( required id ){
        var a = new User();
        a.setEmail( "fake" );
        return a;
    }
}