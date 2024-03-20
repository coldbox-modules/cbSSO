/**
 *
 * The base model to retrieve user information when user logs in
 *
 * */
component accessors="true" {

	property name="subjet"; // The unique identifier for the user.
	property name="username"; // The username.
	property name="givenName"; // User's first name
	property name="lastName"; // User's last name
	property name="fullname"; // The user's fullname.
	property name="email"; // The user's email address.
	property name="emailVerified"; // If user is already verified on google, if so, there is no need to verify on app.
	property name="avatar"; // The user's avatar image URL.

	/**
	 * Constructor
	 */
	function init(){
		return this;
	}

}
