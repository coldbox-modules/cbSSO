interface {

	public boolean function wasSuccessful();
	public string function getSessionId();
	public string function getUserId();
	public string function getEmail();
	public string function getName();
	public string function getFirstName();
	public string function getLastName();
	public any function getRawResponseData();
	public string function getErrorMessage();
	public struct function getClaims();
	public string function getClaim( required string name, string defaultValue );
	public string function getNameId();
	public string function getNameIdFormat();

}
