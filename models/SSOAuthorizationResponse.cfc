component implements="oauth.models.ISSOAuthorizationResponse" accessors = true {
    property name="wasSuccessful";
    property name="SessionId";
    property name="UserId";
    property name="Email";
    property name="Name";
    property name="FirstName";
    property name="LastName";
    property name="RawResponseData";
    property name="ErrorMessage";

    public boolean function wasSuccessful(){
        return variables.wasSuccessful;
    }
    public string function getSessionId(){
        return variables.SessionId;
    }
    public string function getUserId(){
        return variables.UserId;
    }
    public string function getEmail(){
        return variables.Email;
    }
    public string function getName(){
        return variables.FirstName;
    }
    public string function getFirstName(){
        return variables.FirstName;
    }
    public string function getLastName(){
        return variables.LastName;
    }
    public any function getRawResponseData(){
        return variables.RawResponseData;
    }
    public string function getErrormessage(){
        return variables.ErrorMessage;
    }
}