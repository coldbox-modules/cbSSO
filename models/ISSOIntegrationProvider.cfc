interface {
    public string function getName();
    public string function getIconURL();
    public string function startAuthenticationWorflow( required any event );
    public any function processAuthorizationEvent( required any event );
}