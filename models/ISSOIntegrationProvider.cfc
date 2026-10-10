interface {

	public string function getName();
	public string function startAuthenticationWorkflow( required any event );
	public any function processAuthorizationEvent( required any event );

}
