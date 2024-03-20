/**
* My Event Handler Hint
*/
component{

	// Index
	any function index( event,rc, prc ){
		prc.diskService = getInstance( "ProviderService@cbSSO" );

		prc.defaultDisk = prc.diskService.get( "google" );

		writeDump( var = prc.defaultDisk.getProperties(), label = "Google" );
	}

}