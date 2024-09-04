/**
* Description of task
*/
component {

	/**
	*
	*/
	function run() {

		var rootDir = getCWD().reReplace( "[\\/]$", "" );

		print.line( rootDir );
		return;

		command( "run" )
			.inWorkingDirectory( rootDir & "/java/cbsso-opensaml" )
			.params( "gradlew", ":app:shadowJar" )
			.run();
			
		command( "cp" )
			.params( rootDir & "/java/cbsso-opensaml/app/build/libs/cbsso-opensaml-all.jar", rootDir & "/lib/cbsso-opensaml-all.jar" )
			.run();

		command( "cd" )
			.params( rootDir )
			.run();
	}

}