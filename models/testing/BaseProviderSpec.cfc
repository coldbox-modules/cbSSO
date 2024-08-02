/**
 * Disk Service Spec
 */
component extends="cbPlaywright.models.ColdBoxPlaywrightTestCase" {

	this.loadColdbox   = true;
	// Unload Coldbox after this spec, since we are doing a shutdown of all disks
	this.unLoadColdBox = true;
	this.autowire      = true;

	variables.provider = "";

	/*********************************** LIFE CYCLE Methods ***********************************/

	/**
	 * executes before all suites+specs in the run() method
	 */
	function beforeAll(){
		super.beforeAll();
		setup();
	}

	/**
	 * executes after all suites+specs in the run() method
	 */
	function afterAll(){
		super.afterAll();
	}

	/**
	 * ------------------------------------------------------------
	 * Test Helpers
	 * ------------------------------------------------------------
	 */

	function getProvider(){
		return getInstance( "ProviderService@cbsso" ).get( variables.providerName );
	}

	function getProvidersList(){
		return getInstance( "ProviderService@cbsso" ).names();
	}

}
