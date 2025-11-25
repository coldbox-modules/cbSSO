<cfoutput>
Module Tester

<cfscript>
    try{

        user = getInstance( "AuthenticationService@cbauth" ).getUser();
        writeDUmp( user.getEmail() );   
    }
    catch( NoUserLoggedIn e ){
        writeDump( [ "no user" ] );
    }
</cfscript>
</cfoutput>