<cfoutput>
    <cfscript>
        providers = getInstance( "ProviderService@cbsso" );
        // writeDump( providers[1].buildAuthUrl() );
        // abort;

    </cfscript>
    <ul>
        <cfloop array="#providers.getRenderableProviderData()#" index="data">
            <li><a href="#data.url#">Login via #data.name#</a></li>
        </cfloop>
    </ul>
</cfoutput>