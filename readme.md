

# cbSSO

Welcome to cbSSO a ColdBox module to help integrate SSO into your application easily.

Bundled in this module are several SSO provider implementations that allow you to quickly and easily integrate with Identity Providers such as Microsoft, Google, GitHub or Facebook using standard protocols like SAML and oAuth.

To install run 
```
box install cbsso
```

Once installed you can configure your settings like so
```
// config/modules/cbsso.cfc
component {
    function configure(){
        return {
            "providers": [
                {
                    type: "GoogleProvider@cbsso",
                    clientId: getJavaSystem().getProperty( "GOOGLE_CLIENT_ID" ),
                    clientSecret: getJavaSystem().getProperty( "GOOGLE_CLIENT_SECRET" )
                }
            ]
        };
    }
}
```
Your app now has the ability to direct users to Google for authentication!

For more complete documentation covering features and implementation check out our documentation site [cbsso.ortusbooks.com](https://cbsso.ortusbooks.com).



## Ortus Sponsors

ColdBox is a professional open-source project and it is completely funded by the [community](https://patreon.com/ortussolutions) and [Ortus Solutions, Corp](https://www.ortussolutions.com).  Ortus Patreons get many benefits like a cfcasts account, a FORGEBOX Pro account and so much more.  If you are interested in becoming a sponsor, please visit our patronage page: [https://patreon.com/ortussolutions](https://patreon.com/ortussolutions)

### THE DAILY BREAD

 > "I am the way, and the truth, and the life; no one comes to the Father, but by me (JESUS)" Jn 14:1-12
