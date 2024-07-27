component {

    public any function fakeIdentityProvider(){
        relocate( url = "http://" & cgi.HTTP_HOST & "/oauth/auth/customprovider?test=working" );
    }
}
