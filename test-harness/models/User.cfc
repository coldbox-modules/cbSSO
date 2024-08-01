component accessors = true {
    property name = "id";
    property name = "Email";

    function getId(){
        return variables.id;
    }

    boolean function hasPermission( required permission ){
        return true;
    }

    /**
     * Shortcut to verify it the user is logged in or not.
     */
    boolean function isLoggedIn(){
        return true;
    }
}