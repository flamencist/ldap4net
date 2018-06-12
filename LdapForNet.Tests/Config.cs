namespace LdapForNetTests
{
    public static class Config
    {
        public const string LdapHost = "ldap.forumsys.com";
        public const string LdapUserDn = "cn=read-only-admin,dc=example,dc=com";
        public const string LdapPassword = "password";

        public const string LdapHost2 = "localhost";
        public const int LdapPort2 = 3389;
        public const string RootDn2 = "dc=example,dc=com";
        public const string LdapUserDn2 = "cn=admin,dc=example,dc=com";
        public const string LdapPassword2 = "test";
        
    }
}