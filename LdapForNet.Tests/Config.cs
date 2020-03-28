namespace LdapForNetTests
{
    public static class Config
    {
        public const string LdapHost = "localhost";
        public const string LdapHostName = "example";
        public const int LdapPort = 4389;
        public const int LdapsPort = 4636;
        public const string LdapIUnixSocketPath = "/tmp/slapd/slapdunix";
        public const string RootDn = "dc=example,dc=com";
        public const string LdapUserDn = "cn=admin,dc=example,dc=com";
        public const string LdapDigestMd5UserName = "digestTest";
        public const string LdapDigestMd5ProxyDn= "cn=digesttestproxy,dc=example,dc=com";
        public const string LdapPassword = "test";
    }
}