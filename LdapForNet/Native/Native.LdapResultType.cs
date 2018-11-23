namespace LdapForNet.Native
{
    public static partial class Native
    {
        public enum LdapResultType
        {
            LDAP_ERROR = -1,
            LDAP_TIMEOUT = 0,
            LDAP_RES_BIND = 0x61,
            LDAP_RES_SEARCH_ENTRY = 0x64,
            LDAP_RES_SEARCH_REFERENCE = 0x73,
            LDAP_RES_SEARCH_RESULT = 0x65,
            LDAP_RES_MODIFY = 0x67,
            LDAP_RES_ADD = 0x69,
            LDAP_RES_DELETE = 0x6b,
            LDAP_RES_MODDN = 0x6d,
            LDAP_RES_COMPARE = 0x6f,
            LDAP_RES_EXTENDED = 0x78,
            LDAP_RES_INTERMEDIATE = 0x79
        }
    }
}