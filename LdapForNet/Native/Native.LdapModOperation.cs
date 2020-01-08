namespace LdapForNet.Native
{
    public static partial class Native
    {
        public enum LdapModOperation
        {
            LDAP_MOD_ADD=0x00,
            LDAP_MOD_DELETE=0x01,
            LDAP_MOD_REPLACE=0x02,
            LDAP_MOD_BVALUES=0x80
        }
    }
}