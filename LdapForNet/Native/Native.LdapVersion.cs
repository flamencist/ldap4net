// ReSharper disable InconsistentNaming

namespace LdapForNet.Native
{
    public static partial class Native
    {
        public enum LdapVersion
        {
            LDAP_VERSION1 = 1,
            LDAP_VERSION2 = 2,
            LDAP_VERSION3 = 3,

            LDAP_VERSION_MIN = LDAP_VERSION2,
            LDAP_VERSION = LDAP_VERSION2,
            LDAP_VERSION_MAX = LDAP_VERSION3
        }
    }
}