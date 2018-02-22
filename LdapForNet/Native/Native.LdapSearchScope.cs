// ReSharper disable InconsistentNaming
namespace LdapForNet.Native
{
    public static partial class Native
    {
        public enum LdapSearchScope
        {
            LDAP_SCOPE_BASE = 0x0000,
            LDAP_SCOPE_BASEOBJECT = LDAP_SCOPE_BASE,
            LDAP_SCOPE_ONELEVEL = 0x0001,
            LDAP_SCOPE_ONE = LDAP_SCOPE_ONELEVEL,
            LDAP_SCOPE_SUBTREE = 0x0002,
            LDAP_SCOPE_SUB = LDAP_SCOPE_SUBTREE,
            LDAP_SCOPE_SUBORDINATE = 0x0003, /* OpenLDAP extension */
            LDAP_SCOPE_CHILDREN = LDAP_SCOPE_SUBORDINATE,
            LDAP_SCOPE_DEFAULT = -1 /* OpenLDAP extension */
        }
    }
}