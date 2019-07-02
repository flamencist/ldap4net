// ReSharper disable InconsistentNaming

namespace LdapForNet.Native
{
    public static partial class Native
    {
        public enum LdapResultCode
        {
            LDAP_SUCCESS = 0x00,
            LDAP_SASL_BIND_IN_PROGRESS = 0x0e,
            LDAP_PARAM_ERROR = -9,
            LDAP_OTHER =  0x50,
            LDAP_NOT_SUPPORTED = -12
        }
    }
}    