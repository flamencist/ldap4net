// ReSharper disable InconsistentNaming
namespace LdapForNet.Native
{
    public static partial class Native
    {
        public enum LdapPort
        {
            LDAP = 389,
            LDAPS = 636
        }

        public enum LdapSchema
        {
            Unknown = 0,
            LDAP = 1,
            LDAPS = 2,
            LDAPI = 3
        }
    }
}