// ReSharper disable InconsistentNaming
namespace LdapForNet.Native
{
    public static partial class Native
    {
        /// <summary>
        /// Interaction flags (should be passed about in a control)
        /// Automatic (default): use defaults, prompt otherwise
        /// Interactive: prompt always
        /// Quiet: never prompt
        /// </summary>
        public enum LdapInteractionFlags
        {
            LDAP_SASL_AUTOMATIC = 0,
            LDAP_SASL_INTERACTIVE = 1,
            LDAP_SASL_QUIET = 2
        }
    }
}