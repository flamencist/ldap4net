using LdapForNet.Utils;
using static LdapForNet.Native.Native;

namespace LdapForNet
{
    public static class LdapConnectExtensions
    {
        public static void Connect(this ILdapConnection connection,int port = (int)LdapPort.LDAP, LdapVersion version = LdapVersion.LDAP_VERSION3)
        {
            connection.Connect(DomainUtils.GetDomainFromHostname(), port, version);
        }
    }
}