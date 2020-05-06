using System;
using System.Text;
using System.Web;
using LdapForNet.Utils;
using static LdapForNet.Native.Native;

namespace LdapForNet
{
    public static class LdapConnectExtensions
    {
        public static void Connect(this ILdapConnection connection, int port = (int) LdapPort.LDAP,
            LdapVersion version = LdapVersion.LDAP_VERSION3)
        {
            connection.Connect(DomainUtils.GetDomainFromHostname(), port, LdapSchema.LDAP, version);
        }

        public static void Connect(this ILdapConnection connection, Uri uri,
            LdapVersion version = LdapVersion.LDAP_VERSION3)
        {
            connection.Connect(uri.ToString(), version);
        }

        public static void ConnectI(this ILdapConnection connection, string unixSocketPath = "",
            LdapVersion version = LdapVersion.LDAP_VERSION3)
        {
            var encoded = HttpUtility.UrlEncode(unixSocketPath, Encoding.UTF8);
            connection.Connect($"{LdapSchema.LDAPI.ToString()}://{encoded}/", version);
        }

        public static void Connect(this ILdapConnection connection, string hostname, int port,
            LdapSchema ldapSchema = LdapSchema.LDAP,
            LdapVersion version = LdapVersion.LDAP_VERSION3)
        {
            connection.Connect(new Uri($"{ldapSchema.ToString()}://{hostname}:{port}"), version);
        }
    }
}