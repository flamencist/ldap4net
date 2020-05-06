using System.Net;

namespace LdapForNet.Utils
{
    internal static class DomainUtils
    {
        private const char Separator = '.';
        private const string Localhost = "LocalHost";

        internal static string GetDomainFromHostname()
        {
            var hostname = Dns.GetHostEntry(Localhost).HostName.ToLowerInvariant();
            return GetDomainFromHostname(hostname);
        }

        internal static string GetDomainFromHostname(string hostname)
        {
            return hostname.Substring(hostname.IndexOf(Separator) + 1);
        }
    }
}