using System.Linq;
using System.Net;

namespace LdapForNet.Utils
{
    internal static class LdapUtils
    {
        private const char Separator = '.';
        private const string Localhost = "LocalHost";

        internal static string GetDnFromHostname()
        {
            var hostname = Dns.GetHostEntry(Localhost).HostName.ToLowerInvariant();
            return GetDnFromHostname(hostname);
        }

        internal static string GetDnFromHostname(string hostname)
        {
            var fullDomainName = hostname.Substring(hostname.IndexOf(Separator) + 1);
            var parts = fullDomainName.Split(Separator);
            var dnParts = parts.Select(_ => $"dc={_}");
            return string.Join(",", dnParts);
        }
    }
}