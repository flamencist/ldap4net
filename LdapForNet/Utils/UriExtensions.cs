using System;

namespace LdapForNet.Utils
{
    internal static class UriExtensions
    {
        public static bool IsLdaps(this Uri uri)
        {
            return string.Equals(uri.Scheme, Native.Native.LdapSchema.LDAPS.ToString(),
                StringComparison.InvariantCultureIgnoreCase);
        }

        public static string ToHostname(this Uri uri)
        {
            if (uri.Port > 0)
            {
                return $"{uri.Host}:{uri.Port}";
            }

            return uri.Host;
        }
    }
}