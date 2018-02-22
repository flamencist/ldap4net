using System.Collections.Generic;

namespace LdapForNet
{
    public static class LdapSearchExtensions
    {
        public static IList<LdapEntry> SearchByCn(this ILdapConnection connection, string @base, string cn)
        {
            return connection.Search(@base, $"(cn={cn})");
        }
        
        public static IList<LdapEntry> SearchByCn(this ILdapConnection connection, string cn)
        {
            return connection.SearchByCn(LdapUtils.GetDnFromHostname(), $"(cn={cn})");
        }
    }
}