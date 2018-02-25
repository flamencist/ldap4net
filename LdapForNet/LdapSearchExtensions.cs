using System.Collections.Generic;
using LdapForNet.Utils;

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
            return connection.SearchByCn(LdapUtils.GetDnFromHostname(), cn);
        }

        public static IList<LdapEntry> SearchBySid(this ILdapConnection connection,string @base, string sid)
        {
            return connection.Search(@base, $"(objectSID={LdapSidConverter.ConvertToHex(sid)})");
        }
        
        public static IList<LdapEntry> SearchBySid(this ILdapConnection connection, string sid)
        {
            return connection.SearchBySid(LdapUtils.GetDnFromHostname(), sid);
        }
    }
}