using System.Collections.Generic;
using LdapForNet.Utils;
using static LdapForNet.Native.Native;

namespace LdapForNet
{
    public static class LdapSearchExtensions
    {
        public static IList<LdapEntry> SearchByCn(this ILdapConnection connection, string @base, string cn, LdapSearchScope scope = LdapSearchScope.LDAP_SCOPE_SUBTREE )
        {
            return connection.Search(@base, $"(cn={cn})",scope);
        }
        
        public static IList<LdapEntry> SearchByCn(this ILdapConnection connection, string cn)
        {
            return connection.SearchByCn(LdapUtils.GetDnFromHostname(), cn);
        }

        public static IList<LdapEntry> SearchBySid(this ILdapConnection connection,string @base, string sid, LdapSearchScope scope = LdapSearchScope.LDAP_SCOPE_SUBTREE)
        {
            var hex = HexEscaper.Escape(LdapSidConverter.ConvertToHex(sid));
            return connection.Search(@base, $"(objectSID={hex})", scope);
        }
        
        public static IList<LdapEntry> SearchBySid(this ILdapConnection connection, string sid)
        {
            return connection.SearchBySid(LdapUtils.GetDnFromHostname(), sid);
        }
    }
}