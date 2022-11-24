using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using LdapForNet.Utils;
using static LdapForNet.Native.Native;

namespace LdapForNet
{
    public static class LdapSearchExtensions
    {
        public static LdapEntry GetRootDse(this ILdapConnection connection)
        {
            return connection.Search(
                null,
                "(objectclass=*)",
                new[] { "*", "+", "supportedExtension" },
                LdapSearchScope.LDAP_SCOPE_BASE)
                .First();
        }

        public static async Task<LdapEntry> GetRootDseAsync(this ILdapConnection connection,
            CancellationToken token = default)
        {
            return (await connection.SearchAsync(
                null,
                "(objectclass=*)",
                new[] { "*", "+", "supportedExtension" },
                LdapSearchScope.LDAP_SCOPE_BASE,
                token))
                .First();
        }

        public static IList<LdapEntry> SearchByCn(this ILdapConnection connection, string @base, string cn,
            LdapSearchScope scope = LdapSearchScope.LDAP_SCOPE_SUBTREE)
        {
            return connection.Search(@base, $"(cn={cn})", scope: scope);
        }

        public static async Task<IList<LdapEntry>> SearchByCnAsync(this ILdapConnection connection, string @base,
            string cn, LdapSearchScope scope = LdapSearchScope.LDAP_SCOPE_SUBTREE, CancellationToken token = default)
        {
            return await connection.SearchAsync(@base, $"(cn={cn})", scope: scope, token: token);
        }

        public static IList<LdapEntry> SearchByCn(this ILdapConnection connection, string cn)
        {
            return connection.SearchByCn(LdapUtils.GetDnFromHostname(), cn);
        }

        public static async Task<IList<LdapEntry>> SearchByCnAsync(this ILdapConnection connection, string cn,
            CancellationToken token = default)
        {
            return await connection.SearchByCnAsync(LdapUtils.GetDnFromHostname(), cn, token: token);
        }

        public static IList<LdapEntry> SearchBySid(this ILdapConnection connection, string @base, string sid,
            LdapSearchScope scope = LdapSearchScope.LDAP_SCOPE_SUBTREE)
        {
            var hex = HexEscaper.Escape(LdapSidConverter.ConvertToHex(sid));
            return connection.Search(@base, $"(objectSID={hex})", scope: scope);
        }

        public static async Task<IList<LdapEntry>> SearchBySidAsync(this ILdapConnection connection, string @base,
            string sid, LdapSearchScope scope = LdapSearchScope.LDAP_SCOPE_SUBTREE, CancellationToken token = default)
        {
            var hex = HexEscaper.Escape(LdapSidConverter.ConvertToHex(sid));
            return await connection.SearchAsync(@base, $"(objectSID={hex})", scope: scope, token: token);
        }

        public static IList<LdapEntry> SearchBySid(this ILdapConnection connection, string sid)
        {
            return connection.SearchBySid(LdapUtils.GetDnFromHostname(), sid);
        }

        public static async Task<IList<LdapEntry>> SearchBySidAsync(this ILdapConnection connection, string sid,
            CancellationToken token = default)
        {
            return await connection.SearchBySidAsync(LdapUtils.GetDnFromHostname(), sid, token: token);
        }
    }
}