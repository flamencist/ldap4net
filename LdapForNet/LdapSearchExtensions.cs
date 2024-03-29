﻿using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using LdapForNet.Utils;
using static LdapForNet.Native.Native;

namespace LdapForNet
{
    public static class LdapSearchExtensions
    {
        public static IList<LdapEntry> SearchByCn(this ILdapConnection connection, string @base, string cn,
            LdapSearchScope scope = LdapSearchScope.LDAP_SCOPE_SUBTREE)
        {
            return connection.Search(@base, $"(cn={cn})", scope: scope);
        }

        public static LdapEntry GetRootDse(this ILdapConnection connection)
        {
            var result = connection.Search(null, "(objectclass=*)",
                    new[]
                    {
                        "namingContexts", "subschemaSubentry", "supportedLDAPVersion", "supportedSASLMechanisms",
                        "supportedExtension", "supportedControl", "supportedFeatures", "vendorName", "vendorVersion"
                    }, LdapSearchScope.LDAP_SCOPE_BASE)
                .FirstOrDefault();
            if (result == null)
            {
                return null;
            }

            var rootDse = connection.Search(null, "(objectclass=*)", scope: LdapSearchScope.LDAP_SCOPE_BASE).First();
            foreach (var attribute in rootDse.DirectoryAttributes)
            {
	            result.DirectoryAttributes.Remove(attribute.Name);
                result.DirectoryAttributes.Add(attribute);
            }

            return result;
        }

        public static async Task<IList<LdapEntry>> SearchByCnAsync(this ILdapConnection connection, string @base,
            string cn, LdapSearchScope scope = LdapSearchScope.LDAP_SCOPE_SUBTREE)
        {
            return await connection.SearchAsync(@base, $"(cn={cn})", scope: scope);
        }

        public static IList<LdapEntry> SearchByCn(this ILdapConnection connection, string cn)
        {
            return connection.SearchByCn(LdapUtils.GetDnFromHostname(), cn);
        }

        public static async Task<IList<LdapEntry>> SearchByCnAsync(this ILdapConnection connection, string cn)
        {
            return await connection.SearchByCnAsync(LdapUtils.GetDnFromHostname(), cn);
        }

        public static IList<LdapEntry> SearchBySid(this ILdapConnection connection, string @base, string sid,
            LdapSearchScope scope = LdapSearchScope.LDAP_SCOPE_SUBTREE)
        {
            var hex = HexEscaper.Escape(LdapSidConverter.ConvertToHex(sid));
            return connection.Search(@base, $"(objectSID={hex})", scope: scope);
        }

        public static async Task<IList<LdapEntry>> SearchBySidAsync(this ILdapConnection connection, string @base,
            string sid, LdapSearchScope scope = LdapSearchScope.LDAP_SCOPE_SUBTREE)
        {
            var hex = HexEscaper.Escape(LdapSidConverter.ConvertToHex(sid));
            return await connection.SearchAsync(@base, $"(objectSID={hex})", scope: scope);
        }

        public static IList<LdapEntry> SearchBySid(this ILdapConnection connection, string sid)
        {
            return connection.SearchBySid(LdapUtils.GetDnFromHostname(), sid);
        }

        public static async Task<IList<LdapEntry>> SearchBySidAsync(this ILdapConnection connection, string sid)
        {
            return await connection.SearchBySidAsync(LdapUtils.GetDnFromHostname(), sid);
        }
    }
}