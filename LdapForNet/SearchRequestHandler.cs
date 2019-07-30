using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using LdapForNet.Native;
using LdapForNet.Utils;
using static LdapForNet.Native.Native;

namespace LdapForNet
{
    internal class SearchRequestHandler : IRequestHandler
    {
        private readonly SearchResponse _response = new SearchResponse();
        public int SendRequest(SafeHandle handle, DirectoryRequest request, ref int messageId)
        {
            if (request is SearchRequest searchRequest)
            {
                return LdapNative.Instance.ldap_search_ext(
                    handle,
                    searchRequest.DistinguishedName,
                    (int) searchRequest.Scope,
                    searchRequest.Filter,
                    null,
                    (int) LdapSearchAttributesOnly.False,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    (int)LdapSizeLimit.LDAP_NO_LIMIT,
                    ref messageId);
            }

            return 0;
        }

        public LdapResultCompleteStatus Handle(SafeHandle handle, LdapResultType resType, IntPtr msg, out DirectoryResponse response)
        {
            response = default;
            switch (resType)
            {
                case LdapResultType.LDAP_RES_SEARCH_ENTRY:
                    var ber = Marshal.AllocHGlobal(IntPtr.Size);
                    _response.Entries.AddRange(GetLdapEntries(handle, msg, ber));
                    Marshal.FreeHGlobal(ber);
                    LdapNative.Instance.ldap_msgfree(msg);
                    return LdapResultCompleteStatus.Partial;
                case LdapResultType.LDAP_RES_SEARCH_REFERENCE:
                    return LdapResultCompleteStatus.Partial;
                case LdapResultType.LDAP_RES_SEARCH_RESULT:
                    response = _response;
                    return LdapResultCompleteStatus.Complete;
                default:
                    return LdapResultCompleteStatus.Unknown;
            }
        }
        
        private static IEnumerable<LdapEntry> GetLdapEntries(SafeHandle ld, IntPtr msg, IntPtr ber)
        {
            for (var entry = LdapNative.Instance.ldap_first_entry(ld, msg); entry != IntPtr.Zero;
                entry = LdapNative.Instance.ldap_next_entry(ld, entry))
            {
                yield return new LdapEntry
                {
                    Dn = GetLdapDn(ld, entry),
                    Attributes = GetLdapAttributes(ld, entry, ref ber)
                };
            }
        }
        
        private static Dictionary<string, List<string>> GetLdapAttributes(SafeHandle ld, IntPtr entry, ref IntPtr ber)
        {
            var dict = new Dictionary<string, List<string>>();
            for (var attr = LdapNative.Instance.ldap_first_attribute(ld, entry, ref ber);
                attr != IntPtr.Zero;
                attr = LdapNative.Instance.ldap_next_attribute(ld, entry, ber))
            {
                var vals = LdapNative.Instance.ldap_get_values(ld, entry, attr);
                if (vals != IntPtr.Zero)
                {
                    var attrName = Marshal.PtrToStringAnsi(attr);
                    if (attrName != null)
                    {
                        dict.Add(attrName, MarshalUtils.PtrToStringArray(vals));
                    }
                    LdapNative.Instance.ldap_value_free(vals);
                }

                LdapNative.Instance.ldap_memfree(attr);
            }

            return dict;
        }
        
        private static string GetLdapDn(SafeHandle ld, IntPtr entry)
        {
            var ptr = LdapNative.Instance.ldap_get_dn(ld, entry);
            var dn = Marshal.PtrToStringAnsi(ptr);
            LdapNative.Instance.ldap_memfree(ptr);
            return dn;
        }


    }
}