using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using LdapForNet.Utils;

namespace LdapForNet.RequestHandlers
{
    internal class SearchRequestHandler : RequestHandler
    {
        private readonly SearchResponse _response = new SearchResponse();
        protected override int SendRequest(SafeHandle handle, DirectoryRequest request, IntPtr serverControlArray, IntPtr clientControlArray, ref int messageId)
        {
            if (request is SearchRequest searchRequest)
            {
                var attributes = GetAttributesPtr(searchRequest);
                var searchTimeLimit = (int)(searchRequest.TimeLimit.Ticks / TimeSpan.TicksPerSecond);
                return Native.Search(
                    handle,
                    searchRequest.DistinguishedName,
                    (int) searchRequest.Scope,
                    searchRequest.Filter,
                    attributes,
                     searchRequest.AttributesOnly?1:0,
                    serverControlArray,
                    clientControlArray,
                    searchTimeLimit,
                    searchRequest.SizeLimit,
                    ref messageId);
            }

            return 0;
        }

        private static IntPtr GetAttributesPtr(SearchRequest searchRequest)
        {
            
            var attributeCount = searchRequest.Attributes?.Count ?? 0;
            var searchAttributes = IntPtr.Zero;
            if (searchRequest.Attributes == null || attributeCount == 0)
            {
                return searchAttributes;
            }
            
            
            IntPtr tempPtr;
            searchAttributes = MarshalUtils.AllocHGlobalIntPtrArray(attributeCount + 1);
            int i;
            for (i = 0; i < attributeCount; i++)
            {
                var controlPtr = Marshal.StringToHGlobalAnsi(searchRequest.Attributes[i]);
                tempPtr = (IntPtr) ((long) searchAttributes + IntPtr.Size * i);
                Marshal.WriteIntPtr(tempPtr, controlPtr);
            }

            tempPtr = (IntPtr) ((long) searchAttributes + IntPtr.Size * i);
            Marshal.WriteIntPtr(tempPtr, IntPtr.Zero);

            return searchAttributes;
        }

        public override LdapResultCompleteStatus Handle(SafeHandle handle, Native.Native.LdapResultType resType, IntPtr msg, out DirectoryResponse response)
        {
            response = default;
            switch (resType)
            {
                case LdapForNet.Native.Native.LdapResultType.LDAP_RES_SEARCH_ENTRY:
                    var ber = Marshal.AllocHGlobal(IntPtr.Size);
                    _response.Entries.AddRange(GetLdapEntries(handle, msg, ber));
                    Marshal.FreeHGlobal(ber);
                    Native.ldap_msgfree(msg);
                    return LdapResultCompleteStatus.Partial;
                case LdapForNet.Native.Native.LdapResultType.LDAP_RES_SEARCH_REFERENCE:
                    return LdapResultCompleteStatus.Partial;
                case LdapForNet.Native.Native.LdapResultType.LDAP_RES_SEARCH_RESULT:
                    response = _response;
                    return LdapResultCompleteStatus.Complete;
                default:
                    return LdapResultCompleteStatus.Unknown;
            }
        }
        
        private IEnumerable<LdapEntry> GetLdapEntries(SafeHandle ld, IntPtr msg, IntPtr ber)
        {
            for (var entry = Native.ldap_first_entry(ld, msg); entry != IntPtr.Zero;
                entry = Native.ldap_next_entry(ld, entry))
            {
                yield return new LdapEntry
                {
                    Dn = GetLdapDn(ld, entry),
                    Attributes = GetLdapAttributes(ld, entry, ref ber)
                };
            }
        }
        
        private Dictionary<string, List<string>> GetLdapAttributes(SafeHandle ld, IntPtr entry, ref IntPtr ber)
        {
            var dict = new Dictionary<string, List<string>>();
            for (var attr = Native.ldap_first_attribute(ld, entry, ref ber);
                attr != IntPtr.Zero;
                attr = Native.ldap_next_attribute(ld, entry, ber))
            {
                var attrName = Marshal.PtrToStringAnsi(attr);
                if (attrName != null)    
                {
                    dict.Add(attrName, new List<string>());
                    var values = Native.ldap_get_values(ld, entry, attr);
                    if (values != IntPtr.Zero)
                    {
                        dict[attrName] = MarshalUtils.PtrToStringArray(values);
                        Native.ldap_value_free(values);
                    }
                }

                Native.ldap_memfree(attr);
            }

            return dict;
        }
        
        private string GetLdapDn(SafeHandle ld, IntPtr entry)
        {
            var ptr = Native.ldap_get_dn(ld, entry);
            var dn = Marshal.PtrToStringAnsi(ptr);
            Native.ldap_memfree(ptr);        
            return dn;
        }


    }
}