using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using LdapForNet.Utils;

namespace LdapForNet.RequestHandlers
{
    internal class SearchRequestHandler : RequestHandler
    {
        private readonly SearchResponse _response = new SearchResponse();
        public override int SendRequest(SafeHandle handle, DirectoryRequest request, ref int messageId)
        {
            if (request is SearchRequest searchRequest)
            {
                var attributes = GetAttributesPtr(searchRequest);
                var searchTimeLimit = (int)(searchRequest.TimeLimit.Ticks / TimeSpan.TicksPerSecond);
                var res = Native.Search(
                    handle,
                    searchRequest.DistinguishedName,
                    (int)searchRequest.Scope,
                    searchRequest.Filter,
                    attributes,
                    searchRequest.AttributesOnly ? 1 : 0,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    searchTimeLimit,
                    searchRequest.SizeLimit,
                    ref messageId);
                FreeAttributes(attributes);
                return res;
            }

            return 0;
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
        
        private IEnumerable<DirectoryEntry> GetLdapEntries(SafeHandle ld, IntPtr msg, IntPtr ber)
        {
            for (var entry = Native.ldap_first_entry(ld, msg); entry != IntPtr.Zero;
                entry = Native.ldap_next_entry(ld, entry))
            {
                yield return new DirectoryEntry
                {
                    Dn = GetLdapDn(ld, entry),
                    Attributes = GetLdapAttributes(ld, entry, ref ber)
                };
            }
        }
        
        private SearchResultAttributeCollection GetLdapAttributes(SafeHandle ld, IntPtr entry, ref IntPtr ber)
        {
            var attributes = new SearchResultAttributeCollection();
            for (var attr = Native.ldap_first_attribute(ld, entry, ref ber);
                attr != IntPtr.Zero;
                attr = Native.ldap_next_attribute(ld, entry, ber))
            {
                var vals = Native.ldap_get_values_len(ld, entry, attr);
                if (vals != IntPtr.Zero)
                {
                    var attrName = Encoder.Instance.PtrToString(attr);
                    if (attrName != null)    
                    {
                        var directoryAttribute = new DirectoryAttribute
                        {
                            Name = attrName
                        };
                        directoryAttribute.AddValues(MarshalUtils.BerValArrayToByteArrays(vals));
                        attributes.Add(directoryAttribute);
                    }
                    Native.ldap_value_free_len(vals);
                }

                Native.ldap_memfree(attr);
            }

            return attributes;
        }
        
        private string GetLdapDn(SafeHandle ld, IntPtr entry)
        {
            var ptr = Native.ldap_get_dn(ld, entry);
            var dn = Encoder.Instance.PtrToString(ptr);
            Native.ldap_memfree(ptr);        
            return dn;
        }

        private static IntPtr GetAttributesPtr(SearchRequest searchRequest)
        {

            var attributeCount = searchRequest.Attributes?.Count ?? 0;
            var searchAttributes = IntPtr.Zero;
            if (searchRequest.Attributes == null || attributeCount == 0)
            {
                return searchAttributes;
            }


            searchAttributes = MarshalUtils.AllocHGlobalIntPtrArray(attributeCount + 1);
            int i;
            for (i = 0; i < attributeCount; i++)
            {
                var controlPtr = Encoder.Instance.StringToPtr(searchRequest.Attributes[i]);
                Marshal.WriteIntPtr(searchAttributes, IntPtr.Size * i, controlPtr);
            }

            Marshal.WriteIntPtr(searchAttributes, IntPtr.Size * i, IntPtr.Zero);

            return searchAttributes;
        }

        private static void FreeAttributes(IntPtr attributes)
        {
            foreach (var tempPtr in MarshalUtils.GetPointerArray(attributes))
            {
                Marshal.FreeHGlobal(tempPtr);
            }
            Marshal.FreeHGlobal(attributes);
        }


    }
}