using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using LdapForNet.Native;
using LdapForNet.Utils;
using static LdapForNet.Native.Native;

namespace LdapForNet
{
    internal interface IRequestHandler
    {
        int SendRequest(SafeHandle handle, DirectoryRequest request, ref int messageId);

        LdapResultCompleteStatus Handle(SafeHandle handle, LdapResultType resType, IntPtr msg,
            out DirectoryResponse response);
    }

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
                    (int) LdapSizeLimit.LDAP_NO_LIMIT,
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

    internal class AddRequestHandler : IRequestHandler
    {
        public int SendRequest(SafeHandle handle, DirectoryRequest request, ref int messageId)
        {
            if (request is AddRequest addRequest)
            {
                var entry = addRequest.LdapEntry;
                if (string.IsNullOrWhiteSpace(entry.Dn))
                {
                    throw new ArgumentNullException(nameof(entry.Dn));
                }

                if (entry.Attributes == null)
                {
                    entry.Attributes = new Dictionary<string, List<string>>();
                }

                var attrs = entry.Attributes.Select(ToLdapMod).ToList();

                var ptr = Marshal.AllocHGlobal(IntPtr.Size*(attrs.Count+1)); // alloc memory for list with last element null
                MarshalUtils.StructureArrayToPtr(attrs,ptr, true);

                return LdapNative.Instance.ldap_add_ext(handle,
                    addRequest.LdapEntry.Dn,
                    ptr,                
                    IntPtr.Zero, 
                    IntPtr.Zero ,
                    ref messageId
                );    
            }

            return 0;

        }

        public LdapResultCompleteStatus Handle(SafeHandle handle, LdapResultType resType, IntPtr msg, out DirectoryResponse response)
        {
            response = default;
            switch (resType)
            {
                case LdapResultType.LDAP_RES_ADD:
                    response = new AddResponse();
                    return LdapResultCompleteStatus.Complete;
                default:
                    return LdapResultCompleteStatus.Unknown;
            }
        }
        
        private static LDAPMod ToLdapMod(KeyValuePair<string, List<string>> attribute)
        {
            return ToLdapMod(new LdapModifyAttribute
            {
                Type = attribute.Key,
                LdapModOperation = LdapModOperation.LDAP_MOD_ADD,
                Values = attribute.Value
            });
        }
        
        private static LDAPMod ToLdapMod(LdapModifyAttribute attribute)
        {
            var modValue = GetModValue(attribute.Values);
            var modValuePtr = Marshal.AllocHGlobal(IntPtr.Size * (modValue.Count));
            MarshalUtils.StringArrayToPtr(modValue, modValuePtr);
            return new LDAPMod
            {
                mod_op = (int) attribute.LdapModOperation,
                mod_type = attribute.Type,
                mod_vals_u = new LDAPMod.mod_vals
                {
                    modv_strvals = modValuePtr,
                },
                mod_next = IntPtr.Zero
            };
        }
        
        private static List<string> GetModValue(List<string> values)
        {
            var res = values??new List<string>();
            res.Add(null);
            return res;
        }


    }

    internal class ModifyRequestHandler : IRequestHandler
    {
        public int SendRequest(SafeHandle handle, DirectoryRequest request, ref int messageId)
        {
            if (request is ModifyRequest modifyRequest)
            {
                var entry = modifyRequest.LdapEntry;
                if (string.IsNullOrWhiteSpace(entry.Dn))
                {
                    throw new ArgumentNullException(nameof(entry.Dn));
                }
            
                if (entry.Attributes == null)
                {
                    entry.Attributes = new List<LdapModifyAttribute>();
                }
            
                var attrs = entry.Attributes.Select(ToLdapMod).ToList();
            
                var ptr = Marshal.AllocHGlobal(IntPtr.Size*(attrs.Count+1)); // alloc memory for list with last element null
                MarshalUtils.StructureArrayToPtr(attrs,ptr, true);
                
                return LdapNative.Instance.ldap_modify_ext(handle,
                    entry.Dn,
                    ptr,                
                    IntPtr.Zero, 
                    IntPtr.Zero ,
                    ref messageId
                );    
            }

            return 0;
        }

        public LdapResultCompleteStatus Handle(SafeHandle handle, LdapResultType resType, IntPtr msg, out DirectoryResponse response)
        {
            response = default;
            switch (resType)
            {
                case LdapResultType.LDAP_RES_MODIFY:
                    response = new ModifyResponse();
                    return LdapResultCompleteStatus.Complete;
                default:
                    return LdapResultCompleteStatus.Unknown;
            }
        }
        
        private static LDAPMod ToLdapMod(LdapModifyAttribute attribute)
        {
            var modValue = GetModValue(attribute.Values);
            var modValuePtr = Marshal.AllocHGlobal(IntPtr.Size * (modValue.Count));
            MarshalUtils.StringArrayToPtr(modValue, modValuePtr);
            return new LDAPMod
            {
                mod_op = (int) attribute.LdapModOperation,
                mod_type = attribute.Type,
                mod_vals_u = new LDAPMod.mod_vals
                {
                    modv_strvals = modValuePtr,
                },
                mod_next = IntPtr.Zero
            };
        }
        
        private static List<string> GetModValue(List<string> values)
        {
            var res = values??new List<string>();
            res.Add(null);
            return res;
        }
    }

    internal class DeleteRequestHandler : IRequestHandler
    {
        public int SendRequest(SafeHandle handle, DirectoryRequest request, ref int messageId)
        {
            if (request is DeleteRequest deleteRequest)
            {
                var dn = deleteRequest.DistinguishedName;
                if (string.IsNullOrWhiteSpace(dn))
                {
                    throw new ArgumentNullException(nameof(dn));
                }
                return LdapNative.Instance.ldap_delete_ext(handle,
                    dn,
                    IntPtr.Zero, 
                    IntPtr.Zero ,    
                    ref messageId
                );  
            }

            return 0;
        }

        public LdapResultCompleteStatus Handle(SafeHandle handle, LdapResultType resType, IntPtr msg, out DirectoryResponse response)
        {
            response = default;
            switch (resType)
            {
                case LdapResultType.LDAP_RES_DELETE:
                    response = new DeleteResponse();
                    return LdapResultCompleteStatus.Complete;
                default:
                    return LdapResultCompleteStatus.Unknown;
            }
        }
    }
    
    internal class ModifyDnRequestHandler: IRequestHandler
    {
        public int SendRequest(SafeHandle handle, DirectoryRequest request, ref int messageId)
        {
            if (request is ModifyDNRequest modifyDnRequest)
            {
                var dn = modifyDnRequest.DistinguishedName;
                if (string.IsNullOrWhiteSpace(dn))
                {
                    throw new ArgumentNullException(nameof(dn));
                }
                return LdapNative.Instance.ldap_rename(handle,
                    dn,
                    modifyDnRequest.NewName,
                    modifyDnRequest.NewParentDistinguishedName ,    
                    modifyDnRequest.DeleteOldRdn?1:0,
                    IntPtr.Zero, 
                    IntPtr.Zero, 
                    ref messageId
                );  
            }

            return 0;
        }

        public LdapResultCompleteStatus Handle(SafeHandle handle, LdapResultType resType, IntPtr msg, out DirectoryResponse response)
        {
            response = default;
            switch (resType)
            {
                case LdapResultType.LDAP_RES_MODDN:
                    response = new ModifyDNResponse();
                    return LdapResultCompleteStatus.Complete;
                default:
                    return LdapResultCompleteStatus.Unknown;
            }
        }
    }
}