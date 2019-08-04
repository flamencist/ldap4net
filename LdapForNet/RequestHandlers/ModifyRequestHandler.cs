using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using LdapForNet.Utils;

namespace LdapForNet.RequestHandlers
{
    internal class ModifyRequestHandler : RequestHandler
    {
        protected override int SendRequest(SafeHandle handle, DirectoryRequest request, IntPtr serverControlArray, IntPtr clientControlArray, ref int messageId)
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
                
                return Native.ldap_modify_ext(handle,
                    entry.Dn,
                    ptr,                
                    serverControlArray, 
                    clientControlArray,
                    ref messageId
                );    
            }

            return 0;
        }

        public override LdapResultCompleteStatus Handle(SafeHandle handle, Native.Native.LdapResultType resType, IntPtr msg, out DirectoryResponse response)
        {
            response = default;
            switch (resType)
            {
                case LdapForNet.Native.Native.LdapResultType.LDAP_RES_MODIFY:
                    response = new ModifyResponse();
                    return LdapResultCompleteStatus.Complete;
                default:
                    return LdapResultCompleteStatus.Unknown;
            }
        }
        
        private static Native.Native.LDAPMod ToLdapMod(LdapModifyAttribute attribute)
        {
            var modValue = GetModValue(attribute.Values);
            var modValuePtr = Marshal.AllocHGlobal(IntPtr.Size * (modValue.Count));
            MarshalUtils.StringArrayToPtr(modValue, modValuePtr);
            return new Native.Native.LDAPMod
            {
                mod_op = (int) attribute.LdapModOperation,
                mod_type = attribute.Type,
                mod_vals_u = new Native.Native.LDAPMod.mod_vals
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
}