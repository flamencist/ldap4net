using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using LdapForNet.Utils;

namespace LdapForNet.RequestHandlers
{
    internal class AddRequestHandler : RequestHandler
    {
        public override int SendRequest(SafeHandle handle, DirectoryRequest request, ref int messageId)
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

                var ptr = MarshalUtils.AllocHGlobalIntPtrArray(entry.Attributes.Count+1); 
                MarshalUtils.StructureArrayToPtr(attrs,ptr, true);

                var result =  Native.ldap_add_ext(handle,
                    addRequest.LdapEntry.Dn,
                    ptr,                
                    IntPtr.Zero, 
                    IntPtr.Zero ,
                    ref messageId
                );

                attrs.ForEach(_ =>
                {
                    MarshalUtils.BerValuesFree(_.mod_vals_u.modv_bvals);
                    Marshal.FreeHGlobal(_.mod_vals_u.modv_bvals);
                    Marshal.FreeHGlobal(_.mod_type);
                });
                Marshal.FreeHGlobal(ptr);

                return result;
            }

            return 0;

        }

        public override LdapResultCompleteStatus Handle(SafeHandle handle, Native.Native.LdapResultType resType, IntPtr msg, out DirectoryResponse response)
        {
            response = default;
            switch (resType)
            {
                case LdapForNet.Native.Native.LdapResultType.LDAP_RES_ADD:
                    response = new AddResponse();
                    return LdapResultCompleteStatus.Complete;
                default:
                    return LdapResultCompleteStatus.Unknown;
            }
        }
        
        private static Native.Native.LDAPMod ToLdapMod(KeyValuePair<string, List<string>> attribute)
        {
            return ToLdapMod(new LdapModifyAttribute
            {
                Type = attribute.Key,
                LdapModOperation = LdapForNet.Native.Native.LdapModOperation.LDAP_MOD_ADD,
                Values = attribute.Value
            });
        }

        private static Native.Native.LDAPMod ToLdapMod(LdapModifyAttribute attribute)
        {
            var modValue = attribute.Values ?? new List<string>();
            var modValuePtr = MarshalUtils.AllocHGlobalIntPtrArray(modValue.Count + 1);
            MarshalUtils.ByteArraysToBerValueArray(modValue.Select(GetModValue).ToArray(), modValuePtr);
            return new Native.Native.LDAPMod
            {
                mod_op = (int)attribute.LdapModOperation | (int)LdapForNet.Native.Native.LdapModOperation.LDAP_MOD_BVALUES,
                mod_type = Encoder.Instance.StringToPtr(attribute.Type),
                mod_vals_u = new Native.Native.LDAPMod.mod_vals
                {
                    modv_bvals = modValuePtr
                },
                mod_next = IntPtr.Zero
            };
        }

        private static byte[] GetModValue(string str) => string.IsNullOrEmpty(str) ? new byte[0] : Encoder.Instance.GetBytes(str);


    }
}