using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using LdapForNet.Utils;

namespace LdapForNet.RequestHandlers
{
    internal class ModifyRequestHandler : RequestHandler
    {
        public override int SendRequest(SafeHandle handle, DirectoryRequest request, ref int messageId)
        {
            if (request is ModifyRequest modifyRequest)
            {
                if (string.IsNullOrWhiteSpace(modifyRequest.DistinguishedName))
                {
                    throw new ArgumentNullException(nameof(modifyRequest.DistinguishedName));
                }
                      
                var attrs = modifyRequest.Attributes.Select(ToLdapMod).ToList();
            
                var ptr = Marshal.AllocHGlobal(IntPtr.Size*(attrs.Count+1)); // alloc memory for list with last element null
                MarshalUtils.StructureArrayToPtr(attrs,ptr, true);
                
                var result =  Native.ldap_modify_ext(handle,
                    modifyRequest.DistinguishedName,
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
                case LdapForNet.Native.Native.LdapResultType.LDAP_RES_MODIFY:
                    response = new ModifyResponse();
                    return LdapResultCompleteStatus.Complete;
                default:
                    return LdapResultCompleteStatus.Unknown;
            }
        }
        
        private static Native.Native.LDAPMod ToLdapMod(DirectoryModificationAttribute attribute)
        {
            var modValue = attribute.GetValues<byte[]>().ToList() ?? new List<byte[]>();
            var modValuePtr = Marshal.AllocHGlobal(IntPtr.Size * (modValue.Count+1));
            MarshalUtils.ByteArraysToBerValueArray(modValue.Select(_ => _ ?? new byte[0]).ToArray(),modValuePtr);
            return new Native.Native.LDAPMod
            {
                mod_op = (int) attribute.LdapModOperation | (int) LdapForNet.Native.Native.LdapModOperation.LDAP_MOD_BVALUES,
                mod_type = Encoder.Instance.StringToPtr(attribute.Name),
                mod_vals_u = new Native.Native.LDAPMod.mod_vals
                {
                    modv_bvals = modValuePtr
                },
                mod_next = IntPtr.Zero
            };
        }

    }
}