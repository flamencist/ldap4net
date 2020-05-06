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
                if (string.IsNullOrWhiteSpace(addRequest.DistinguishedName))
                {
                    throw new ArgumentNullException(nameof(addRequest.DistinguishedName));
                }

                var attrs = addRequest.Attributes.Select(ToLdapMod).ToList();

                var ptr = MarshalUtils.AllocHGlobalIntPtrArray(addRequest.Attributes.Count + 1);
                MarshalUtils.StructureArrayToPtr(attrs, ptr, true);

                var result = Native.ldap_add_ext(handle,
                    addRequest.DistinguishedName,
                    ptr,
                    IntPtr.Zero,
                    IntPtr.Zero,
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

        public override LdapResultCompleteStatus Handle(SafeHandle handle, Native.Native.LdapResultType resType,
            IntPtr msg, out DirectoryResponse response)
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

        private static Native.Native.LDAPMod ToLdapMod(DirectoryAttribute attribute) =>
            ToLdapMod(attribute, LdapForNet.Native.Native.LdapModOperation.LDAP_MOD_ADD);

        private static Native.Native.LDAPMod ToLdapMod(DirectoryAttribute attribute,
            Native.Native.LdapModOperation operation)
        {
            var modValue = attribute.GetValues<byte[]>().ToList() ?? new List<byte[]>();
            var modValuePtr = MarshalUtils.AllocHGlobalIntPtrArray(modValue.Count + 1);
            MarshalUtils.ByteArraysToBerValueArray(modValue.Select(_ => _ ?? new byte[0]).ToArray(), modValuePtr);
            return new Native.Native.LDAPMod
            {
                mod_op = (int) operation | (int) LdapForNet.Native.Native.LdapModOperation.LDAP_MOD_BVALUES,
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