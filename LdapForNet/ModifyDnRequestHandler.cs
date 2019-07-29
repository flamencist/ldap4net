using System;
using System.Runtime.InteropServices;
using LdapForNet.Native;

namespace LdapForNet
{
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

        public LdapResultCompleteStatus Handle(SafeHandle handle, Native.Native.LdapResultType resType, IntPtr msg, out DirectoryResponse response)
        {
            response = default;
            switch (resType)
            {
                case Native.Native.LdapResultType.LDAP_RES_MODDN:
                    response = new ModifyDNResponse();
                    return LdapResultCompleteStatus.Complete;
                default:
                    return LdapResultCompleteStatus.Unknown;
            }
        }
    }
}