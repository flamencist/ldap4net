using System;
using System.Runtime.InteropServices;

namespace LdapForNet.RequestHandlers
{
    internal class DeleteRequestHandler : RequestHandler
    {
        public override int SendRequest(SafeHandle handle, DirectoryRequest request, ref int messageId)
        {
            if (request is DeleteRequest deleteRequest)
            {
                var dn = deleteRequest.DistinguishedName;
                if (string.IsNullOrWhiteSpace(dn))
                {
                    throw new ArgumentNullException(nameof(dn));
                }

                return Native.ldap_delete_ext(handle,
                    dn,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    ref messageId
                );
            }

            return 0;
        }

        public override LdapResultCompleteStatus Handle(SafeHandle handle, Native.Native.LdapResultType resType,
            IntPtr msg, out DirectoryResponse response)
        {
            response = default;
            switch (resType)
            {
                case LdapForNet.Native.Native.LdapResultType.LDAP_RES_DELETE:
                    response = new DeleteResponse();
                    return LdapResultCompleteStatus.Complete;
                default:
                    return LdapResultCompleteStatus.Unknown;
            }
        }
    }
}