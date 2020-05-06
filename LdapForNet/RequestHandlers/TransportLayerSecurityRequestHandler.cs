using System;
using System.Runtime.InteropServices;

namespace LdapForNet.RequestHandlers
{
    internal class TransportLayerSecurityRequestHandler : RequestHandler
    {
        public override int SendRequest(SafeHandle handle, DirectoryRequest request, ref int messageId)
        {
            var returnValue = 0;
            var message = IntPtr.Zero;
            return Native.ldap_start_tls_s(handle, ref returnValue, ref message, IntPtr.Zero, IntPtr.Zero);
        }

        public override LdapResultCompleteStatus Handle(SafeHandle handle, Native.Native.LdapResultType resType,
            IntPtr msg, out DirectoryResponse response)
        {
            throw new NotImplementedException();
        }
    }
}