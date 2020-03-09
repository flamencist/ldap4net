using System;
using System.Runtime.InteropServices;

namespace LdapForNet.RequestHandlers
{
    internal class AbandonRequestHandler : RequestHandler
    {
        protected override int SendRequest(SafeHandle handle, DirectoryRequest request, IntPtr serverControls, IntPtr clientControls,
            ref int messageId)
        {
            messageId = request.MessageId;
            return Native.Abandon(handle, request.MessageId, serverControls, clientControls);
        }

        public override LdapResultCompleteStatus Handle(SafeHandle handle, Native.Native.LdapResultType resType, IntPtr msg, out DirectoryResponse response)
        {
            throw new NotImplementedException();
        }
    }
}