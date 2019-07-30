using System;
using System.Runtime.InteropServices;
using LdapForNet.Native;

namespace LdapForNet.RequestHandlers
{
    internal abstract class RequestHandler
    {
        protected LdapNative Native;

        protected RequestHandler()
        {
            Native = LdapNative.Instance;
        }

        internal void SetNative(LdapNative native) => Native = native;
        
        public abstract int SendRequest(SafeHandle handle, DirectoryRequest request, ref int messageId);

        public abstract LdapResultCompleteStatus Handle(SafeHandle handle, Native.Native.LdapResultType resType, IntPtr msg,
            out DirectoryResponse response);
    }
}