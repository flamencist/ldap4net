using System;
using System.Runtime.InteropServices;

namespace LdapForNet
{
    internal interface IRequestHandler
    {
        int SendRequest(SafeHandle handle, DirectoryRequest request, ref int messageId);

        LdapResultCompleteStatus Handle(SafeHandle handle, Native.Native.LdapResultType resType, IntPtr msg,
            out DirectoryResponse response);
    }
}