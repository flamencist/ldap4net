using System;
using System.Runtime.InteropServices;

namespace LdapForNet.RequestHandlers
{
    internal class ExtendedRequestHandler:RequestHandler{
        protected override int SendRequest(SafeHandle handle, DirectoryRequest request, IntPtr serverControlArray, IntPtr clientControlArray, ref int messageId)
        {
            if (request is ExtendedRequest extendedRequest)
            {
                var name = extendedRequest.RequestName;
                var val = extendedRequest.RequestValue;
                var berValuePtr = IntPtr.Zero;

                if (val != null && val.Length != 0)
                {
                    var berValue = new Native.Native.berval()
                    {
                        bv_len = val.Length,
                        bv_val = Marshal.AllocHGlobal(val.Length)
                    };
                    Marshal.Copy(val, 0, berValue.bv_val, val.Length);
                    Marshal.StructureToPtr(berValue, berValuePtr, true);
                }

                return Native.ldap_extended_operation(handle, name, berValuePtr, IntPtr.Zero, IntPtr.Zero,
                    ref messageId);
            }

            return 0;
        }

        public override LdapResultCompleteStatus Handle(SafeHandle handle, Native.Native.LdapResultType resType, IntPtr msg, out DirectoryResponse response)
        {
            response = default;
            switch (resType)
            {
                case LdapForNet.Native.Native.LdapResultType.LDAP_RES_EXTENDED:
                    var requestName = IntPtr.Zero;
                    var requestValue = IntPtr.Zero;
                    string name = null;
                    byte[] value = null;
                    var rc = Native.ldap_parse_extended_result(handle, msg, ref requestName, ref requestValue, 0);
                    if (rc == (int) LdapForNet.Native.Native.ResultCode.Success)
                    {
                        if (requestName != IntPtr.Zero)
                        {
                            name = Marshal.PtrToStringAnsi(requestName);
                            Native.ldap_memfree(requestName);
                        }

                        if (requestValue != IntPtr.Zero)
                        {
                            var berval = Marshal.PtrToStructure<Native.Native.berval>(requestValue);
                            if (berval.bv_len != 0 && berval.bv_val != IntPtr.Zero)
                            {
                                value = new byte[berval.bv_len];
                                Marshal.Copy(berval.bv_val,value,0,berval.bv_len);
                            }
                            Native.ldap_memfree(requestValue);
                        }
                    }
                    response = new ExtendedResponse
                    {
                        ResultCode = (Native.Native.ResultCode)rc,
                        ResponseName = name,
                        ResponseValue = value
                    };
                    msg = IntPtr.Zero;
                    return LdapResultCompleteStatus.Complete;
                default:
                    return LdapResultCompleteStatus.Unknown;
            }
        }
    }
}