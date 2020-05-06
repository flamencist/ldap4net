using System;
using System.Runtime.InteropServices;
using LdapForNet.Utils;

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
                    berValuePtr = MarshalUtils.ByteArrayToBerValue(val);
                }

                var result =  Native.ldap_extended_operation(handle, name, berValuePtr, serverControlArray, clientControlArray,
                    ref messageId);
                MarshalUtils.BerValFree(berValuePtr);
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
                            name = Encoder.Instance.PtrToString(requestName);
                            Native.ldap_memfree(requestName);
                        }

                        if (requestValue != IntPtr.Zero)
                        {
                            var berval = Marshal.PtrToStructure<Native.Native.berval>(requestValue);
                            if (berval.bv_len != 0 && berval.bv_val != IntPtr.Zero)
                            {
                                value = new byte[berval.bv_len];
                                Marshal.Copy(berval.bv_val, value, 0, berval.bv_len);
                            }

                            Native.ldap_memfree(requestValue);
                        }
                    }

                    response = new ExtendedResponse
                    {
                        ResultCode = (Native.Native.ResultCode) rc,
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