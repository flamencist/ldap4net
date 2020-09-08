using System;
using System.Linq;
using System.Runtime.InteropServices;
using LdapForNet.Utils;

namespace LdapForNet.RequestHandlers
{
    internal class CompareRequestHandler : RequestHandler
    {
        protected override int SendRequest(SafeHandle handle, DirectoryRequest request, IntPtr serverControlArray, IntPtr clientControlArray, ref int messageId)
        {
            if (request is CompareRequest compareRequest)
            {
                if (string.IsNullOrEmpty(compareRequest.DistinguishedName) ||
                    string.IsNullOrEmpty(compareRequest.Assertion?.Name) ||
                    compareRequest.Assertion.GetRawValues().Count != 1
                )
                {
                    throw new LdapException(new LdapExceptionData("Wrong assertion"));
                }

                var value = compareRequest.Assertion.GetRawValues().Single();
                var stringValue = value as string;
                var berValuePtr = IntPtr.Zero;
                if (value is byte[] binaryValue && binaryValue.Length != 0)
                {
                    berValuePtr = MarshalUtils.ByteArrayToBerValue(binaryValue);
                }
                
                var result = Native.Compare(handle,compareRequest.DistinguishedName, compareRequest.Assertion.Name, stringValue, berValuePtr, serverControlArray, clientControlArray, ref messageId);
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
                case LdapForNet.Native.Native.LdapResultType.LDAP_RES_COMPARE:
                    response = new CompareResponse();
                    return LdapResultCompleteStatus.Complete;
                default:
                    return LdapResultCompleteStatus.Unknown;
            }
        }
    }
}