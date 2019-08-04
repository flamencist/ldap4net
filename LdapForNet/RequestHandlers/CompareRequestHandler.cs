using System;
using System.Linq;
using System.Runtime.InteropServices;

namespace LdapForNet.RequestHandlers
{
    internal class CompareRequestHandler:RequestHandler
    {
        protected override int SendRequest(SafeHandle handle, DirectoryRequest request, IntPtr serverControlArray, IntPtr clientControlArray, ref int messageId)
        {
            if (request is CompareRequest compareRequest)
            {
                if (compareRequest.LdapEntry.Attributes == null || 
                    compareRequest.LdapEntry.Attributes?.Count != 1 ||
                    compareRequest.LdapEntry.Attributes.Single().Value.Count != 1
                    )
                {
                    throw new LdapException("Wrong assertion");
                }

                var assertion = compareRequest.LdapEntry.Attributes.Single();
                var name = assertion.Key;
                var value = assertion.Value[0];
                //TODO implement for bytes assertion
                
                return Native.Compare(handle,compareRequest.LdapEntry.Dn,name,value,IntPtr.Zero, serverControlArray, clientControlArray, ref messageId);

            }

            return 0;
        }

        public override LdapResultCompleteStatus Handle(SafeHandle handle, Native.Native.LdapResultType resType, IntPtr msg, out DirectoryResponse response)
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