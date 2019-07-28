using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace LdapForNet
{
    public partial class LdapConnection
    {
        private SafeHandle _ld;
        private bool _bound;
        
        private IEnumerable<LdapEntry> GetLdapReferences(SafeHandle ld, IntPtr msg)
        {
            string[] refs = null;
            var ctrls = IntPtr.Zero;
            var rc = _native.ldap_parse_reference(ld, msg, ref refs, ref ctrls, 0);
            _native.ThrowIfError(ld, rc, nameof(_native.ldap_parse_reference));
            if (refs != null)
            {
                
            }

            if (ctrls != IntPtr.Zero)
            {
                _native.ldap_controls_free(ctrls);
            }

            return default;
        }

        private void ThrowIfNotInitialized()
        {
            if (_ld == null || _ld.IsInvalid)
            {
                throw new LdapException($"Not initialized connection. Please invoke {nameof(Connect)} method before.");
            }
        }

        private void ThrowIfNotBound()
        {
            ThrowIfNotInitialized();
            if (_bound == false)
            {
                throw new LdapException($"Not bound. Please invoke {nameof(Bind)} method before.");
            }
        }

        private static LdapOperation GetLdapOperation(DirectoryRequest request)
        {
            LdapOperation operation;
            switch (request)
            {
                case DeleteRequest _:
                    operation = LdapOperation.LdapDelete;
                    break;
                case AddRequest _:
                    operation = LdapOperation.LdapAdd;
                    break;
                case ModifyRequest _:
                    operation = LdapOperation.LdapModify;
                    break;
                case SearchRequest _:
                    operation = LdapOperation.LdapSearch;
                    break;
                case ModifyDNRequest _:
                    operation = LdapOperation.LdapModifyDn;
                    break;
                default:
                    throw new LdapException($"Unknown ldap operation for {request.GetType()}");
            }
            
            return operation;
        }
    }
}
