using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using LdapForNet.Native;
using Microsoft.Win32.SafeHandles;
using static LdapForNet.Native.Native;

namespace LdapForNet
{
    public partial class LdapConnection
    {
        private SafeHandle _ld;
        private bool _bound;
        
        private void GssApiBind()
        {
            var saslDefaults = GetSaslDefaults(_ld);
            var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(saslDefaults));
            Marshal.StructureToPtr(saslDefaults, ptr, false);

            var res = ldap_sasl_interactive_bind_s(_ld, null, LdapAuthMechanism.GSSAPI, IntPtr.Zero, IntPtr.Zero,
                (uint)LdapInteractionFlags.LDAP_SASL_QUIET, (l, flags, d, interact) => (int)LdapResultCode.LDAP_SUCCESS, ptr);

            ThrowIfError(_ld, res,nameof(ldap_sasl_interactive_bind_s), new Dictionary<string, string>
            {
                [nameof(saslDefaults)] = saslDefaults.ToString()
            });
        }

        private async Task<IntPtr> WinBindAsync()
        {
            
            var msgid = 0;
            var cred = new SEC_WINNT_AUTH_IDENTITY_EX
            {
                version = SEC_WINNT_AUTH_IDENTITY_VERSION,
                length = Marshal.SizeOf(typeof(SEC_WINNT_AUTH_IDENTITY_EX)),
                flags = SEC_WINNT_AUTH_IDENTITY_UNICODE
            };
//
//            cred.packageList = MICROSOFT_KERBEROS_NAME_W;
//            cred.packageListLength = cred.packageList.Length;
            var task = Task.Factory.StartNew(() =>
            {
//                ThrowIfError(ldap_bind(_ld, null, cred, BindMethod.LDAP_AUTH_NEGOTIATE, ref msgid),nameof(ldap_bind));
                ThrowIfError(ldap_bind_s(_ld, null, cred, BindMethod.LDAP_AUTH_NEGOTIATE),nameof(ldap_bind_s));
                if (msgid == -1)
                {
                    throw new LdapException($"{nameof(WinBindAsync)} failed. {nameof(ldap_bind)} returns wrong or empty result",  nameof(ldap_bind), 1);
                }

                var result = IntPtr.Zero;
//                var rc = ldap_result(_ld, msgid, 0, IntPtr.Zero, ref result);
//
//                if (rc == LdapResultType.LDAP_ERROR || rc == LdapResultType.LDAP_TIMEOUT)
//                {
//                    ThrowIfError((int)rc,nameof(ldap_sasl_bind));
//                }

                return result;
            });
            return await task.ConfigureAwait(false);
        }

        private void LdapConnect()
        {
            var timeout = new LDAP_TIMEVAL()
            {
                tv_sec = (int)(TimeSpan.FromMinutes(2).Ticks / TimeSpan.TicksPerSecond)
            };
            ThrowIfError(ldap_connect(_ld, timeout),nameof(ldap_connect));
        }
        
        private async Task<IntPtr> GssApiBindAsync()
        {
            var task = Task.Factory.StartNew(() =>
            {
                var rc = 0;
                var msgid = 0;
                var result = IntPtr.Zero;
                var rmech = IntPtr.Zero;
                var saslDefaults = GetSaslDefaults(_ld);
                var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(saslDefaults));
                Marshal.StructureToPtr(saslDefaults, ptr, false);
                do
                {
                    rc = ldap_sasl_interactive_bind(_ld, null, LdapAuthMechanism.GSSAPI, IntPtr.Zero, IntPtr.Zero,
                        (uint) LdapInteractionFlags.LDAP_SASL_QUIET,
                        SaslInteractProc , ptr, result, ref rmech,
                        ref msgid);
                    if (rc != (int) LdapResultCode.LDAP_SASL_BIND_IN_PROGRESS)
                    {
                        break;
                    }
                    ldap_msgfree(result);

                    if (ldap_result(_ld, msgid, 0, IntPtr.Zero, ref result) == LdapResultType.LDAP_ERROR)
                    {
                        ThrowIfError(rc,nameof(ldap_sasl_interactive_bind));
                    }

                    if (result == IntPtr.Zero)
                    {
                        throw new LdapException("Result is not initialized", nameof(ldap_sasl_interactive_bind), 1);
                    }
                    
                } while (rc == (int) LdapResultCode.LDAP_SASL_BIND_IN_PROGRESS);
                
                ThrowIfError(_ld,rc, nameof(ldap_sasl_interactive_bind), new Dictionary<string, string>
                {
                    [nameof(saslDefaults)] = saslDefaults.ToString()
                });
                return result;
            });
            return await task.ConfigureAwait(false);
        }

        private static int SaslInteractProc(IntPtr ld, uint flags, IntPtr d, IntPtr @in)
        {
            var ptr = @in;
            var interact = Marshal.PtrToStructure<SaslInteract>(ptr);
            if (ld == IntPtr.Zero)
            {
                return (int)LdapResultCode.LDAP_PARAM_ERROR;
            }

            var defaults = Marshal.PtrToStructure<LdapSaslDefaults>(d);

            while (interact.id != (int)SaslCb.SASL_CB_LIST_END)
            {
                var rc = SaslInteraction(flags, interact, defaults);
                if (rc != (int) LdapResultCode.LDAP_SUCCESS)
                {
                    return rc;
                }

                ptr = IntPtr.Add(ptr, Marshal.SizeOf<LdapSaslDefaults>());
                interact = Marshal.PtrToStructure<SaslInteract>(ptr);
            }

            return (int) LdapResultCode.LDAP_SUCCESS;
        }

        private static int SaslInteraction(uint flags, SaslInteract interact, LdapSaslDefaults defaults)
        {
            var noecho = false;
            var challenge = false;
            switch (interact.id)
            {
                case (int)SaslCb.SASL_CB_GETREALM:
                    if (!defaults.IsEmpty())
                    {
                        interact.defresult = defaults.realm;
                    }
                    break;
                case (int)SaslCb.SASL_CB_AUTHNAME:
                    if (!defaults.IsEmpty())
                    {
                        interact.defresult = defaults.authcid;
                    }
                    break;
                case (int)SaslCb.SASL_CB_PASS:
                    if (!defaults.IsEmpty())
                    {
                        interact.defresult = defaults.passwd;
                    }
                    break;
                case (int)SaslCb.SASL_CB_USER:
                    if (!defaults.IsEmpty())
                    {
                        interact.defresult = defaults.authzid;
                    }
                    break;
                case (int)SaslCb.SASL_CB_NOECHOPROMPT:
                    noecho = true;
                    challenge = true;
                    break;
                case (int)SaslCb.SASL_CB_ECHOPROMPT:
                    challenge = true;
                    break;
            }

            if (flags != (uint)LdapInteractionFlags.LDAP_SASL_INTERACTIVE && (interact.id == (int)SaslCb.SASL_CB_USER || !string.IsNullOrEmpty(interact.defresult)))
            {
                interact.result = Marshal.StringToHGlobalAnsi(interact.defresult);
                interact.len = interact.defresult != null?(ushort)interact.defresult.Length:(ushort)0;
                return (int) LdapResultCode.LDAP_SUCCESS;
            }

            if (flags == (int) LdapInteractionFlags.LDAP_SASL_QUIET)
            {
                return (int) LdapResultCode.LDAP_OTHER;
            }

            if (noecho)
            {
                interact.result = Marshal.StringToHGlobalAnsi(interact.promt);
                interact.len = (ushort)interact.promt.Length;
            }
            else
            {
                return (int)LdapResultCode.LDAP_NOT_SUPPORTED;
            }

            if (interact.len > 0)
            {
                /*
                 * 
                 */
            }
            else
            {
                interact.result = Marshal.StringToHGlobalAnsi(interact.defresult);
                interact.len = interact.defresult != null ? (ushort) interact.defresult.Length : (ushort)0;
            }

            return (int) LdapResultCode.LDAP_SUCCESS;
        }


        private static LdapSaslDefaults GetSaslDefaults(SafeHandle ld)
        {
            var defaults = new LdapSaslDefaults { mech = LdapAuthMechanism.GSSAPI };
            ThrowIfError(ldap_get_option(ld, (int)LdapOption.LDAP_OPT_X_SASL_REALM, ref defaults.realm),nameof(ldap_get_option));
            ThrowIfError(ldap_get_option(ld, (int)LdapOption.LDAP_OPT_X_SASL_AUTHCID, ref defaults.authcid),nameof(ldap_get_option));
            ThrowIfError(ldap_get_option(ld, (int)LdapOption.LDAP_OPT_X_SASL_AUTHZID, ref defaults.authzid),nameof(ldap_get_option));
            return defaults;
        }
        
        private void SimpleBind(string userDn, string password)
        {
            ThrowIfError(
                _ld,
                ldap_simple_bind_s(_ld, userDn, password)
                ,nameof(ldap_simple_bind_s)
            );
        }

        private async Task<IntPtr> WinSimpleBindAsync(string userDn, string password)
        {
            return await Task.Factory.StartNew(() =>
            {
                var berval = new berval(password);
                var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(berval));
                Marshal.StructureToPtr(berval,ptr,false);
                var result = IntPtr.Zero;
                var msgidp = ldap_simple_bind(_ld, userDn, password);
  
                if (msgidp == -1)
                {
                    throw new LdapException($"{nameof(WinSimpleBindAsync)} failed. {nameof(ldap_simple_bind)} returns wrong or empty result",  nameof(ldap_simple_bind), 1);
                }

                var rc = ldap_result(_ld, msgidp, 0, IntPtr.Zero, ref result);

                if (rc == LdapResultType.LDAP_ERROR || rc == LdapResultType.LDAP_TIMEOUT)
                {
                    ThrowIfError((int)rc,nameof(ldap_simple_bind));
                }

                return result;
            }).ConfigureAwait(false);
        }

        private async Task<IntPtr> SimpleBindAsync(string userDn, string password)
        {
            return await Task.Factory.StartNew(() =>
            {
                var berval = new berval(password);
                var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(berval));
                Marshal.StructureToPtr(berval,ptr,false);
                var msgidp = 0;
                var result = IntPtr.Zero;
                ThrowIfError(ldap_sasl_bind(_ld, userDn, null, ptr, IntPtr.Zero, IntPtr.Zero, ref msgidp), nameof(ldap_sasl_bind));
                if (msgidp == -1)
                {
                    throw new LdapException($"{nameof(SimpleBindAsync)} failed. {nameof(ldap_result)} returns wrong or empty result",  nameof(ldap_sasl_bind), 1);
                }

                var rc = ldap_result(_ld, msgidp, 0, IntPtr.Zero, ref result);

                if (rc == LdapResultType.LDAP_ERROR || rc == LdapResultType.LDAP_TIMEOUT)
                {
                    ThrowIfError((int)rc,nameof(ldap_sasl_bind));
                }

                return result;
            }).ConfigureAwait(false);
        }
        
        private static IEnumerable<LdapEntry> GetLdapReferences(SafeHandle ld, IntPtr msg)
        {
            string[] refs = null;
            var ctrls = IntPtr.Zero;
            var rc = ldap_parse_reference(ld, msg, ref refs, ref ctrls, 0);
            ThrowIfError(ld, rc, nameof(ldap_parse_reference));
            if (refs != null)
            {
                
            }

            if (ctrls != IntPtr.Zero)
            {
                ldap_controls_free(ctrls);
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

        private static void ThrowIfError(int res, string method, IDictionary<string,string> details = default)
        {
            if (res != (int)LdapResultCode.LDAP_SUCCESS)
            {
                if (details != default)
                {
                    throw new LdapException(LdapError2String(res), method, res, DetailsToString(details));
                }
                throw new LdapException(LdapError2String(res), method, res);
            }
        }

        private static string DetailsToString(IDictionary<string,string> details)
        {
            return string.Join(Environment.NewLine, details.Select(_ => $"{_.Key}:{_.Value}"));
        }

        private static void ThrowIfError(SafeHandle ld, int res, string method, IDictionary<string,string> details = default)
        {
            if (res != (int)LdapResultCode.LDAP_SUCCESS)
            {
                var error = LdapError2String(res);
                var info = GetAdditionalErrorInfo(ld);
                var message = !string.IsNullOrWhiteSpace(info)? $"{error}. {info}": error;
                if (details != default)
                {
                    throw new LdapException(message, method, res, DetailsToString(details));
                }
                throw new LdapException(message, method, res);
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

    public class LdapHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public LdapHandle(IntPtr handle) : base(true)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            return ldap_unbind_s(handle) == (int) LdapResultCode.LDAP_SUCCESS;
        }
    }
}
