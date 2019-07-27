using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static LdapForNet.Native.Native;

namespace LdapForNet.Native
{
    internal abstract class LdapNative
    {
        internal abstract int Init(ref IntPtr ld, string hostname, int port);
        internal abstract int BindKerberos(SafeHandle ld);
        internal abstract Task<IntPtr> BindKerberosAsync(SafeHandle ld);
        internal abstract int BindSimple(SafeHandle ld, string who,string password);
        internal abstract Task<IntPtr> BindSimpleAsync(SafeHandle ld, string who,string password);
        internal abstract int ldap_set_option(SafeHandle ld, int option, ref int invalue);
        internal abstract int ldap_set_option(SafeHandle ld, int option, ref string invalue);
        internal abstract int ldap_set_option(SafeHandle ld, int option, IntPtr invalue);
        internal abstract int ldap_get_option(SafeHandle ld, int option, ref string value);
        internal abstract int ldap_get_option(SafeHandle ld, int option, ref IntPtr value);
        internal abstract int ldap_unbind_s(IntPtr ld);
        internal abstract int ldap_search_ext(SafeHandle ld, string @base, int scope, string filter, string[] attrs,
            int attrsonly, IntPtr serverctrls, IntPtr clientctrls, IntPtr timeout, int sizelimit, ref int msgidp);
        internal abstract LdapResultType ldap_result(SafeHandle ld, int msgid, int all, IntPtr timeout,ref IntPtr pMessage);
        internal abstract int ldap_parse_result(SafeHandle ld, IntPtr result, ref int errcodep, ref string matcheddnp, ref string errmsgp, ref IntPtr referralsp,ref IntPtr serverctrlsp, int freeit);
        internal abstract string LdapError2String(int error);
        internal abstract string GetAdditionalErrorInfo(SafeHandle ld);
        internal abstract int ldap_parse_reference(SafeHandle ld, IntPtr reference, ref string[] referralsp, ref IntPtr serverctrlsp, int freeit);
        internal abstract IntPtr ldap_first_entry(SafeHandle ld, IntPtr message);
        internal abstract IntPtr ldap_next_entry(SafeHandle ld, IntPtr message);
        internal abstract IntPtr ldap_get_dn(SafeHandle ld, IntPtr message);
        internal abstract void ldap_memfree(IntPtr ptr);
        internal abstract void ldap_msgfree(IntPtr message);
        internal abstract IntPtr ldap_first_attribute(SafeHandle ld, IntPtr entry, ref IntPtr ppBer);
        internal abstract IntPtr ldap_next_attribute(SafeHandle ld, IntPtr entry, IntPtr pBer);
        internal abstract void ldap_value_free(IntPtr vals);
        internal abstract IntPtr ldap_get_values(SafeHandle ld, IntPtr entry, IntPtr pBer);
        internal abstract int ldap_add_ext(SafeHandle ld,string dn,IntPtr attrs,IntPtr serverctrls, IntPtr clientctrls,ref int msgidp );
        internal abstract int ldap_modify_ext(SafeHandle ld, string dn,IntPtr mods , IntPtr serverctrls, IntPtr clientctrls, ref int msgidp);
        internal abstract int ldap_delete_ext(SafeHandle ld, string dn, IntPtr serverctrls, IntPtr clientctrls, ref int msgidp);
        internal abstract int ldap_compare_ext(SafeHandle ld, string dn, string attr, IntPtr bvalue, IntPtr serverctrls, IntPtr clientctrls, ref int msgidp);
        internal abstract int ldap_rename(SafeHandle ld, string dn, string newrdn, string newparent, int deleteoldrdn, IntPtr serverctrls, IntPtr clientctrls, ref int msgidp);
        internal abstract void ldap_controls_free(IntPtr ctrls);
        
        
        internal void ThrowIfError(int res, string method, IDictionary<string,string> details = default)
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

        internal void ThrowIfError(SafeHandle ld, int res, string method, IDictionary<string,string> details = default)
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

    }
    
    internal class LinuxLdapNative:LdapNative
    {
        internal override int Init(ref IntPtr ld, string hostname, int port) => 
            ldap_initialize(ref ld,$"LDAP://{hostname}:{port}");

        internal override int BindKerberos(SafeHandle ld)
        {
            var saslDefaults = GetSaslDefaults(ld);
            var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(saslDefaults));
            Marshal.StructureToPtr(saslDefaults, ptr, false);

            return ldap_sasl_interactive_bind_s(ld, null, LdapAuthMechanism.GSSAPI, IntPtr.Zero, IntPtr.Zero,
                (uint)LdapInteractionFlags.LDAP_SASL_QUIET, (l, flags, d, interact) => (int)LdapResultCode.LDAP_SUCCESS, ptr);
        }
        
        private LdapSaslDefaults GetSaslDefaults(SafeHandle ld)
        {
            var defaults = new LdapSaslDefaults { mech = LdapAuthMechanism.GSSAPI };
            ThrowIfError(ldap_get_option(ld, (int)LdapOption.LDAP_OPT_X_SASL_REALM, ref defaults.realm),nameof(ldap_get_option));
            ThrowIfError(ldap_get_option(ld, (int)LdapOption.LDAP_OPT_X_SASL_AUTHCID, ref defaults.authcid),nameof(ldap_get_option));
            ThrowIfError(ldap_get_option(ld, (int)LdapOption.LDAP_OPT_X_SASL_AUTHZID, ref defaults.authzid),nameof(ldap_get_option));
            return defaults;
        }


        internal override async Task<IntPtr> BindKerberosAsync(SafeHandle ld)
        {
            var task = Task.Factory.StartNew(() =>
            {
                var rc = 0;
                var msgid = 0;
                var result = IntPtr.Zero;
                var rmech = IntPtr.Zero;
                var saslDefaults = GetSaslDefaults(ld);
                var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(saslDefaults));
                Marshal.StructureToPtr(saslDefaults, ptr, false);
                do
                {
                    rc = ldap_sasl_interactive_bind(ld, null, LdapAuthMechanism.GSSAPI, IntPtr.Zero, IntPtr.Zero,
                        (uint) LdapInteractionFlags.LDAP_SASL_QUIET,
                        SaslInteractProc , ptr, result, ref rmech,
                        ref msgid);
                    if (rc != (int) LdapResultCode.LDAP_SASL_BIND_IN_PROGRESS)
                    {
                        break;
                    }
                    ldap_msgfree(result);

                    if (ldap_result(ld, msgid, 0, IntPtr.Zero, ref result) == LdapResultType.LDAP_ERROR)
                    {
                        ThrowIfError(rc,nameof(ldap_sasl_interactive_bind));
                    }

                    if (result == IntPtr.Zero)
                    {
                        throw new LdapException("Result is not initialized", nameof(ldap_sasl_interactive_bind), 1);
                    }
                    
                } while (rc == (int) LdapResultCode.LDAP_SASL_BIND_IN_PROGRESS);
                
                ThrowIfError(ld,rc, nameof(ldap_sasl_interactive_bind), new Dictionary<string, string>
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


        internal override int BindSimple(SafeHandle ld, string userDn, string password) =>
            ldap_simple_bind_s(ld, userDn, password);

        internal override async Task<IntPtr> BindSimpleAsync(SafeHandle _ld, string userDn, string password)
        {
            
            return await Task.Factory.StartNew(() =>
            {
                var berval = new berval(password);
                var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(berval));
                Marshal.StructureToPtr(berval,ptr,false);
                var msgidp = 0;
                var result = IntPtr.Zero;
                ldap_sasl_bind(_ld, userDn, null, ptr, IntPtr.Zero, IntPtr.Zero, ref msgidp);
                if (msgidp == -1)
                {
                    throw new LdapException($"{nameof(BindSimpleAsync)} failed. {nameof(ldap_sasl_bind)} returns wrong or empty result",  nameof(ldap_sasl_bind), 1);
                }

                var rc = ldap_result(_ld, msgidp, 0, IntPtr.Zero, ref result);

                if (rc == LdapResultType.LDAP_ERROR || rc == LdapResultType.LDAP_TIMEOUT)
                {
                    ThrowIfError((int)rc,nameof(ldap_sasl_bind));
                }

                return result;
            }).ConfigureAwait(false);
        }

        internal override int ldap_set_option(SafeHandle ld, int option, ref int invalue)
        {
            throw new NotImplementedException();
        }

        internal override int ldap_set_option(SafeHandle ld, int option, ref string invalue)
        {
            throw new NotImplementedException();
        }

        internal override int ldap_set_option(SafeHandle ld, int option, IntPtr invalue)
        {
            throw new NotImplementedException();
        }

        internal override int ldap_get_option(SafeHandle ld, int option, ref string value)
        {
            throw new NotImplementedException();
        }

        internal override int ldap_get_option(SafeHandle ld, int option, ref IntPtr value)
        {
            throw new NotImplementedException();
        }

        internal override int ldap_unbind_s(IntPtr ld)
        {
            throw new NotImplementedException();
        }

        internal override int ldap_search_ext(SafeHandle ld, string @base, int scope, string filter, string[] attrs, int attrsonly,
            IntPtr serverctrls, IntPtr clientctrls, IntPtr timeout, int sizelimit, ref int msgidp)
        {
            throw new NotImplementedException();
        }

        internal override LdapResultType ldap_result(SafeHandle ld, int msgid, int all, IntPtr timeout, ref IntPtr pMessage)
        {
            throw new NotImplementedException();
        }

        internal override int ldap_parse_result(SafeHandle ld, IntPtr result, ref int errcodep, ref string matcheddnp, ref string errmsgp,
            ref IntPtr referralsp, ref IntPtr serverctrlsp, int freeit)
        {
            throw new NotImplementedException();
        }

        internal override string LdapError2String(int error)
        {
            throw new NotImplementedException();
        }

        internal override string GetAdditionalErrorInfo(SafeHandle ld)
        {
            throw new NotImplementedException();
        }

        internal override int ldap_parse_reference(SafeHandle ld, IntPtr reference, ref string[] referralsp, ref IntPtr serverctrlsp, int freeit)
        {
            throw new NotImplementedException();
        }

        internal override IntPtr ldap_first_entry(SafeHandle ld, IntPtr message)
        {
            throw new NotImplementedException();
        }

        internal override IntPtr ldap_next_entry(SafeHandle ld, IntPtr message)
        {
            throw new NotImplementedException();
        }

        internal override IntPtr ldap_get_dn(SafeHandle ld, IntPtr message)
        {
            throw new NotImplementedException();
        }

        internal override void ldap_memfree(IntPtr ptr)
        {
            throw new NotImplementedException();
        }

        internal override void ldap_msgfree(IntPtr message)
        {
            throw new NotImplementedException();
        }

        internal override IntPtr ldap_first_attribute(SafeHandle ld, IntPtr entry, ref IntPtr ppBer)
        {
            throw new NotImplementedException();
        }

        internal override IntPtr ldap_next_attribute(SafeHandle ld, IntPtr entry, IntPtr pBer)
        {
            throw new NotImplementedException();
        }

        internal override void ldap_value_free(IntPtr vals)
        {
            throw new NotImplementedException();
        }

        internal override IntPtr ldap_get_values(SafeHandle ld, IntPtr entry, IntPtr pBer)
        {
            throw new NotImplementedException();
        }

        internal override int ldap_add_ext(SafeHandle ld, string dn, IntPtr attrs, IntPtr serverctrls, IntPtr clientctrls, ref int msgidp)
        {
            throw new NotImplementedException();
        }

        internal override int ldap_modify_ext(SafeHandle ld, string dn, IntPtr mods, IntPtr serverctrls, IntPtr clientctrls, ref int msgidp)
        {
            throw new NotImplementedException();
        }

        internal override int ldap_delete_ext(SafeHandle ld, string dn, IntPtr serverctrls, IntPtr clientctrls, ref int msgidp)
        {
            throw new NotImplementedException();
        }

        internal override int ldap_compare_ext(SafeHandle ld, string dn, string attr, IntPtr bvalue, IntPtr serverctrls, IntPtr clientctrls,
            ref int msgidp)
        {
            throw new NotImplementedException();
        }

        internal override int ldap_rename(SafeHandle ld, string dn, string newrdn, string newparent, int deleteoldrdn, IntPtr serverctrls,
            IntPtr clientctrls, ref int msgidp)
        {
            throw new NotImplementedException();
        }

        internal override void ldap_controls_free(IntPtr ctrls)
        {
            throw new NotImplementedException();
        }
        
        
    }
}