using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using LdapForNet.Utils;

namespace LdapForNet.Native
{
    internal class LdapNativeOsx:LdapNative
    {
        internal override int Init(ref IntPtr ld, Uri uri) =>
            NativeMethodsOsx.ldap_initialize(ref ld, uri.ToString());

        internal override int Init(ref IntPtr ld, string hostname, int port) => 
            NativeMethodsOsx.ldap_initialize(ref ld,$"LDAP://{hostname}:{port}");

        internal override int BindKerberos(SafeHandle ld)
        {
            var saslDefaults = GetSaslDefaults(ld);
            var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(saslDefaults));
            Marshal.StructureToPtr(saslDefaults, ptr, false);

            var rc = NativeMethodsOsx.ldap_sasl_interactive_bind_s(ld, null, Native.LdapAuthMechanism.GSSAPI, IntPtr.Zero, IntPtr.Zero,
                (uint)Native.LdapInteractionFlags.LDAP_SASL_QUIET, (l, flags, d, interact) => (int)Native.ResultCode.Success, ptr);
            Marshal.FreeHGlobal(ptr);
            return rc;
        }
        
        private Native.LdapSaslDefaults GetSaslDefaults(SafeHandle ld)
        {
            var defaults = new Native.LdapSaslDefaults { mech = Native.LdapAuthMechanism.GSSAPI };
            ThrowIfError(ldap_get_option(ld, (int)Native.LdapOption.LDAP_OPT_X_SASL_REALM, ref defaults.realm),nameof(ldap_get_option));
            ThrowIfError(ldap_get_option(ld, (int)Native.LdapOption.LDAP_OPT_X_SASL_AUTHCID, ref defaults.authcid),nameof(ldap_get_option));
            ThrowIfError(ldap_get_option(ld, (int)Native.LdapOption.LDAP_OPT_X_SASL_AUTHZID, ref defaults.authzid),nameof(ldap_get_option));
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
                    rc = NativeMethodsOsx.ldap_sasl_interactive_bind(ld, null, Native.LdapAuthMechanism.GSSAPI, IntPtr.Zero, IntPtr.Zero,
                        (uint) Native.LdapInteractionFlags.LDAP_SASL_QUIET,
                        SaslInteractProc , ptr, result, ref rmech,
                        ref msgid);
                    if (rc != (int) Native.ResultCode.SaslBindInProgress)
                    {
                        break;
                    }
                    NativeMethodsOsx.ldap_msgfree(result);

                    if (NativeMethodsOsx.ldap_result(ld, msgid, 0, IntPtr.Zero, ref result) == Native.LdapResultType.LDAP_ERROR)
                    {
                        ThrowIfError(rc,nameof(NativeMethodsOsx.ldap_sasl_interactive_bind));
                    }

                    if (result == IntPtr.Zero)
                    {
                        throw new LdapException("Result is not initialized", nameof(NativeMethodsOsx.ldap_sasl_interactive_bind), 1);
                    }
                    
                } while (rc == (int) Native.ResultCode.SaslBindInProgress);

                Marshal.FreeHGlobal(ptr);
                ThrowIfError(ld,rc, nameof(NativeMethodsOsx.ldap_sasl_interactive_bind), new Dictionary<string, string>
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
            var interact = Marshal.PtrToStructure<Native.SaslInteract>(ptr);
            if (ld == IntPtr.Zero)
            {
                return (int)Native.ResultCode.LDAP_PARAM_ERROR;
            }

            var defaults = Marshal.PtrToStructure<Native.LdapSaslDefaults>(d);

            while (interact.id != (int)Native.SaslCb.SASL_CB_LIST_END)
            {
                var rc = SaslInteraction(flags, interact, defaults);
                if (rc != (int) Native.ResultCode.Success)
                {
                    return rc;
                }

                ptr = IntPtr.Add(ptr, Marshal.SizeOf<Native.LdapSaslDefaults>());
                interact = Marshal.PtrToStructure<Native.SaslInteract>(ptr);
            }

            return (int) Native.ResultCode.Success;
        }

        private static int SaslInteraction(uint flags, Native.SaslInteract interact, Native.LdapSaslDefaults defaults)
        {
            var noecho = false;
            switch (interact.id)
            {
                case (int)Native.SaslCb.SASL_CB_GETREALM:
                    if (!defaults.IsEmpty())
                    {
                        interact.defresult = defaults.realm;
                    }
                    break;
                case (int)Native.SaslCb.SASL_CB_AUTHNAME:
                    if (!defaults.IsEmpty())
                    {
                        interact.defresult = defaults.authcid;
                    }
                    break;
                case (int)Native.SaslCb.SASL_CB_PASS:
                    if (!defaults.IsEmpty())
                    {
                        interact.defresult = defaults.passwd;
                    }
                    break;
                case (int)Native.SaslCb.SASL_CB_USER:
                    if (!defaults.IsEmpty())
                    {
                        interact.defresult = defaults.authzid;
                    }
                    break;
                case (int)Native.SaslCb.SASL_CB_NOECHOPROMPT:
                    noecho = true;
                    break;
                case (int)Native.SaslCb.SASL_CB_ECHOPROMPT:
                    break;
            }

            if (flags != (uint)Native.LdapInteractionFlags.LDAP_SASL_INTERACTIVE && (interact.id == (int)Native.SaslCb.SASL_CB_USER || !string.IsNullOrEmpty(interact.defresult)))
            {
                interact.result = Encoder.Instance.StringToPtr(interact.defresult);
                interact.len = interact.defresult != null?(ushort)interact.defresult.Length:(ushort)0;
                return (int) Native.ResultCode.Success;
            }

            if (flags == (int) Native.LdapInteractionFlags.LDAP_SASL_QUIET)
            {
                return (int) Native.ResultCode.Other;
            }

            if (noecho)
            {
                interact.result = Encoder.Instance.StringToPtr(interact.promt);
                interact.len = (ushort)interact.promt.Length;
            }
            else
            {
                return (int)Native.ResultCode.LDAP_NOT_SUPPORTED;
            }

            if (interact.len > 0)
            {
                /*
                 * 
                 */
            }
            else
            {
                interact.result = Encoder.Instance.StringToPtr(interact.defresult);
                interact.len = interact.defresult != null ? (ushort) interact.defresult.Length : (ushort)0;
            }

            return (int) Native.ResultCode.Success;
        }


        internal override int BindSimple(SafeHandle ld, string userDn, string password) =>
            NativeMethodsOsx.ldap_simple_bind_s(ld, userDn, password);

        internal override async Task<IntPtr> BindSimpleAsync(SafeHandle _ld, string userDn, string password)
        {
            
            return await Task.Factory.StartNew(() =>
            {
                var berval = new Native.berval
                {
                    bv_len = password.Length,
                    bv_val = Encoder.Instance.StringToPtr(password)
                };
                var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(berval));
                Marshal.StructureToPtr(berval,ptr,false);
                var msgidp = 0;
                var result = IntPtr.Zero;
                NativeMethodsOsx.ldap_sasl_bind(_ld, userDn, null, ptr, IntPtr.Zero, IntPtr.Zero, ref msgidp);
                Marshal.FreeHGlobal(ptr);
                if (msgidp == -1)
                {
                    throw new LdapException($"{nameof(BindSimpleAsync)} failed. {nameof(NativeMethodsOsx.ldap_sasl_bind)} returns wrong or empty result",  nameof(NativeMethodsOsx.ldap_sasl_bind), 1);
                }

                var rc = NativeMethodsOsx.ldap_result(_ld, msgidp, 0, IntPtr.Zero, ref result);

                if (rc == Native.LdapResultType.LDAP_ERROR || rc == Native.LdapResultType.LDAP_TIMEOUT)
                {
                    ThrowIfError((int)rc,nameof(NativeMethodsOsx.ldap_sasl_bind));
                }

                return result;
            }).ConfigureAwait(false);
        }

        internal override int ldap_set_option(SafeHandle ld, int option, ref int invalue) 
            => NativeMethodsOsx.ldap_set_option(ld, option, ref invalue);

        internal override int ldap_set_option(SafeHandle ld, int option, ref string invalue)=>
            NativeMethodsOsx.ldap_set_option(ld, option, ref invalue);

        internal override int ldap_set_option(SafeHandle ld, int option, IntPtr invalue)
            => NativeMethodsOsx.ldap_set_option(ld, option,  invalue);


        internal override int ldap_get_option(SafeHandle ld, int option, ref string value) 
            => NativeMethodsOsx.ldap_get_option(ld, option, ref value);

        internal override int ldap_get_option(SafeHandle ld, int option, ref IntPtr value)
            => NativeMethodsOsx.ldap_get_option(ld, option, ref value);
        
        internal override int ldap_unbind_s(IntPtr ld) => NativeMethodsOsx.ldap_unbind_s(ld);

        internal override int ldap_search_ext(SafeHandle ld, string @base, int scope, string filter, string[] attrs, int attrsonly,
            IntPtr serverctrls, IntPtr clientctrls, IntPtr timeout, int sizelimit, ref int msgidp) =>
            NativeMethodsOsx.ldap_search_ext(ld, @base, scope, filter, attrs, attrsonly,
                serverctrls, clientctrls, timeout, sizelimit, ref msgidp);

        internal override Native.LdapResultType ldap_result(SafeHandle ld, int msgid, int all, IntPtr timeout, ref IntPtr pMessage) => 
            NativeMethodsOsx.ldap_result(ld,msgid,all,timeout,ref pMessage);

        internal override int ldap_parse_result(SafeHandle ld, IntPtr result, ref int errcodep, ref IntPtr matcheddnp, ref IntPtr errmsgp,
            ref IntPtr referralsp, ref IntPtr serverctrlsp, int freeit) =>
            NativeMethodsOsx.ldap_parse_result(ld, result, ref errcodep, ref matcheddnp, ref errmsgp, ref referralsp,
                ref serverctrlsp, freeit);

        internal override string LdapError2String(int error) => NativeMethodsOsx.LdapError2String(error);

        internal override string GetAdditionalErrorInfo(SafeHandle ld) => NativeMethodsOsx.GetAdditionalErrorInfo(ld);

        internal override int ldap_parse_reference(SafeHandle ld, IntPtr reference, ref string[] referralsp, ref IntPtr serverctrlsp, int freeit) => NativeMethodsOsx.ldap_parse_reference(ld, reference, ref referralsp, ref serverctrlsp, freeit);

        internal override IntPtr ldap_first_entry(SafeHandle ld, IntPtr message) => NativeMethodsOsx.ldap_first_entry(ld, message);

        internal override IntPtr ldap_next_entry(SafeHandle ld, IntPtr message) => NativeMethodsOsx.ldap_next_entry(ld, message);

        internal override IntPtr ldap_get_dn(SafeHandle ld, IntPtr message) => NativeMethodsOsx.ldap_get_dn(ld, message);

        internal override void ldap_memfree(IntPtr ptr) => NativeMethodsOsx.ldap_memfree(ptr);

        internal override void ldap_msgfree(IntPtr message) => NativeMethodsOsx.ldap_msgfree(message);

        internal override IntPtr ldap_first_attribute(SafeHandle ld, IntPtr entry, ref IntPtr ppBer) => NativeMethodsOsx.ldap_first_attribute(ld, entry, ref ppBer);

        internal override IntPtr ldap_next_attribute(SafeHandle ld, IntPtr entry, IntPtr pBer) => NativeMethodsOsx.ldap_next_attribute(ld, entry, pBer);

        internal override int ldap_count_values(IntPtr vals) => NativeMethodsOsx.ldap_count_values(vals);
        internal override void ldap_value_free(IntPtr vals) => NativeMethodsOsx.ldap_value_free(vals);
        internal override IntPtr ldap_get_values_len(SafeHandle ld, IntPtr entry, IntPtr pBer) =>
            NativeMethodsOsx.ldap_get_values_len(ld, entry, pBer);

        internal override int ldap_count_values_len(IntPtr vals) => NativeMethodsOsx.ldap_count_values_len(vals);

        internal override void ldap_value_free_len(IntPtr vals) => NativeMethodsOsx.ldap_value_free_len(vals);

        internal override IntPtr ldap_get_values(SafeHandle ld, IntPtr entry, IntPtr pBer) => NativeMethodsOsx.ldap_get_values(ld, entry, pBer);

        internal override int ldap_add_ext(SafeHandle ld, string dn, IntPtr attrs, IntPtr serverctrls, IntPtr clientctrls, ref int msgidp) => NativeMethodsOsx.ldap_add_ext(ld, dn, attrs, serverctrls, clientctrls, ref msgidp);

        internal override int ldap_modify_ext(SafeHandle ld, string dn, IntPtr mods, IntPtr serverctrls, IntPtr clientctrls, ref int msgidp) => NativeMethodsOsx.ldap_modify_ext(ld, dn, mods, serverctrls, clientctrls, ref msgidp);

        internal override int ldap_delete_ext(SafeHandle ld, string dn, IntPtr serverctrls, IntPtr clientctrls, ref int msgidp) => NativeMethodsOsx.ldap_delete_ext(ld, dn, serverctrls, clientctrls, ref msgidp);

        internal override int Compare(SafeHandle ld, string dn, string attr, string value, IntPtr bvalue, IntPtr serverctrls, IntPtr clientctrls,
            ref int msgidp)
        {
            var ptr = bvalue == IntPtr.Zero && value != null ?
                StringToBerVal(value) : bvalue;
            return NativeMethodsOsx.ldap_compare_ext(ld, dn, attr, ptr, serverctrls, clientctrls, ref msgidp);
        }

        private static IntPtr StringToBerVal(string value)
        {
            var berval = new Native.berval
            {
                bv_len = value.Length,
                bv_val = Encoder.Instance.StringToPtr(value)
            };
            var bervalPtr = Marshal.AllocHGlobal(Marshal.SizeOf(berval));
            Marshal.StructureToPtr(berval, bervalPtr, true);
            return bervalPtr;
        }
        internal override int ldap_extended_operation(SafeHandle ld, string requestoid, IntPtr requestdata, IntPtr serverctrls,
            IntPtr clientctrls, ref int msgidp) =>
            NativeMethodsOsx.ldap_extended_operation(ld, requestoid, requestdata, serverctrls, clientctrls, ref msgidp);

        internal override int ldap_rename(SafeHandle ld, string dn, string newrdn, string newparent, int deleteoldrdn, IntPtr serverctrls,
            IntPtr clientctrls, ref int msgidp) =>
            NativeMethodsOsx.ldap_rename(ld, dn, newrdn, newparent, deleteoldrdn, serverctrls, clientctrls, ref msgidp);

        internal override int ldap_parse_extended_result(SafeHandle ldapHandle, IntPtr result, ref IntPtr oid, ref IntPtr data, byte freeIt) => 
            NativeMethodsOsx.ldap_parse_extended_result(ldapHandle, result, ref  oid, ref data,freeIt);
        
        internal override void ldap_controls_free(IntPtr ctrls) => NativeMethodsOsx.ldap_controls_free(ctrls);
    }
}