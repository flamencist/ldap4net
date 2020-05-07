using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using LdapForNet.Utils;

namespace LdapForNet.Native
{
    internal class LdapNativeLinux : LdapNative
    {
        internal override int TrustAllCertificates(SafeHandle ld)
        {
            var value = (int) Native.LdapOption.LDAP_OPT_X_TLS_ALLOW;
            return ldap_set_option(new LdapHandle(IntPtr.Zero), (int) Native.LdapOption.LDAP_OPT_X_TLS_REQUIRE_CERT,
                ref value);
        }

        internal override int SetClientCertificate(SafeHandle ld, X509Certificate2 certificate)
        {
            const int verifyDepth = 6;
            var certData = MarshalUtils.ByteArrayToGnuTlsDatum(certificate.Export(X509ContentType.Cert));
            var certs = Marshal.AllocHGlobal(IntPtr.Size * verifyDepth);
            for (var i = 0; i < verifyDepth; i++)
            {
                Marshal.WriteIntPtr(certs, i * IntPtr.Size, IntPtr.Zero);
            }

            var privateKey = (RSA) certificate.PrivateKey;

            var keyData = MarshalUtils.ByteArrayToGnuTlsDatum(privateKey.ToRsaPrivateKey());
            try
            {
                var max = verifyDepth;
                var tlsCtx = IntPtr.Zero;
                var isServer = 0;
                ThrowIfError(ld,
                    ldap_set_option(new LdapHandle(IntPtr.Zero), (int) Native.LdapOption.LDAP_OPT_X_TLS_NEWCTX,
                        ref isServer), nameof(ldap_set_option));
                ThrowIfError(ld,
                    ldap_get_option(new LdapHandle(IntPtr.Zero), (int) Native.LdapOption.LDAP_OPT_X_TLS_CTX,
                        ref tlsCtx),
                    nameof(ldap_set_option));

                var key = IntPtr.Zero;
                var cred = Marshal.ReadIntPtr(tlsCtx);

                ThrowIfGnuTlsError(NativeMethodsLinux.gnutls_x509_privkey_init(ref key),
                    nameof(NativeMethodsLinux.gnutls_x509_privkey_init));
                ThrowIfGnuTlsError(
                    NativeMethodsLinux.gnutls_x509_privkey_import(key, keyData,
                        NativeMethodsLinux.GNUTLS_X509_FMT.GNUTLS_X509_FMT_DER),
                    nameof(NativeMethodsLinux.gnutls_x509_privkey_import));
                ThrowIfGnuTlsError(
                    NativeMethodsLinux.gnutls_x509_crt_list_import(certs, ref max, certData,
                        NativeMethodsLinux.GNUTLS_X509_FMT.GNUTLS_X509_FMT_DER, 0),
                    nameof(NativeMethodsLinux.gnutls_x509_crt_list_import));

                var cert = Marshal.ReadIntPtr(certs);

                // If there's only one cert and it's not self-signed, then we have to build the cert chain.
                if (max == 1 && !IsSelfSigned(cert))
                {
                    for (var i = 1; i < verifyDepth; i++)
                    {
                        cert = Marshal.ReadIntPtr(certs, (i - 1) * IntPtr.Size);
                        var issuer = Marshal.ReadIntPtr(certs, i * IntPtr.Size);


                        if (NativeMethodsLinux.gnutls_certificate_get_issuer(cred, cert, ref issuer, 0) != 0)
                        {
                            break;
                        }

                        Marshal.WriteIntPtr(certs, i * IntPtr.Size, issuer);
                        max++;

                        if (IsSelfSigned(issuer))
                        {
                            break;
                        }
                    }
                }

                ThrowIfGnuTlsError(NativeMethodsLinux.gnutls_certificate_set_x509_key(cred, certs, max, key),
                    nameof(NativeMethodsLinux.gnutls_certificate_set_x509_key));
                NativeMethodsLinux.gnutls_certificate_set_verify_flags(cred, 0);
                return ldap_set_option(new LdapHandle(IntPtr.Zero), (int) Native.LdapOption.LDAP_OPT_X_TLS_CTX, tlsCtx);
            }
            finally
            {
                MarshalUtils.TlsDatumFree(certData);
                MarshalUtils.TlsDatumFree(keyData);
                if (certs != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(certs);
                }
            }
        }

        private bool IsSelfSigned(IntPtr cert) => NativeMethodsLinux.gnutls_x509_crt_check_issuer(cert, cert) != 0;

        private static void ThrowIfGnuTlsError(int res, string method)
        {
            if (res < 0)
            {
                var errorName = Encoder.Instance.PtrToString(NativeMethodsLinux.gnutls_strerror_name(res));
                var errorMessage = Encoder.Instance.PtrToString(NativeMethodsLinux.gnutls_strerror(res));
                throw new LdapException(
                    $"GnuTls error name: {errorName}. GnuTls error message: {errorMessage} Result: {res}. Method: {method}");
            }
        }

        internal override int Init(ref IntPtr ld, string url)
        {
            return NativeMethodsLinux.ldap_initialize(ref ld, url);
        }

        internal override int BindSasl(SafeHandle ld, Native.LdapAuthType authType, LdapCredential ldapCredential)
        {
            var mechanism = Native.LdapAuthMechanism.FromAuthType(authType);
            var cred = ToNative(ld, mechanism, ldapCredential);

            var rc = NativeMethodsLinux.ldap_sasl_interactive_bind_s(ld, null, mechanism, IntPtr.Zero, IntPtr.Zero,
                (uint) Native.LdapInteractionFlags.LDAP_SASL_QUIET, UnixSaslMethods.SaslInteractionProcedure, cred);
            Marshal.FreeHGlobal(cred);
            return rc;
        }

        private IntPtr ToNative(SafeHandle ld, string mechanism, LdapCredential ldapCredential)
        {
            var saslDefaults = GetSaslDefaults(ld, mechanism);
            return UnixSaslMethods.GetSaslCredentials(ldapCredential, saslDefaults);
        }

        private Native.LdapSaslDefaults GetSaslDefaults(SafeHandle ld, string mechanism)
        {
            var defaults = new Native.LdapSaslDefaults {mech = mechanism};
            ThrowIfError(ldap_get_option(ld, (int) Native.LdapOption.LDAP_OPT_X_SASL_REALM, ref defaults.realm),
                nameof(ldap_get_option));
            ThrowIfError(ldap_get_option(ld, (int) Native.LdapOption.LDAP_OPT_X_SASL_AUTHCID, ref defaults.authcid),
                nameof(ldap_get_option));
            ThrowIfError(ldap_get_option(ld, (int) Native.LdapOption.LDAP_OPT_X_SASL_AUTHZID, ref defaults.authzid),
                nameof(ldap_get_option));
            return defaults;
        }


        internal override async Task<IntPtr> BindSaslAsync(SafeHandle ld, Native.LdapAuthType authType,
            LdapCredential ldapCredential)
        {
            var task = Task.Factory.StartNew(() =>
            {
                int rc;
                var msgid = 0;
                var result = IntPtr.Zero;
                var rmech = IntPtr.Zero;
                var mech = Native.LdapAuthMechanism.FromAuthType(authType);
                var cred = ToNative(ld, mech, ldapCredential);
                var saslDefaults = Marshal.PtrToStructure<Native.LdapSaslDefaults>(cred);
                do
                {
                    rc = NativeMethodsLinux.ldap_sasl_interactive_bind(ld, null, mech, IntPtr.Zero, IntPtr.Zero,
                        (uint) Native.LdapInteractionFlags.LDAP_SASL_QUIET,
                        UnixSaslMethods.SaslInteractionProcedure, cred, result, ref rmech,
                        ref msgid);
                    if (rc != (int) Native.ResultCode.SaslBindInProgress)
                    {
                        break;
                    }

                    ldap_msgfree(result);

                    if (ldap_result(ld, msgid, 0, IntPtr.Zero, ref result) == Native.LdapResultType.LDAP_ERROR)
                    {
                        ThrowIfError(rc, nameof(NativeMethodsLinux.ldap_sasl_interactive_bind));
                    }

                    if (result == IntPtr.Zero)
                    {
                        throw new LdapException("Result is not initialized",
                            nameof(NativeMethodsLinux.ldap_sasl_interactive_bind), 1);
                    }
                } while (rc == (int) Native.ResultCode.SaslBindInProgress);

                Marshal.FreeHGlobal(cred);

                ThrowIfError(ld, rc, nameof(NativeMethodsLinux.ldap_sasl_interactive_bind),
                    new Dictionary<string, string>
                    {
                        [nameof(saslDefaults)] = saslDefaults.ToString()
                    });
                return result;
            });
            return await task.ConfigureAwait(false);
        }

        internal override int BindSimple(SafeHandle ld, string userDn, string password) =>
            NativeMethodsLinux.ldap_simple_bind_s(ld, userDn, password);

        internal override async Task<IntPtr> BindSimpleAsync(SafeHandle ld, string userDn, string password)
        {
            return await Task.Factory.StartNew(() =>
            {
                var berval = new Native.berval
                {
                    bv_len = password.Length,
                    bv_val = Encoder.Instance.StringToPtr(password)
                };
                var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(berval));
                Marshal.StructureToPtr(berval, ptr, false);
                var msgidp = 0;
                var result = IntPtr.Zero;
                NativeMethodsLinux.ldap_sasl_bind(ld, userDn, null, ptr, IntPtr.Zero, IntPtr.Zero, ref msgidp);
                Marshal.FreeHGlobal(ptr);
                if (msgidp == -1)
                {
                    throw new LdapException(
                        $"{nameof(BindSimpleAsync)} failed. {nameof(NativeMethodsLinux.ldap_sasl_bind)} returns wrong or empty result",
                        nameof(NativeMethodsLinux.ldap_sasl_bind), 1);
                }

                var rc = ldap_result(ld, msgidp, 0, IntPtr.Zero, ref result);

                if (rc == Native.LdapResultType.LDAP_ERROR || rc == Native.LdapResultType.LDAP_TIMEOUT)
                {
                    ThrowIfError((int) rc, nameof(NativeMethodsLinux.ldap_sasl_bind));
                }

                return result;
            }).ConfigureAwait(false);
        }

        internal override int Abandon(SafeHandle ld, int msgId, IntPtr serverctrls, IntPtr clientctrls) =>
            NativeMethodsLinux.ldap_abandon_ext(ld, msgId, serverctrls, clientctrls);

        internal override int ldap_set_option(SafeHandle ld, int option, ref int invalue)
            => NativeMethodsLinux.ldap_set_option(ld, option, ref invalue);

        internal override int ldap_set_option(SafeHandle ld, int option, string invalue) =>
            NativeMethodsLinux.ldap_set_option(ld, option, invalue);

        internal override int ldap_set_option(SafeHandle ld, int option, IntPtr invalue)
            => NativeMethodsLinux.ldap_set_option(ld, option, invalue);


        internal override int ldap_get_option(SafeHandle ld, int option, ref string value)
            => NativeMethodsLinux.ldap_get_option(ld, option, ref value);

        internal override int ldap_get_option(SafeHandle ld, int option, ref IntPtr value)
            => NativeMethodsLinux.ldap_get_option(ld, option, ref value);

        internal override int ldap_get_option(SafeHandle ld, int option, ref int value)
            => NativeMethodsLinux.ldap_get_option(ld, option, ref value);

        internal override int ldap_unbind_s(IntPtr ld) => NativeMethodsLinux.ldap_unbind_s(ld);

        internal override int Search(SafeHandle ld, string @base, int scope, string filter, IntPtr attributes,
            int attrsonly, IntPtr serverctrls,
            IntPtr clientctrls, int timeout, int sizelimit, ref int msgidp)
        {
            var timePtr = IntPtr.Zero;

            try
            {
                if (timeout > 0)
                {
                    var timeval = new LDAP_TIMEVAL
                    {
                        tv_sec = timeout
                    };
                    timePtr = Marshal.AllocHGlobal(Marshal.SizeOf<LDAP_TIMEVAL>());
                    Marshal.StructureToPtr(timeval, timePtr, true);
                }

                return NativeMethodsLinux.ldap_search_ext(ld, @base, scope, filter, attributes, attrsonly,
                    serverctrls, clientctrls, timePtr, sizelimit, ref msgidp);
            }
            finally
            {
                if (timePtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(timePtr);
                }
            }
        }

        internal override Native.LdapResultType ldap_result(SafeHandle ld, int msgid, int all, IntPtr timeout,
            ref IntPtr pMessage) =>
            NativeMethodsLinux.ldap_result(ld, msgid, all, timeout, ref pMessage);

        internal override int ldap_parse_result(SafeHandle ld, IntPtr result, ref int errcodep, ref IntPtr matcheddnp,
            ref IntPtr errmsgp,
            ref IntPtr referralsp, ref IntPtr serverctrlsp, int freeit) =>
            NativeMethodsLinux.ldap_parse_result(ld, result, ref errcodep, ref matcheddnp, ref errmsgp, ref referralsp,
                ref serverctrlsp, freeit);

        internal override string LdapError2String(int error) => NativeMethodsLinux.LdapError2String(error);

        internal override string GetAdditionalErrorInfo(SafeHandle ld) => NativeMethodsLinux.GetAdditionalErrorInfo(ld);

        internal override int LdapGetLastError(SafeHandle ld)
        {
            int err = -1;
            NativeMethodsLinux.ldap_get_option(ld, (int) Native.LdapOption.LDAP_OPT_RESULT_CODE, ref err);
            return err;
        }

        internal override int ldap_parse_reference(SafeHandle ld, IntPtr reference, ref string[] referralsp,
            ref IntPtr serverctrlsp, int freeit) =>
            NativeMethodsLinux.ldap_parse_reference(ld, reference, ref referralsp, ref serverctrlsp, freeit);

        internal override IntPtr ldap_first_entry(SafeHandle ld, IntPtr message) =>
            NativeMethodsLinux.ldap_first_entry(ld, message);

        internal override IntPtr ldap_next_entry(SafeHandle ld, IntPtr message) =>
            NativeMethodsLinux.ldap_next_entry(ld, message);

        internal override IntPtr ldap_get_dn(SafeHandle ld, IntPtr message) =>
            NativeMethodsLinux.ldap_get_dn(ld, message);

        internal override void ldap_memfree(IntPtr ptr) => NativeMethodsLinux.ldap_memfree(ptr);

        internal override void ldap_msgfree(IntPtr message) => NativeMethodsLinux.ldap_msgfree(message);

        internal override IntPtr ldap_first_attribute(SafeHandle ld, IntPtr entry, ref IntPtr ppBer) =>
            NativeMethodsLinux.ldap_first_attribute(ld, entry, ref ppBer);

        internal override IntPtr ldap_next_attribute(SafeHandle ld, IntPtr entry, IntPtr pBer) =>
            NativeMethodsLinux.ldap_next_attribute(ld, entry, pBer);

        internal override int ldap_count_values(IntPtr vals) => NativeMethodsLinux.ldap_count_values(vals);

        internal override void ldap_value_free(IntPtr vals) => NativeMethodsLinux.ldap_value_free(vals);

        internal override IntPtr ldap_get_values_len(SafeHandle ld, IntPtr entry, IntPtr pBer) =>
            NativeMethodsLinux.ldap_get_values_len(ld, entry, pBer);

        internal override int ldap_count_values_len(IntPtr vals) => NativeMethodsLinux.ldap_count_values_len(vals);

        internal override void ldap_value_free_len(IntPtr vals) => NativeMethodsLinux.ldap_value_free_len(vals);

        internal override IntPtr ldap_get_values(SafeHandle ld, IntPtr entry, IntPtr pBer) =>
            NativeMethodsLinux.ldap_get_values(ld, entry, pBer);

        internal override int ldap_add_ext(SafeHandle ld, string dn, IntPtr attrs, IntPtr serverctrls,
            IntPtr clientctrls, ref int msgidp) =>
            NativeMethodsLinux.ldap_add_ext(ld, dn, attrs, serverctrls, clientctrls, ref msgidp);

        internal override int ldap_modify_ext(SafeHandle ld, string dn, IntPtr mods, IntPtr serverctrls,
            IntPtr clientctrls, ref int msgidp) =>
            NativeMethodsLinux.ldap_modify_ext(ld, dn, mods, serverctrls, clientctrls, ref msgidp);

        internal override int ldap_delete_ext(SafeHandle ld, string dn, IntPtr serverctrls, IntPtr clientctrls,
            ref int msgidp) => NativeMethodsLinux.ldap_delete_ext(ld, dn, serverctrls, clientctrls, ref msgidp);

        internal override int Compare(SafeHandle ld, string dn, string attr, string value, IntPtr bvalue,
            IntPtr serverctrls, IntPtr clientctrls,
            ref int msgidp)
        {
            var ptr = bvalue == IntPtr.Zero && value != null ? StringToBerVal(value) : bvalue;
            return NativeMethodsLinux.ldap_compare_ext(ld, dn, attr, ptr, serverctrls, clientctrls, ref msgidp);
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


        internal override int ldap_rename(SafeHandle ld, string dn, string newrdn, string newparent, int deleteoldrdn,
            IntPtr serverctrls,
            IntPtr clientctrls, ref int msgidp) =>
            NativeMethodsLinux.ldap_rename(ld, dn, newrdn, newparent, deleteoldrdn, serverctrls, clientctrls,
                ref msgidp);

        internal override int ldap_extended_operation(SafeHandle ld, string requestoid, IntPtr requestdata,
            IntPtr serverctrls,
            IntPtr clientctrls, ref int msgidp) =>
            NativeMethodsLinux.ldap_extended_operation(ld, requestoid, requestdata, serverctrls, clientctrls,
                ref msgidp);

        internal override int ldap_parse_extended_result(SafeHandle ldapHandle, IntPtr result, ref IntPtr oid,
            ref IntPtr data, byte freeIt) =>
            NativeMethodsLinux.ldap_parse_extended_result(ldapHandle, result, ref oid, ref data, freeIt);

        internal override int ldap_start_tls_s(SafeHandle ld, ref int serverReturnValue, ref IntPtr message,
            IntPtr serverctrls, IntPtr clientctrls)
        {
            return NativeMethodsLinux.ldap_start_tls_s(ld, serverctrls, clientctrls);
        }

        internal override int ldap_stop_tls_s(SafeHandle ld) => 0;

        internal override void Dispose(SafeHandle ld)
        {
            //no actions
        }

        internal override void LdapConnect(SafeHandle ld)
        {
            //no such method in openldap client library
        }

        internal override void ldap_controls_free(IntPtr ctrls) => NativeMethodsLinux.ldap_controls_free(ctrls);
        internal override int ldap_control_free(IntPtr control) => NativeMethodsLinux.ldap_control_free(control);

        internal override int ldap_create_sort_control(SafeHandle handle, IntPtr keys, byte critical,
            ref IntPtr control)
            => NativeMethodsLinux.ldap_create_sort_control(handle, keys, critical, ref control);

        internal override IntPtr ber_alloc_t(int option) => NativeMethodsLinux.ber_alloc_t(option);

        internal override int ber_printf_emptyarg(SafeHandle berElement, string format)
            => NativeMethodsLinux.ber_printf_emptyarg(berElement, format);

        internal override int ber_printf_int(SafeHandle berElement, string format, int value)
            => NativeMethodsLinux.ber_printf_int(berElement, format, value);
        internal override int ber_printf_bytearray(SafeHandle berElement, string format, HGlobalMemHandle value, int length)
            => NativeMethodsLinux.ber_printf_bytearray(berElement, format, value, length);

        internal override int ber_printf_berarray(SafeHandle berElement, string format, IntPtr value)
            => NativeMethodsLinux.ber_printf_berarray(berElement, format, value);

        internal override int ber_flatten(SafeHandle berElement, ref IntPtr value)
            => NativeMethodsLinux.ber_flatten(berElement, ref value);

        internal override IntPtr ber_init(IntPtr value)
            => NativeMethodsLinux.ber_init(value);

        internal override int ber_scanf(SafeHandle berElement, string format)
            => NativeMethodsLinux.ber_scanf(berElement,format);

        internal override int ber_scanf_int(SafeHandle berElement, string format, ref int value)
            => NativeMethodsLinux.ber_scanf_int(berElement, format, ref value);

        internal override int ber_scanf_ptr(SafeHandle berElement, string format, ref IntPtr value)
            => NativeMethodsLinux.ber_scanf_ptr(berElement, format, ref value);

        internal override int ber_scanf_ostring(SafeHandle berElement, string format, IntPtr value) => 
            NativeMethodsLinux.ber_scanf_ostring(berElement, format, value);

        internal override int ber_scanf_bitstring(SafeHandle berElement, string format, ref IntPtr value, ref int length)
            => NativeMethodsLinux.ber_scanf_bitstring(berElement, format, ref value, ref length);

        internal override int ber_scanf_string(SafeHandle berElement, string format, IntPtr value, ref int length) 
            => NativeMethodsLinux.ber_scanf_string(berElement, format, value, ref  length);

        internal override int ber_peek_tag(SafeHandle berElement, ref int length) => NativeMethodsLinux.ber_peek_tag(berElement, ref length);
        internal override int ber_bvfree(IntPtr value)
            => NativeMethodsLinux.ber_bvfree(value);

        internal override int ber_bvecfree(IntPtr value)
            => NativeMethodsLinux.ber_bvecfree(value);

        internal override IntPtr ber_free(IntPtr berelem, int option)
            => NativeMethodsLinux.ber_free(berelem, option);

        internal override void ber_memfree(IntPtr value) => NativeMethodsLinux.ber_memfree(value);
        internal override bool BerScanfSupports(char fmt) => true;
    }
}