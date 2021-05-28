using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using LdapForNet.Utils;

namespace LdapForNet.Native
{
    internal class LdapNativeOsx : LdapNative
    {
        private readonly IList<string> _tempFiles = new List<string>();

        internal override int TrustAllCertificates(SafeHandle ld)
        {
            var value = (int) Native.LdapOption.LDAP_OPT_X_TLS_ALLOW;
            return ldap_set_option(new LdapHandle(IntPtr.Zero), (int) Native.LdapOption.LDAP_OPT_X_TLS_REQUIRE_CERT,
                ref value);
        }

        internal override int TrustAllCertificatesTls(SafeHandle ld)
        {
            return TrustAllCertificates(ld);
        }

        internal override int SetClientCertificate(SafeHandle ld, X509Certificate2 certificate)
        {
            var certFile = Path.GetTempFileName();
            var keyFile = Path.GetTempFileName();
            File.WriteAllText(certFile, CertificateToPem(certificate));
            File.WriteAllText(keyFile, RsaKeyToPem(certificate));
            _tempFiles.Add(certFile);
            _tempFiles.Add(keyFile);

            var globalHandle = new LdapHandle(IntPtr.Zero);
            ThrowIfError(ldap_set_option(globalHandle, (int) Native.LdapOption.LDAP_OPT_X_TLS_CERTFILE, certFile),
                nameof(ldap_set_option));
            return ldap_set_option(globalHandle, (int) Native.LdapOption.LDAP_OPT_X_TLS_KEYFILE, keyFile);
        }

        private static string CertificateToPem(X509Certificate2 certificate) =>
            $"-----BEGIN CERTIFICATE-----{Environment.NewLine}{Convert.ToBase64String(certificate.RawData, Base64FormattingOptions.InsertLineBreaks)}-----END CERTIFICATE-----";

        private static string RsaKeyToPem(X509Certificate2 certificate)
        {
            var privateKey = (RSA) certificate.PrivateKey;
            var keyData = privateKey.ToRsaPrivateKey();
            return
                $"-----BEGIN RSA PRIVATE KEY-----{Environment.NewLine}{Convert.ToBase64String(keyData, Base64FormattingOptions.InsertLineBreaks)}-----END RSA PRIVATE KEY-----";
        }

        internal override int Init(ref IntPtr ld, string url) => NativeMethodsOsx.ldap_initialize(ref ld, url);

        internal override int BindSasl(SafeHandle ld, Native.LdapAuthType authType, LdapCredential ldapCredential)
        {
            var mech = Native.LdapAuthMechanism.FromAuthType(authType);
            var cred = ToNative(ld, mech, ldapCredential);

            var rc = NativeMethodsOsx.ldap_sasl_interactive_bind_s(ld, null, mech, IntPtr.Zero, IntPtr.Zero,
                (uint) Native.LdapInteractionFlags.LDAP_SASL_QUIET, UnixSaslMethods.SaslInteractionProcedure, cred);
            Marshal.FreeHGlobal(cred);
            return rc;
        }

        internal override async Task<IntPtr> BindSaslAsync(SafeHandle ld, Native.LdapAuthType authType,
            LdapCredential ldapCredential, LDAP_TIMEVAL timeout)
        {
            var task = Task.Factory.StartNew(() =>
            {
                var rc = 0;
                var msgid = 0;
                var result = IntPtr.Zero;
                var rmech = IntPtr.Zero;
                var mech = Native.LdapAuthMechanism.FromAuthType(authType);
                var cred = ToNative(ld, mech, ldapCredential);
                var saslDefaults = Marshal.PtrToStructure<Native.LdapSaslDefaults>(cred);
                do
                {
                    rc = NativeMethodsOsx.ldap_sasl_interactive_bind(ld, null, mech, IntPtr.Zero, IntPtr.Zero,
                        (uint) Native.LdapInteractionFlags.LDAP_SASL_QUIET,
                        UnixSaslMethods.SaslInteractionProcedure, cred, result, ref rmech,
                        ref msgid);
                    if (rc != (int) Native.ResultCode.SaslBindInProgress)
                    {
                        break;
                    }

                    ldap_msgfree(result);

                    if (ldap_result(ld, msgid, 0, timeout, ref result) == Native.LdapResultType.LDAP_ERROR)
                    {
                        ThrowIfError(rc, nameof(NativeMethodsOsx.ldap_sasl_interactive_bind));
                    }

                    if (result == IntPtr.Zero)
                    {
                        throw new LdapException(new LdapExceptionData("Result is not initialized",
                            nameof(NativeMethodsOsx.ldap_sasl_interactive_bind), 1));
                    }
                } while (rc == (int) Native.ResultCode.SaslBindInProgress);

                Marshal.FreeHGlobal(cred);

                ThrowIfError(ld, rc, nameof(NativeMethodsOsx.ldap_sasl_interactive_bind), new Dictionary<string, string>
                {
                    [nameof(saslDefaults)] = saslDefaults.ToString()
                });
                return result;
            });
            return await task.ConfigureAwait(false);
        }

        internal override int BindSimple(SafeHandle ld, string userDn, string password) =>
            NativeMethodsOsx.ldap_simple_bind_s(ld, userDn, password);

        internal override async Task<IntPtr> BindSimpleAsync(SafeHandle ld, string userDn, string password, LDAP_TIMEVAL timeout)
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
                NativeMethodsOsx.ldap_sasl_bind(ld, userDn, null, ptr, IntPtr.Zero, IntPtr.Zero, ref msgidp);
                Marshal.FreeHGlobal(ptr);
                if (msgidp == -1)
                {
                    throw new LdapException(
                        new LdapExceptionData($"{nameof(BindSimpleAsync)} failed. {nameof(NativeMethodsOsx.ldap_sasl_bind)} returns wrong or empty result",
                            nameof(NativeMethodsOsx.ldap_sasl_bind), 1));
                }

                var rc = NativeMethodsOsx.ldap_result(ld, msgidp, 0, timeout, ref result);

                if (rc == Native.LdapResultType.LDAP_ERROR || rc == Native.LdapResultType.LDAP_TIMEOUT)
                {
                    ThrowIfError((int) rc, nameof(NativeMethodsOsx.ldap_sasl_bind));
                }

                return result;
            }).ConfigureAwait(false);
        }

        internal override int Abandon(SafeHandle ld, int msgId, IntPtr serverctrls, IntPtr clientctrls) =>
            NativeMethodsOsx.ldap_abandon_ext(ld, msgId, serverctrls, clientctrls);

        internal override int ldap_set_option(SafeHandle ld, int option, ref int invalue)
            => NativeMethodsOsx.ldap_set_option(ld, option, ref invalue);

        internal override int ldap_set_option(SafeHandle ld, int option, string invalue) =>
            NativeMethodsOsx.ldap_set_option(ld, option, invalue);

        internal override int ldap_set_option(SafeHandle ld, int option, IntPtr invalue)
            => NativeMethodsOsx.ldap_set_option(ld, option, invalue);


        internal override int ldap_get_option(SafeHandle ld, int option, ref string value)
            => NativeMethodsOsx.ldap_get_option(ld, option, ref value);

        internal override int ldap_get_option(SafeHandle ld, int option, ref IntPtr value)
            => NativeMethodsOsx.ldap_get_option(ld, option, ref value);

        internal override int ldap_get_option(SafeHandle ld, int option, ref int value) =>
            NativeMethodsOsx.ldap_get_option(ld, option, ref value);

        internal override int ldap_unbind_s(IntPtr ld) => NativeMethodsOsx.ldap_unbind_s(ld);

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

                return NativeMethodsOsx.ldap_search_ext(ld, @base, scope, filter, attributes, attrsonly,
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

        internal override Native.LdapResultType ldap_result(SafeHandle ld, int msgid, int all, LDAP_TIMEVAL timeout,
            ref IntPtr pMessage) =>
            NativeMethodsOsx.ldap_result(ld, msgid, all, timeout, ref pMessage);

        internal override int ldap_parse_result(SafeHandle ld, IntPtr result, ref int errcodep, ref IntPtr matcheddnp,
            ref IntPtr errmsgp,
            ref IntPtr referralsp, ref IntPtr serverctrlsp, int freeit) =>
            NativeMethodsOsx.ldap_parse_result(ld, result, ref errcodep, ref matcheddnp, ref errmsgp, ref referralsp,
                ref serverctrlsp, freeit);

        internal override string LdapError2String(int error) => NativeMethodsOsx.LdapError2String(error);

        internal override string GetAdditionalErrorInfo(SafeHandle ld) => NativeMethodsOsx.GetAdditionalErrorInfo(ld);

        internal override int LdapGetLastError(SafeHandle ld)
        {
            int err = -1;
            NativeMethodsOsx.ldap_get_option(ld, (int) Native.LdapOption.LDAP_OPT_RESULT_CODE, ref err);
            return err;
        }

        internal override int ldap_parse_reference(SafeHandle ld, IntPtr reference, ref IntPtr referralsp,
            ref IntPtr serverctrlsp, int freeit) =>
            NativeMethodsOsx.ldap_parse_reference(ld, reference, ref referralsp, ref serverctrlsp, freeit);

        internal override IntPtr ldap_first_entry(SafeHandle ld, IntPtr message) =>
            NativeMethodsOsx.ldap_first_entry(ld, message);

        internal override IntPtr ldap_next_entry(SafeHandle ld, IntPtr message) =>
            NativeMethodsOsx.ldap_next_entry(ld, message);

        internal override IntPtr ldap_get_dn(SafeHandle ld, IntPtr message) =>
            NativeMethodsOsx.ldap_get_dn(ld, message);

        internal override void ldap_memfree(IntPtr ptr) => NativeMethodsOsx.ldap_memfree(ptr);

        internal override void ldap_msgfree(IntPtr message) => NativeMethodsOsx.ldap_msgfree(message);

        internal override IntPtr ldap_first_attribute(SafeHandle ld, IntPtr entry, ref IntPtr ppBer) =>
            NativeMethodsOsx.ldap_first_attribute(ld, entry, ref ppBer);

        internal override IntPtr ldap_next_attribute(SafeHandle ld, IntPtr entry, IntPtr pBer) =>
            NativeMethodsOsx.ldap_next_attribute(ld, entry, pBer);

        internal override int ldap_count_values(IntPtr vals) => NativeMethodsOsx.ldap_count_values(vals);
        internal override void ldap_value_free(IntPtr vals) => NativeMethodsOsx.ldap_value_free(vals);

        internal override IntPtr ldap_get_values_len(SafeHandle ld, IntPtr entry, IntPtr pBer) =>
            NativeMethodsOsx.ldap_get_values_len(ld, entry, pBer);

        internal override int ldap_count_values_len(IntPtr vals) => NativeMethodsOsx.ldap_count_values_len(vals);

        internal override void ldap_value_free_len(IntPtr vals) => NativeMethodsOsx.ldap_value_free_len(vals);

        internal override IntPtr ldap_get_values(SafeHandle ld, IntPtr entry, IntPtr pBer) =>
            NativeMethodsOsx.ldap_get_values(ld, entry, pBer);

        internal override int ldap_add_ext(SafeHandle ld, string dn, IntPtr attrs, IntPtr serverctrls,
            IntPtr clientctrls, ref int msgidp) =>
            NativeMethodsOsx.ldap_add_ext(ld, dn, attrs, serverctrls, clientctrls, ref msgidp);

        internal override int ldap_modify_ext(SafeHandle ld, string dn, IntPtr mods, IntPtr serverctrls,
            IntPtr clientctrls, ref int msgidp) =>
            NativeMethodsOsx.ldap_modify_ext(ld, dn, mods, serverctrls, clientctrls, ref msgidp);

        internal override int ldap_delete_ext(SafeHandle ld, string dn, IntPtr serverctrls, IntPtr clientctrls,
            ref int msgidp) => NativeMethodsOsx.ldap_delete_ext(ld, dn, serverctrls, clientctrls, ref msgidp);

        internal override int Compare(SafeHandle ld, string dn, string attr, string value, IntPtr bvalue,
            IntPtr serverctrls, IntPtr clientctrls,
            ref int msgidp)
        {
            var ptr = bvalue == IntPtr.Zero && value != null ? StringToBerVal(value) : bvalue;
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

        internal override int ldap_extended_operation(SafeHandle ld, string requestoid, IntPtr requestdata,
            IntPtr serverctrls,
            IntPtr clientctrls, ref int msgidp) =>
            NativeMethodsOsx.ldap_extended_operation(ld, requestoid, requestdata, serverctrls, clientctrls, ref msgidp);

        internal override int ldap_rename(SafeHandle ld, string dn, string newrdn, string newparent, int deleteoldrdn,
            IntPtr serverctrls,
            IntPtr clientctrls, ref int msgidp) =>
            NativeMethodsOsx.ldap_rename(ld, dn, newrdn, newparent, deleteoldrdn, serverctrls, clientctrls, ref msgidp);

        internal override int ldap_parse_extended_result(SafeHandle ldapHandle, IntPtr result, ref IntPtr oid,
            ref IntPtr data, byte freeIt) =>
            NativeMethodsOsx.ldap_parse_extended_result(ldapHandle, result, ref oid, ref data, freeIt);

        internal override int ldap_start_tls_s(SafeHandle ld, ref int serverReturnValue, ref IntPtr message,
            IntPtr serverctrls, IntPtr clientctrls)
        {
            return NativeMethodsOsx.ldap_start_tls_s(ld, serverctrls, clientctrls);
        }

        internal override int ldap_stop_tls_s(SafeHandle ld) => 0;

        internal override void Dispose(SafeHandle ld)
        {
            try
            {
                foreach (var file in _tempFiles)
                {
                    if (File.Exists(file))
                    {
                        File.Delete(file);
                    }
                }

                _tempFiles.Clear();
            }
            catch (Exception)
            {
                // no catch
            }
        }
        
        internal override void ldap_controls_free(IntPtr ctrls) => NativeMethodsOsx.ldap_controls_free(ctrls);
        internal override int ldap_control_free(IntPtr control) => NativeMethodsOsx.ldap_control_free(control);

        internal override int ldap_create_sort_control(SafeHandle handle, IntPtr keys, byte critical,
            ref IntPtr control)
            => NativeMethodsOsx.ldap_create_sort_control(handle, keys, critical, ref control);

        internal override IntPtr ber_alloc_t(int option) => NativeMethodsOsx.ber_alloc_t(option);

        internal override int ber_printf_emptyarg(SafeHandle berElement, string format)
            => NativeMethodsOsx.ber_printf_emptyarg(berElement, format);

        internal override int ber_printf_int(SafeHandle berElement, string format, int value)
            => NativeMethodsOsx.ber_printf_int(berElement, format, value);
        internal override int ber_printf_bytearray(SafeHandle berElement, string format, HGlobalMemHandle value, int length)
            => NativeMethodsOsx.ber_printf_bytearray(berElement, format, value, length);

        internal override int ber_printf_berarray(SafeHandle berElement, string format, IntPtr value)
            => NativeMethodsOsx.ber_printf_berarray(berElement, format, value);

        internal override int ber_flatten(SafeHandle berElement, ref IntPtr value)
            => NativeMethodsOsx.ber_flatten(berElement, ref value);

        internal override IntPtr ber_init(IntPtr value)
            => NativeMethodsOsx.ber_init(value);

        internal override int ber_scanf(SafeHandle berElement, string format)
            => NativeMethodsOsx.ber_scanf(berElement,format);

        internal override int ber_scanf_int(SafeHandle berElement, string format, ref int value)
            => NativeMethodsOsx.ber_scanf_int(berElement, format, ref value);

        internal override int ber_scanf_ptr(SafeHandle berElement, string format, ref IntPtr value)
            => NativeMethodsOsx.ber_scanf_ptr(berElement, format, ref value);

        internal override int ber_scanf_ostring(SafeHandle berElement, string format, IntPtr value) => 
            NativeMethodsOsx.ber_scanf_ostring(berElement, format, value);

        internal override int ber_scanf_string(SafeHandle berElement, string format, IntPtr value, ref int length) 
            => NativeMethodsOsx.ber_scanf_string(berElement, format, value, ref  length);

        internal override void ber_memfree(IntPtr value) => NativeMethodsOsx.ber_memfree(value);

        internal override int ber_scanf_bitstring(SafeHandle berElement, string format, ref IntPtr value, ref int length)
            => NativeMethodsOsx.ber_scanf_bitstring(berElement, format, ref value, ref length);
        internal override int ber_peek_tag(SafeHandle berElement, ref int length) => NativeMethodsOsx.ber_peek_tag(berElement, ref length);
        internal override int ber_bvfree(IntPtr value)
            => NativeMethodsOsx.ber_bvfree(value);

        internal override int ber_bvecfree(IntPtr value)
            => NativeMethodsOsx.ber_bvecfree(value);

        internal override IntPtr ber_free(IntPtr berelem, int option)
            => NativeMethodsOsx.ber_free(berelem, option);
        internal override bool BerScanfSupports(char fmt) => true;
        
        private Native.LdapSaslDefaults GetSaslDefaults(SafeHandle ld, string mech)
        {
            var defaults = new Native.LdapSaslDefaults {mech = mech};
            ThrowIfError(ldap_get_option(ld, (int) Native.LdapOption.LDAP_OPT_X_SASL_REALM, ref defaults.realm),
                nameof(ldap_get_option));
            ThrowIfError(ldap_get_option(ld, (int) Native.LdapOption.LDAP_OPT_X_SASL_AUTHCID, ref defaults.authcid),
                nameof(ldap_get_option));
            ThrowIfError(ldap_get_option(ld, (int) Native.LdapOption.LDAP_OPT_X_SASL_AUTHZID, ref defaults.authzid),
                nameof(ldap_get_option));
            return defaults;
        }

        private IntPtr ToNative(SafeHandle ld, string mech, LdapCredential ldapCredential)
        {
            var saslDefaults = GetSaslDefaults(ld, mech);
            return UnixSaslMethods.GetSaslCredentials(ldapCredential, saslDefaults);
        }

        internal override void LdapConnect(SafeHandle ld, TimeSpan connectionTimeout)
        {
            //no such method in openldap client library
        }
    }
}