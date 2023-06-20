using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using static LdapForNet.Native.Native;

namespace LdapForNet.Native
{
    internal abstract class LdapNative
    {
        internal static LdapNative Instance => CreateInstance();

        private static LdapNative CreateInstance()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return new LdapNativeLinux();
            }

#if NETCOREAPP3_1 || NETCOREAPP5_0
            if (RuntimeInformation.IsOSPlatform(OSPlatform.FreeBSD))
            {
                return new LdapNativeLinux();
            }
#endif

            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return new LdapNativeOsx();
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return new LdapNativeWindows();
            }

            throw new PlatformNotSupportedException();
        }

        internal abstract int TrustAllCertificates(SafeHandle ld, CertificateOptions certificateType = CertificateOptions.SslTls);
        internal abstract int SetClientCertificate(SafeHandle ld, X509Certificate2 certificate);
        internal abstract int Init(ref IntPtr ld, string url);
        internal abstract void LdapConnect(SafeHandle ld, TimeSpan connectionTimeout);
        internal abstract int BindSasl(SafeHandle ld, LdapAuthType authType, LdapCredential ldapCredential);

        internal abstract Task<IntPtr> BindSaslAsync(SafeHandle ld, LdapAuthType authType,
            LdapCredential ldapCredential, LDAP_TIMEVAL timeout);

        internal abstract int BindSimple(SafeHandle ld, string who, string password);
        internal abstract Task<IntPtr> BindSimpleAsync(SafeHandle ld, string who, string password, LDAP_TIMEVAL timeout);
        internal abstract int Abandon(SafeHandle ld, int msgId, IntPtr serverctrls, IntPtr clientctrls);
        internal abstract int ldap_set_option(SafeHandle ld, int option, ref int invalue);
        internal abstract int ldap_set_option(SafeHandle ld, int option, string invalue);
        internal abstract int ldap_set_option(SafeHandle ld, int option, IntPtr invalue);
        internal abstract int ldap_get_option(SafeHandle ld, int option, ref string value);
        internal abstract int ldap_get_option(SafeHandle ld, int option, ref IntPtr value);
        internal abstract int ldap_get_option(SafeHandle ld, int option, ref int value);
        internal abstract int ldap_unbind_s(IntPtr ld);

        internal abstract int Search(SafeHandle ld, string @base, int scope, string filter, IntPtr attributes,
            int attrsonly, IntPtr serverctrls, IntPtr clientctrls, int timeout, int sizelimit, ref int msgidp);

        internal abstract LdapResultType ldap_result(SafeHandle ld, int msgid, int all, LDAP_TIMEVAL timeout,
            ref IntPtr pMessage);


        internal abstract int ldap_parse_result(SafeHandle ld, IntPtr result, ref int errcodep, ref IntPtr matcheddnp,
            ref IntPtr errmsgp, ref IntPtr referralsp, ref IntPtr serverctrlsp, int freeit);

        internal abstract string LdapError2String(int error);
        internal abstract string GetAdditionalErrorInfo(SafeHandle ld);
        internal abstract int LdapGetLastError(SafeHandle ld);

        internal abstract int ldap_parse_reference(SafeHandle ld, IntPtr reference, ref IntPtr referralsp,
            ref IntPtr serverctrlsp, int freeit);

        internal abstract IntPtr ldap_first_entry(SafeHandle ld, IntPtr message);
        internal abstract IntPtr ldap_next_entry(SafeHandle ld, IntPtr message);
        internal abstract IntPtr ldap_get_dn(SafeHandle ld, IntPtr message);
        internal abstract void ldap_memfree(IntPtr ptr);
        internal abstract void ldap_msgfree(IntPtr message);
        internal abstract IntPtr ldap_first_attribute(SafeHandle ld, IntPtr entry, ref IntPtr ppBer);
        internal abstract IntPtr ldap_next_attribute(SafeHandle ld, IntPtr entry, IntPtr pBer);
        internal abstract IntPtr ldap_get_values(SafeHandle ld, IntPtr entry, IntPtr pBer);
        internal abstract int ldap_count_values(IntPtr vals);
        internal abstract void ldap_value_free(IntPtr vals);
        internal abstract IntPtr ldap_get_values_len(SafeHandle ld, IntPtr entry, IntPtr pBer);
        internal abstract int ldap_count_values_len(IntPtr vals);
        internal abstract void ldap_value_free_len(IntPtr vals);

        internal abstract int ldap_add_ext(SafeHandle ld, string dn, IntPtr attrs, IntPtr serverctrls,
            IntPtr clientctrls, ref int msgidp);

        internal abstract int ldap_modify_ext(SafeHandle ld, string dn, IntPtr mods, IntPtr serverctrls,
            IntPtr clientctrls, ref int msgidp);

        internal abstract int ldap_delete_ext(SafeHandle ld, string dn, IntPtr serverctrls, IntPtr clientctrls,
            ref int msgidp);

        internal abstract int Compare(SafeHandle ld, string dn, string attr, string value, IntPtr bvalue,
            IntPtr serverctrls, IntPtr clientctrls, ref int msgidp);

        internal abstract int ldap_rename(SafeHandle ld, string dn, string newrdn, string newparent, int deleteoldrdn,
            IntPtr serverctrls, IntPtr clientctrls, ref int msgidp);

        internal abstract int ldap_extended_operation(SafeHandle ld, string requestoid, IntPtr requestdata,
            IntPtr serverctrls, IntPtr clientctrls, ref int msgidp);

        internal abstract int ldap_parse_extended_result(SafeHandle ldapHandle, IntPtr result, ref IntPtr oid,
            ref IntPtr data, byte freeIt);

        internal abstract int ldap_start_tls_s(SafeHandle ld, ref int serverReturnValue, ref IntPtr message,
            IntPtr serverctrls, IntPtr clientctrls);

        internal abstract int ldap_stop_tls_s(SafeHandle ld);

        internal abstract void Dispose(SafeHandle ld);

        internal abstract void ldap_controls_free(IntPtr ctrls);
        internal abstract int ldap_control_free(IntPtr control);
        internal abstract int ldap_create_sort_control(SafeHandle handle, IntPtr keys, byte critical, ref IntPtr control);
        internal abstract IntPtr ber_alloc_t(int option);
        internal abstract int ber_printf_emptyarg(SafeHandle berElement, string format);

        internal abstract int ber_printf_int(SafeHandle berElement, string format, int value);

        internal abstract int ber_printf_bytearray(SafeHandle berElement, string format, HGlobalMemHandle value, int length);

        internal abstract int ber_printf_berarray(SafeHandle berElement, string format, IntPtr value);

        internal abstract int ber_flatten(SafeHandle berElement, ref IntPtr value);

        internal abstract IntPtr ber_init(IntPtr berVal);

        internal abstract int ber_scanf(SafeHandle berElement, string format);

        internal abstract int ber_scanf_int(SafeHandle berElement, string format, ref int value);
        internal abstract int ber_peek_tag(SafeHandle berElement, ref int length);

        internal abstract int ber_scanf_ptr(SafeHandle berElement, string format, ref IntPtr value);
        internal abstract int ber_scanf_ostring(SafeHandle berElement, string format, ref IntPtr value);

        internal abstract int ber_scanf_string(SafeHandle berElement, string format, ref IntPtr value, ref int length);
        internal abstract int ber_scanf_bitstring(SafeHandle berElement, string format, ref IntPtr value, ref int length);

        internal abstract int ber_bvfree(IntPtr value);

        internal abstract int ber_bvecfree(IntPtr value);
        
        internal abstract IntPtr ber_free(IntPtr berelement, int option);
        internal abstract void ber_memfree(IntPtr value);

        internal abstract bool BerScanfSupports(char fmt);

        internal abstract void BerScanfFree(char fmt, IntPtr ptr);
        
        internal void ThrowIfError(int res, string method, IDictionary<string,string> details = default)
        {
            if (res != (int) ResultCode.Success)
            {
                throw ConstructException(LdapError2String(res), method, res, details);
            }
        }

        private static string DetailsToString(IDictionary<string, string> details)
        {
            return string.Join(Environment.NewLine, details.Select(_ => $"{_.Key}: {_.Value}"));
        }

        internal void ThrowIfError(SafeHandle ld, int res, string method, IDictionary<string, string> details = default)
        {
            if (res != (int) ResultCode.Success && res != (int) ResultCode.CompareFalse && res != (int) ResultCode.CompareTrue && res != (int) ResultCode.Referral && res != (int) ResultCode.ReferralV2)
            {
                var error = LdapError2String(res);
                var info = GetAdditionalErrorInfo(ld);
                var message = !string.IsNullOrWhiteSpace(info) ? $"{error}. {info}" : error;
                throw ConstructException(message, method, res, details);
            }
        }

        private LdapException ConstructException(string message, string method, int res,
            IDictionary<string, string> details)
        {
            var data = details != null ? new LdapExceptionData(message, method, res, DetailsToString(details)): new LdapExceptionData(message, method, res);
            return ConstructException(data);
        }
        internal LdapException ConstructException(LdapExceptionData data)
        {
            if (data.Result == null)
            {
                return new LdapException(data);
            }
            return (ResultCode) data.Result switch
            {
                ResultCode.LDAP_NOT_SUPPORTED => new LdapNotSupportedException(data),
                ResultCode.LDAP_PARAM_ERROR => new LdapParamErrorException(data),
                ResultCode.OperationsError => new LdapOperationsErrorException(data),
                ResultCode.ProtocolError => new LdapProtocolErrorException(data),
                ResultCode.TimeLimitExceeded => new LdapTimeLimitExceededException(data),
                ResultCode.SizeLimitExceeded => new LdapSizeLimitExceededException(data),
                ResultCode.AuthMethodNotSupported => new LdapAuthMethodNotSupportedException(data),
                ResultCode.StrongAuthRequired => new LdapStrongAuthRequiredException(data),
                ResultCode.AdminLimitExceeded => new LdapAdminLimitExceededException(data),
                ResultCode.UnavailableCriticalExtension => new LdapUnavailableCriticalExtensionException(data),
                ResultCode.ConfidentialityRequired => new LdapConfidentialityRequiredException(data),
                ResultCode.NoSuchAttribute => new LdapNoSuchAttributeException(data),
                ResultCode.UndefinedAttributeType => new LdapUndefinedAttributeTypeException(data),
                ResultCode.InappropriateMatching => new LdapInappropriateMatchingException(data),
                ResultCode.ConstraintViolation => new LdapConstraintViolationException(data),
                ResultCode.AttributeOrValueExists => new LdapAttributeOrValueExistsException(data),
                ResultCode.InvalidAttributeSyntax => new LdapInvalidAttributeSyntaxException(data),
                ResultCode.NoSuchObject => new LdapNoSuchObjectException(data),
                ResultCode.AliasProblem => new LdapAliasProblemException(data),
                ResultCode.InvalidDNSyntax => new LdapInvalidDnSyntaxException(data),
                ResultCode.AliasDereferencingProblem => new LdapAliasDereferencingProblemException(data),
                ResultCode.InappropriateAuthentication => new LdapInappropriateAuthenticationException(data),
                ResultCode.InvalidCredentials => new LdapInvalidCredentialsException(data),
                ResultCode.InsufficientAccessRights => new LdapInsufficientAccessRightsException(data),
                ResultCode.Busy => new LdapBusyException(data),
                ResultCode.Unavailable => new LdapUnavailableException(data),
                ResultCode.UnwillingToPerform => new LdapUnwillingToPerformException(data),
                ResultCode.LoopDetect => new LdapLoopDetectException(data),
                ResultCode.SortControlMissing => new LdapSortControlMissingException(data),
                ResultCode.OffsetRangeError => new LdapOffsetRangeErrorException(data),
                ResultCode.NamingViolation => new LdapNamingViolationException(data),
                ResultCode.ObjectClassViolation => new LdapObjectClassViolationException(data),
                ResultCode.NotAllowedOnNonLeaf => new LdapNotAllowedOnNonLeafException(data),
                ResultCode.NotAllowedOnRdn => new LdapNotAllowedOnRdnException(data),
                ResultCode.EntryAlreadyExists => new LdapEntryAlreadyExistsException(data),
                ResultCode.ObjectClassModificationsProhibited => new LdapObjectClassModificationsProhibitedException(data),
                ResultCode.ResultsTooLarge => new LdapResultsTooLargeException(data),
                ResultCode.AffectsMultipleDsas => new LdapAffectsMultipleDsasException(data),
                ResultCode.VirtualListViewError => new LdapVirtualListViewErrorException(data),
                ResultCode.Other => new LdapOtherException(data),
                _ => new LdapException(data)
            };
        }
    }
}