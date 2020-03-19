using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace LdapForNet.Native
{
    internal class LdapNativeWindows : LdapNative
    {
        internal override int Init(ref IntPtr ld, Uri uri)
        {
            var port = uri.Port;
            if (uri.IsDefaultPort)
            {
                if (string.Compare(uri.Scheme, Native.LdapPort.LDAP.ToString(), StringComparison.InvariantCultureIgnoreCase) == 0)
                {
                    port = (int)Native.LdapPort.LDAP;
                }
                else if (string.Compare(uri.Scheme, Native.LdapPort.LDAPS.ToString(), StringComparison.InvariantCultureIgnoreCase) == 0)
                {
                    port = (int)Native.LdapPort.LDAPS;
                }
            }

            return Init(ref ld, uri.Host, port);
        }

        private readonly char[] _supportedFormats = {'a', 'O', 'b', 'e', 'i', 'B', 'n', 't', 'v', 'V', 'x', '{', '}', '[', ']', 's', 'o', 'A', 'm' };
        internal override int Init(ref IntPtr ld, string hostname, int port)
        {
            ld =  NativeMethodsWindows.ldap_init(hostname, port);
            if (ld == IntPtr.Zero)
            {
                return -1;
            }
            return (int)Native.ResultCode.Success;
        }

        private void LdapConnect(SafeHandle ld)
        {
            var timeout = new LDAP_TIMEVAL
            {
                tv_sec = (int)(TimeSpan.FromMinutes(10).Ticks / TimeSpan.TicksPerSecond)
            };
            ThrowIfError(NativeMethodsWindows.ldap_connect(ld, timeout),nameof(NativeMethodsWindows.ldap_connect));
        }

        internal override int BindSasl(SafeHandle ld, Native.LdapAuthType authType, LdapCredential ldapCredential)
        {
            LdapConnect(ld);
            var cred = ToNative(ldapCredential);
            return NativeMethodsWindows.ldap_bind_s(ld, null, cred, BindMethod.LDAP_AUTH_NEGOTIATE);
        }



        internal override async Task<IntPtr> BindSaslAsync(SafeHandle ld, Native.LdapAuthType authType, LdapCredential ldapCredential)
        {
            LdapConnect(ld);
            var cred = ToNative(ldapCredential);

            var task = Task.Factory.StartNew(() =>
            {
                ThrowIfError(NativeMethodsWindows.ldap_bind_s(ld, null, cred, BindMethod.LDAP_AUTH_NEGOTIATE),nameof(NativeMethodsWindows.ldap_bind_s));

                return IntPtr.Zero;
            });
            return await task.ConfigureAwait(false);
        }



        internal override int BindSimple(SafeHandle ld, string who, string password)
        {
            LdapConnect(ld);
            return NativeMethodsWindows.ldap_bind_s(ld, who, password, BindMethod.LDAP_AUTH_SIMPLE);
        }

        internal override async Task<IntPtr> BindSimpleAsync(SafeHandle ld, string who, string password)
        {
            LdapConnect(ld);
            return await Task.Factory.StartNew(() =>
            {
                var result = IntPtr.Zero;
                var msgidp = NativeMethodsWindows.ldap_bind(ld, who, password, BindMethod.LDAP_AUTH_SIMPLE);
  
                if (msgidp == -1)
                {
                    throw new LdapException($"{nameof(BindSimpleAsync)} failed. {nameof(NativeMethodsWindows.ldap_bind)} returns wrong or empty result",  nameof(NativeMethodsWindows.ldap_bind), 1);
                }

                var rc = ldap_result(ld, msgidp, 0, IntPtr.Zero, ref result);

                if (rc == Native.LdapResultType.LDAP_ERROR || rc == Native.LdapResultType.LDAP_TIMEOUT)
                {
                    ThrowIfError((int)rc,nameof(NativeMethodsWindows.ldap_bind));
                }
                
                return result;
            }).ConfigureAwait(false);
        }

        internal override int Abandon(SafeHandle ld, int msgId, IntPtr serverctrls, IntPtr clientctrls) => NativeMethodsWindows.ldap_abandon(ld, msgId);

        internal override int ldap_set_option(SafeHandle ld, int option, ref int invalue) 
            => NativeMethodsWindows.ldap_set_option(ld, option, ref invalue);

        internal override int ldap_set_option(SafeHandle ld, int option, ref string invalue)=>
            NativeMethodsWindows.ldap_set_option(ld, option, ref invalue);

        internal override int ldap_set_option(SafeHandle ld, int option, IntPtr invalue)
            => NativeMethodsWindows.ldap_set_option(ld, option,  invalue);


        internal override int ldap_get_option(SafeHandle ld, int option, ref string value) 
            => NativeMethodsWindows.ldap_get_option(ld, option, ref value);

        internal override int ldap_get_option(SafeHandle ld, int option, ref IntPtr value)
            => NativeMethodsWindows.ldap_get_option(ld, option, ref value);
        
        internal override int ldap_unbind_s(IntPtr ld) => NativeMethodsWindows.ldap_unbind_s(ld);

        internal override int Search(SafeHandle ld, string @base, int scope, string filter, IntPtr attributes, int attrsonly, IntPtr serverctrls,
            IntPtr clientctrls, int timeout, int sizelimit, ref int msgidp) =>
            NativeMethodsWindows.ldap_search_ext(ld, @base, scope, filter, attributes, attrsonly,
                serverctrls, clientctrls, timeout, sizelimit, ref msgidp);

        internal override Native.LdapResultType ldap_result(SafeHandle ld, int msgid, int all, IntPtr timeout, ref IntPtr pMessage) => 
            NativeMethodsWindows.ldap_result(ld,msgid,all,timeout,ref pMessage);

        internal override int ldap_parse_result(SafeHandle ld, IntPtr result, ref int errcodep, ref IntPtr matcheddnp, ref IntPtr errmsgp,
            ref IntPtr referralsp, ref IntPtr serverctrlsp, int freeit) =>
            NativeMethodsWindows.ldap_parse_result(ld, result, ref errcodep, ref matcheddnp, ref errmsgp, ref referralsp,
                ref serverctrlsp, freeit);

        internal override string LdapError2String(int error) => NativeMethodsWindows.LdapError2String(error);

        internal override string GetAdditionalErrorInfo(SafeHandle ld) => NativeMethodsWindows.GetAdditionalErrorInfo(ld);
        internal override int LdapGetLastError(SafeHandle ld) => NativeMethodsWindows.LdapGetLastError();

        internal override int ldap_parse_reference(SafeHandle ld, IntPtr reference, ref string[] referralsp, ref IntPtr serverctrlsp, int freeit) => NativeMethodsWindows.ldap_parse_reference(ld, reference, ref referralsp, ref serverctrlsp, freeit);

        internal override IntPtr ldap_first_entry(SafeHandle ld, IntPtr message) => NativeMethodsWindows.ldap_first_entry(ld, message);

        internal override IntPtr ldap_next_entry(SafeHandle ld, IntPtr message) => NativeMethodsWindows.ldap_next_entry(ld, message);

        internal override IntPtr ldap_get_dn(SafeHandle ld, IntPtr message) => NativeMethodsWindows.ldap_get_dn(ld, message);

        internal override void ldap_memfree(IntPtr ptr) => NativeMethodsWindows.ldap_memfree(ptr);

        internal override void ldap_msgfree(IntPtr message) => NativeMethodsWindows.ldap_msgfree(message);

        internal override IntPtr ldap_first_attribute(SafeHandle ld, IntPtr entry, ref IntPtr ppBer) => NativeMethodsWindows.ldap_first_attribute(ld, entry, ref ppBer);

        internal override IntPtr ldap_next_attribute(SafeHandle ld, IntPtr entry, IntPtr pBer) => NativeMethodsWindows.ldap_next_attribute(ld, entry, pBer);

        internal override int ldap_count_values(IntPtr vals) => NativeMethodsWindows.ldap_count_values(vals);

        internal override void ldap_value_free(IntPtr vals) => NativeMethodsWindows.ldap_value_free(vals);
        internal override IntPtr ldap_get_values_len(SafeHandle ld, IntPtr entry, IntPtr pBer) =>
            NativeMethodsWindows.ldap_get_values_len(ld, entry, pBer);

        internal override int ldap_count_values_len(IntPtr vals) => NativeMethodsWindows.ldap_count_values_len(vals);

        internal override void ldap_value_free_len(IntPtr vals) => NativeMethodsWindows.ldap_value_free_len(vals);

        internal override IntPtr ldap_get_values(SafeHandle ld, IntPtr entry, IntPtr pBer) => NativeMethodsWindows.ldap_get_values(ld, entry, pBer);

        internal override int ldap_add_ext(SafeHandle ld, string dn, IntPtr attrs, IntPtr serverctrls, IntPtr clientctrls, ref int msgidp) => NativeMethodsWindows.ldap_add_ext(ld, dn, attrs, serverctrls, clientctrls, ref msgidp);

        internal override int ldap_modify_ext(SafeHandle ld, string dn, IntPtr mods, IntPtr serverctrls, IntPtr clientctrls, ref int msgidp) => NativeMethodsWindows.ldap_modify_ext(ld, dn, mods, serverctrls, clientctrls, ref msgidp);

        internal override int ldap_delete_ext(SafeHandle ld, string dn, IntPtr serverctrls, IntPtr clientctrls, ref int msgidp) => NativeMethodsWindows.ldap_delete_ext(ld, dn, serverctrls, clientctrls, ref msgidp);

        internal override int Compare(SafeHandle ld, string dn, string attr, string value, IntPtr bvalue, IntPtr serverctrls,
            IntPtr clientctrls,
            ref int msgidp) =>
            NativeMethodsWindows.ldap_compare_ext(ld, dn, attr, value, bvalue, serverctrls, clientctrls, ref msgidp);

        internal override int ldap_extended_operation(SafeHandle ld, string requestoid, IntPtr requestdata, IntPtr serverctrls,
            IntPtr clientctrls, ref int msgidp) =>
            NativeMethodsWindows.ldap_extended_operation(ld, requestoid, requestdata, serverctrls, clientctrls, ref msgidp);

        internal override int ldap_rename(SafeHandle ld, string dn, string newrdn, string newparent, int deleteoldrdn, IntPtr serverctrls,
            IntPtr clientctrls, ref int msgidp)
        {
            return NativeMethodsWindows.ldap_rename(ld, dn,
                newrdn,newparent, deleteoldrdn,
                serverctrls, clientctrls, ref msgidp);
        }

        internal override int ldap_parse_extended_result(SafeHandle ldapHandle, IntPtr result, ref IntPtr oid, ref IntPtr data, byte freeIt) => 
            NativeMethodsWindows.ldap_parse_extended_result(ldapHandle, result, ref  oid, ref data,freeIt);
        private static SEC_WINNT_AUTH_IDENTITY_EX ToNative(LdapCredential ldapCredential)
        {
            var cred = new SEC_WINNT_AUTH_IDENTITY_EX
            {
                version = NativeMethodsWindows.SEC_WINNT_AUTH_IDENTITY_VERSION,
                length = Marshal.SizeOf(typeof(SEC_WINNT_AUTH_IDENTITY_EX)),
                flags = NativeMethodsWindows.SEC_WINNT_AUTH_IDENTITY_UNICODE
            };

            if (ldapCredential != null)
            {
                cred.user = string.IsNullOrEmpty(ldapCredential.UserName) ? null : ldapCredential.UserName;
                cred.userLength = ldapCredential.UserName.Length;
                cred.password = string.IsNullOrEmpty(ldapCredential.Password) ? null : ldapCredential.Password;
                cred.passwordLength = ldapCredential.Password.Length;
                cred.domain = string.IsNullOrEmpty(ldapCredential.Realm) ? null : ldapCredential.Realm;
                cred.domainLength = ldapCredential.Realm.Length;
            }

            return cred;
        }
    }
}