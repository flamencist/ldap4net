﻿using System;
using System.Runtime.InteropServices;

namespace LdapForNet.Native
{
    internal static class NativeMethodsWindows
    {
        internal const int SEC_WINNT_AUTH_IDENTITY_UNICODE = 0x2;
        internal const int SEC_WINNT_AUTH_IDENTITY_VERSION = 0x200;
        internal const string MICROSOFT_KERBEROS_NAME_W = "Kerberos";
        private const string LIB_LDAP_PATH = "Wldap32";
        internal delegate int LDAP_SASL_INTERACT_PROC(IntPtr ld, uint flags, IntPtr defaults, IntPtr interact);
        
        [DllImport(LIB_LDAP_PATH)]
        internal static extern IntPtr ldap_init(string host, int port);
        
        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_connect(SafeHandle ld,LDAP_TIMEVAL timeout);

        [DllImport(LIB_LDAP_PATH, EntryPoint = "ldap_bindW")]
        internal static extern int ldap_bind(SafeHandle ld, string who,  SEC_WINNT_AUTH_IDENTITY_EX credentials, BindMethod method, ref int msgidp); 
        
        [DllImport(LIB_LDAP_PATH, EntryPoint = "ldap_bind_sW")]
        internal static extern int ldap_bind_s(SafeHandle ld, string who,  SEC_WINNT_AUTH_IDENTITY_EX credentials, BindMethod method);
        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_simple_bind_s(SafeHandle ld, string who, string cred);
        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_simple_bind(SafeHandle ld, string who, string cred);


        /// <summary>
        /// ldap_sasl_bind <a href="https://linux.die.net/man/3/ldap_sasl_bind">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="dn">const char           *dn</param>
        /// <param name="mechanism">const char           *mechanism</param>
        /// <param name="cred">const struct berval  *cred</param>
        /// <param name="serverctrls">LDAPControl         **serverctrls</param>
        /// <param name="clientctrls">LDAPControl         **clientctrls</param>
        /// <param name="msgidp">int *msgidp</param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_sasl_bind(SafeHandle ld, string dn, string mechanism,
            IntPtr cred, IntPtr serverctrls, IntPtr clientctrls, ref int msgidp);
        
        
        /// <summary>
        /// ldap_sasl_interactive_bind_s <a href="https://linux.die.net/man/3/ldap_sasl_bind_s">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="dn">const char           *dn</param>
        /// <param name="mechanism">const char           *mechanism</param>
        /// <param name="serverctrls">LDAPControl         **serverctrls</param>
        /// <param name="clientctrls">LDAPControl         **clientctrls</param>
        /// <param name="flags">unsigned flags </param>
        /// <param name="proc">delegate</param>
        /// <param name="defaults">void *defaults</param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_sasl_interactive_bind_s(SafeHandle ld, string dn, string mechanism,
            IntPtr serverctrls, IntPtr clientctrls, uint flags,
            [MarshalAs(UnmanagedType.FunctionPtr)] LDAP_SASL_INTERACT_PROC proc, IntPtr defaults);

        /// <summary>
        /// ldap_sasl_interactive_bind_s <a href="https://linux.die.net/man/3/ldap_sasl_bind_s">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="dn">const char           *dn</param>
        /// <param name="mechanism">const char           *mechanism</param>
        /// <param name="serverctrls">LDAPControl         **serverctrls</param>
        /// <param name="clientctrls">LDAPControl         **clientctrls</param>
        /// <param name="flags">unsigned flags </param>
        /// <param name="proc">delegate</param>
        /// <param name="defaults">void *defaults</param>
        /// <param name="result">LDAPMessage* result</param>
        /// <param name="rmech"></param>
        /// <param name="msgid"></param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_sasl_interactive_bind(SafeHandle ld, string dn, string mechanism,
            IntPtr serverctrls, IntPtr clientctrls, uint flags,
            [MarshalAs(UnmanagedType.FunctionPtr)] LDAP_SASL_INTERACT_PROC proc, IntPtr defaults, IntPtr result, ref IntPtr rmech, ref int msgid);
        

        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_set_option(SafeHandle ld, int option, [In] ref int invalue);

        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_set_option(SafeHandle ld, int option, [In] ref string invalue);

        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_set_option(SafeHandle ld, int option, IntPtr invalue);

        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_get_option(SafeHandle ld, int option, ref string value);

        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_get_option(SafeHandle ld, int option, ref IntPtr value);

        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_unbind_s(IntPtr ld);

        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_unbind(IntPtr ld);
        
        /// <summary>
        /// ldap_search_ext_s <a href="https://linux.die.net/man/3/ldap_search_ext">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="base">char *base</param>
        /// <param name="scope">int scope</param>
        /// <param name="filter">char *filter</param>
        /// <param name="attrs">char *attrs[]</param>
        /// <param name="attrsonly">int attrsonly</param>
        /// <param name="serverctrls">LDAPControl **serverctrls</param>
        /// <param name="clientctrls">LDAPControl **clientctrls</param>
        /// <param name="timeout">struct timeval *timeout</param>
        /// <param name="sizelimit">int sizelimit</param>
        /// <param name="msgidp">int *msgidp</param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_search_ext(SafeHandle ld, string @base, int scope, string filter, string[] attrs,
            int attrsonly, IntPtr serverctrls, IntPtr clientctrls, IntPtr timeout, int sizelimit, ref int msgidp);

        /// <summary>
        /// ldap_result <a href="https://linux.die.net/man/3/ldap_result">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="msgid">int msgid</param>
        /// <param name="all">int all</param>
        /// <param name="timeout">struct timeval *timeout</param>
        /// <param name="pMessage">LDAPMessage **result</param>
        /// <returns>result type </returns>
        [DllImport(LIB_LDAP_PATH)]
        internal static extern Native.LdapResultType ldap_result(SafeHandle ld, int msgid, int all, IntPtr timeout,ref IntPtr pMessage);
        
        
        
        [DllImport(LIB_LDAP_PATH)]
        private static extern uint LdapGetLastError();

        
        [DllImport(LIB_LDAP_PATH)]
        private static extern IntPtr ldap_err2string(int error);

        internal static string LdapError2String(int error)
        {
            return Marshal.PtrToStringAnsi(ldap_err2string(error));
        }


        internal static string GetAdditionalErrorInfo(SafeHandle ld)
        {
            var ptr = Marshal.AllocHGlobal(IntPtr.Size);
            //Sets or retrieves the pointer to a TCHAR string giving the error message of the most recent LDAP error that occurred for this session.
            //The error string returned by this option should not be freed by the user
            ldap_get_option(ld,(int)Native.LdapOption.LDAP_OPT_ERROR_STRING,ref ptr);
            var info = Marshal.PtrToStringAnsi(ptr);
            return info;
        }

        
        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_parse_reference(SafeHandle ld, IntPtr reference, ref string[] referralsp, ref IntPtr serverctrlsp, int freeit);
        
        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_count_entries(SafeHandle ld, IntPtr message);

        [DllImport(LIB_LDAP_PATH)]
        internal static extern IntPtr ldap_first_entry(SafeHandle ld, IntPtr message);

        [DllImport(LIB_LDAP_PATH)]
        internal static extern IntPtr ldap_next_entry(SafeHandle ld, IntPtr message);

        [DllImport(LIB_LDAP_PATH)]
        internal static extern IntPtr ldap_get_dn(SafeHandle ld, IntPtr message);

        [DllImport(LIB_LDAP_PATH)]
        internal static extern void ldap_memfree(IntPtr ptr);

        [DllImport(LIB_LDAP_PATH)]
        internal static extern void ldap_msgfree(IntPtr message);

        [DllImport(LIB_LDAP_PATH)]
        internal static extern IntPtr ldap_first_attribute(SafeHandle ld, IntPtr entry, ref IntPtr ppBer);

        [DllImport(LIB_LDAP_PATH)]
        internal static extern IntPtr ldap_next_attribute(SafeHandle ld, IntPtr entry, IntPtr pBer);

        [DllImport(LIB_LDAP_PATH)]
        internal static extern void ldap_value_free(IntPtr vals);

        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_count_values(IntPtr vals);
        
        [DllImport(LIB_LDAP_PATH)]
        internal static extern IntPtr ldap_get_values(SafeHandle ld, IntPtr entry, IntPtr pBer);
        
        /// <summary>
        /// ldap_add_ext <a href="https://linux.die.net/man/3/ldap_add">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="dn">const char *dn</param>
        /// <param name="attrs">LDAPMod **attrs</param>
        /// <param name="serverctrls">LDAPControl  **serverctrls</param>
        /// <param name="clientctrls">LDAPControl  **clientctrls</param>
        /// <param name="msgidp"></param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_add_ext(SafeHandle ld,string dn,IntPtr attrs,IntPtr serverctrls, IntPtr clientctrls,ref int msgidp );
       
        /// <summary>
        /// ldap_modify_ext <a href="https://linux.die.net/man/3/ldap_modify_s">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="dn">const char           *dn</param>
        /// <param name="mods">LDAPMod *mods[]</param>
        /// <param name="serverctrls">LDAPControl     **serverctrls</param>
        /// <param name="clientctrls">LDAPControl     **clientctrls</param>
        /// <param name="msgidp"></param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_modify_ext(SafeHandle ld, string dn,IntPtr mods , IntPtr serverctrls, IntPtr clientctrls, ref int msgidp);
        
        /// <summary>
        /// ldap_delete_ext <a href="https://linux.die.net/man/3/ldap_delete_s">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="dn">const char           *dn</param>
        /// <param name="serverctrls">LDAPControl     **serverctrls</param>
        /// <param name="clientctrls">LDAPControl     **clientctrls</param>
        /// <param name="msgidp"></param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_delete_ext(SafeHandle ld, string dn, IntPtr serverctrls, IntPtr clientctrls, ref int msgidp);

        
        /// <summary>
        /// ldap_compare_ext <a href="https://linux.die.net/man/3/ldap_compare_ext_s">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="dn">const char   *dn</param>
        /// <param name="attr">char *attr</param>
        /// <param name="bvalue">const struct berval  *bvalue</param>
        /// <param name="serverctrls">LDAPControl     **serverctrls</param>
        /// <param name="clientctrls">LDAPControl     **clientctrls</param>
        /// <param name="msgidp"></param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_compare_ext(SafeHandle ld, string dn, string attr, string value, IntPtr bvalue, IntPtr serverctrls, IntPtr clientctrls, ref int msgidp);

        
        /// <summary>
        /// ldap_rename <a href="https://linux.die.net/man/3/ldap_rename_s">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="dn">const char   *dn</param>
        /// <param name="newrdn">const char *newrdn</param>
        /// <param name="deleteoldrdn"></param>
        /// <param name="serverctrls">LDAPControl     **serverctrls</param>
        /// <param name="clientctrls">LDAPControl     **clientctrls</param>
        /// <param name="newparent"></param>
        /// <param name="msgidp"></param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH, EntryPoint = "ldap_rename_ext")]
        internal static extern int ldap_rename(SafeHandle ld, string dn, string newrdn, string newparent, int deleteoldrdn, IntPtr serverctrls, IntPtr clientctrls, ref int msgidp);
        
        
        /// <summary>
        /// ldap_is_ldap_url <a href="https://linux.die.net/man/3/ldap_is_ldap_url">Documentation</a>
        /// </summary>
        /// <param name="url">const char *url</param>
        /// <returns></returns>
        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_is_ldap_url(string url);

        /// <summary>
        /// ldap_url_parse <a href="https://linux.die.net/man/3/ldap_url_parse">Documentation</a>
        /// </summary>
        /// <param name="url">const char *url</param>
        /// <param name="ludpp">LDAPURLDesc **ludpp </param>
        /// <returns></returns>
        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_url_parse(string url, ref IntPtr ludpp);

        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_free_urldesc(string url, ref IntPtr ludpp);

        [DllImport(LIB_LDAP_PATH)]
        internal static extern void ldap_controls_free(IntPtr ctrls);
        
        [DllImport("lber")]
        internal static extern void ber_memfree(IntPtr ptr);
        
        [DllImport("lber")]
        internal static extern void ber_memvfree(IntPtr vector);

        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_parse_result([In] SafeHandle ld, [In] IntPtr result, ref int errcodep, ref IntPtr matcheddnp, ref IntPtr errmsgp, ref IntPtr referralsp,ref IntPtr serverctrlsp, int freeit);
        
        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_extended_operation(SafeHandle ld, string requestoid, IntPtr requestdata, IntPtr serverctrls, IntPtr clientctrls, ref int msgidp);
        
        [DllImport(LIB_LDAP_PATH)]
        internal static extern int ldap_parse_extended_result([In] SafeHandle ldapHandle, [In] IntPtr result, ref IntPtr oid, ref IntPtr data, int freeIt);
    }
}