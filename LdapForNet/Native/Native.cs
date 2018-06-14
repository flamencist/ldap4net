using System;
using System.Runtime.InteropServices;

// ReSharper disable InconsistentNaming
namespace LdapForNet.Native
{
    public static partial class Native
    {
        private const string LIB_LDAP_PATH = "ldap";
        public delegate int LDAP_SASL_INTERACT_PROC(IntPtr ld, uint flags, IntPtr defaults, IntPtr interact);

        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_initialize(ref IntPtr ld, string uri);

        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_simple_bind_s(IntPtr ld, string who, string cred);

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
        public static extern int ldap_sasl_interactive_bind_s(IntPtr ld, string dn, string mechanism,
            IntPtr serverctrls, IntPtr clientctrls, uint flags,
            [MarshalAs(UnmanagedType.FunctionPtr)] LDAP_SASL_INTERACT_PROC proc, IntPtr defaults);

        /// <summary>
        /// ldap_sasl_bind_s <a href="https://linux.die.net/man/3/ldap_sasl_bind_s">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="dn">const char           *dn</param>
        /// <param name="mechanism">const char           *mechanism</param>
        /// <param name="cred">const struct berval  *cred</param>
        /// <param name="serverctrls">LDAPControl         **serverctrls</param>
        /// <param name="clientctrls">LDAPControl         **clientctrls</param>
        /// <param name="servercredp">struct berval       **servercredp</param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_sasl_bind_s(IntPtr ld, string dn, string mechanism,
            IntPtr cred, IntPtr serverctrls, IntPtr clientctrls, IntPtr servercredp);
       
        
        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_set_option(IntPtr ld, int option, [In] ref int invalue);

        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_set_option(IntPtr ld, int option, [In] ref string invalue);

        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_set_option(IntPtr ld, int option, IntPtr invalue);

        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_get_option(IntPtr ld, int option, ref string value);

        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_get_option(IntPtr ld, int option, ref IntPtr value);

        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_unbind_s(IntPtr ld);

        /// <summary>
        /// ldap_search_ext_s <a href="https://linux.die.net/man/3/ldap_search_ext_s">Documentation</a>
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
        /// <param name="pMessage">LDAPMessage **res</param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_search_ext_s(IntPtr ld, string @base, int scope, string filter, string[] attrs,
            int attrsonly, IntPtr serverctrls, IntPtr clientctrls, IntPtr timeout, int sizelimit, ref IntPtr pMessage);


        [DllImport(LIB_LDAP_PATH)]
        private static extern IntPtr ldap_err2string(int error);

        public static string LdapError2String(int error)
        {
            return Marshal.PtrToStringAnsi(ldap_err2string(error));
        }


        public static string GetAdditionalErrorInfo(IntPtr ld)
        {
            var ptr = Marshal.AllocHGlobal(IntPtr.Size);
            ldap_get_option(ld,(int)LdapOption.LDAP_OPT_DIAGNOSTIC_MESSAGE,ref ptr);
            var info = Marshal.PtrToStringAnsi(ptr);
            ldap_memfree(ptr);
            return info;
        }


        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_count_entries(IntPtr ld, IntPtr message);

        [DllImport(LIB_LDAP_PATH)]
        public static extern IntPtr ldap_first_entry(IntPtr ld, IntPtr message);

        [DllImport(LIB_LDAP_PATH)]
        public static extern IntPtr ldap_next_entry(IntPtr ld, IntPtr message);

        [DllImport(LIB_LDAP_PATH)]
        public static extern IntPtr ldap_get_dn(IntPtr ld, IntPtr message);

        [DllImport(LIB_LDAP_PATH)]
        public static extern void ldap_memfree(IntPtr ptr);

        [DllImport(LIB_LDAP_PATH)]
        public static extern void ldap_msgfree(IntPtr message);

        [DllImport(LIB_LDAP_PATH)]
        public static extern IntPtr ldap_first_attribute(IntPtr ld, IntPtr entry, ref IntPtr ppBer);

        [DllImport(LIB_LDAP_PATH)]
        public static extern IntPtr ldap_next_attribute(IntPtr ld, IntPtr entry, IntPtr pBer);

        [DllImport(LIB_LDAP_PATH)]
        public static extern void ldap_value_free(IntPtr vals);

        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_count_values(IntPtr vals);
        
        [DllImport(LIB_LDAP_PATH)]
        public static extern IntPtr ldap_get_values(IntPtr ld, IntPtr entry, IntPtr pBer);
        
        /// <summary>
        /// ldap_add_ext_s <a href="https://linux.die.net/man/3/ldap_add">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="dn">const char *dn</param>
        /// <param name="attrs">LDAPMod **attrs</param>
        /// <param name="serverctrls">LDAPControl  **serverctrls</param>
        /// <param name="clientctrls">LDAPControl  **clientctrls</param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_add_ext_s(IntPtr ld, string dn, IntPtr attrs , IntPtr serverctrls, IntPtr clientctrls);
        
        /// <summary>
        /// ldap_modify_ext_s <a href="https://linux.die.net/man/3/ldap_modify_s">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="dn">const char           *dn</param>
        /// <param name="mods">LDAPMod *mods[]</param>
        /// <param name="serverctrls">LDAPControl     **serverctrls</param>
        /// <param name="clientctrls">LDAPControl     **clientctrls</param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_modify_ext_s(IntPtr ld, string dn,IntPtr mods , IntPtr serverctrls, IntPtr clientctrls);
        
        /// <summary>
        /// ldap_delete_ext_s <a href="https://linux.die.net/man/3/ldap_delete_s">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="dn">const char           *dn</param>
        /// <param name="serverctrls">LDAPControl     **serverctrls</param>
        /// <param name="clientctrls">LDAPControl     **clientctrls</param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_delete_ext_s(IntPtr ld, string dn, IntPtr serverctrls, IntPtr clientctrls);

    }

    /// <summary>
    /// ldapmod <a href="https://linux.die.net/man/3/ldap_modify_ext"/>
    /// </summary>
    /*
     * typedef struct ldapmod {
        int mod_op;
        char *mod_type;
        
        union {
        
        char **modv_strvals;
        
        struct berval **modv_bvals;
        
        } mod_vals;
        
        struct ldapmod *mod_next;
        
        } LDAPMod;
        
        #define mod_values mod_vals.modv_strvals
        
        #define mod_bvalues mod_vals.modv_bvals
     */
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct LDAPMod
    {
        /// <summary>
        /// Values that you want to add, delete, or replace.
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct mod_vals
        {
            /// <summary>
            /// Pointer to a NULL terminated array of string values for the attribute.
            /// </summary>
            [FieldOffset(0)]
            public IntPtr modv_strvals;
            /// <summary>
            /// Pointer to a NULL-terminated array of berval structures for the attribute.
            /// </summary>
            [FieldOffset(0)]
            public IntPtr modv_bvals;
        }
        
        /// <summary>
        /// The operation to be performed on the attribute and the type of data specified as the attribute values.
        /// </summary>
        public int mod_op;
        /// <summary>
        /// Pointer to the attribute type that you want to add, delete, or replace.
        /// </summary>
        [MarshalAs(UnmanagedType.LPStr)]
        public string mod_type;

        /// <summary>
        /// A NULL-terminated array of string values for the attribute.
        /// </summary>
        public mod_vals mod_vals_u;
        
        public IntPtr mod_next;

    }

    public enum LDAP_MOD_OPERATION
    {
        LDAP_MOD_ADD=0x00,
        LDAP_MOD_DELETE=0x01,
        LDAP_MOD_REPLACE=0x02
    }
}