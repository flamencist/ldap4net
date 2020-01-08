using System;
using System.Runtime.InteropServices;

namespace LdapForNet.Native
{
    public static partial class Native
    {
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
        [StructLayout(LayoutKind.Sequential)]
        public sealed class LDAPMod
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
            public IntPtr mod_type;

            /// <summary>
            /// A NULL-terminated array of string values for the attribute.
            /// </summary>
            public mod_vals mod_vals_u;

            public IntPtr mod_next;
            
        }

        [StructLayout(LayoutKind.Sequential)]
        public sealed class berval
        {
            public int bv_len = 0;
            public IntPtr bv_val = IntPtr.Zero;
        }
        
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal sealed class LdapControl
        {
            public IntPtr ldctl_oid = IntPtr.Zero;
            public berval ldctl_value = null;
            public bool ldctl_iscritical = false;

            public LdapControl() { }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal sealed class SafeBerval
        {
            public int bv_len = 0;
            public IntPtr bv_val = IntPtr.Zero;

            ~SafeBerval()
            {
                if (bv_val != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(bv_val);
                }
            }
            }
    }
    
    
}