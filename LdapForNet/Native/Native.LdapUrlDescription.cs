using System;
using System.Runtime.InteropServices;

namespace LdapForNet.Native
{
    public static partial class Native
    {
        //        typedef struct ldap_url_desc {
//            char *      lud_scheme;     /* URI scheme */
//            char *      lud_host;       /* LDAP host to contact */
//            int         lud_port;       /* port on host */
//            char *      lud_dn;         /* base for search */
//            char **     lud_attrs;      /* list of attributes */
//            int         lud_scope;      /* a LDAP_SCOPE_... value */
//            char *      lud_filter;     /* LDAP search filter */
//            char **     lud_exts;       /* LDAP extensions */
//            int         lud_crit_exts;  /* true if any extension is critical */
//            /* may contain additional fields for internal use */
//        } LDAPURLDesc;
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct LdapUrlDescription
        {
            public string lud_scheme;
            public string lud_host;
            public int lud_port;
            public string lud_dn;
            public IntPtr lud_attrs;
            public int lud_scope;
            public string lud_filter;
            public IntPtr lud_exts;
            public int lud_crit_exts;
        }
    }
}