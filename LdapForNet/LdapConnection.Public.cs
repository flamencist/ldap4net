using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using LdapForNet.Utils;
using static LdapForNet.Native.Native;

namespace LdapForNet
{
    public partial class LdapConnection: ILdapConnection
    {
        public void Connect(string hostname, int port = (int)LdapPort.LDAP, LdapVersion version = LdapVersion.LDAP_VERSION3)
        {
            ThrowIfError(
                ldap_initialize(ref _ld, $"LDAP://{hostname}:{port}"),
                nameof(ldap_initialize)
            );
            var ldapVersion = (int)version;
            ThrowIfError(
                ldap_set_option(_ld, (int)LdapOption.LDAP_OPT_PROTOCOL_VERSION, ref ldapVersion),
                nameof(ldap_set_option)
            );
        }

        public void Bind(string mechanism = LdapAuthMechanism.GSSAPI, string userDn = null, string password = null)
        {
            ThrowIfNotInitialized();
            if (LdapAuthMechanism.SIMPLE.Equals(mechanism,StringComparison.OrdinalIgnoreCase))
            {
                SimpleBind(userDn,password);
            }
            else if (LdapAuthMechanism.GSSAPI.Equals(mechanism,StringComparison.OrdinalIgnoreCase))
            {
                GssApiBind();
            }
            else
            {
                throw new LdapException($"Not implemented mechanism: {mechanism}. Available: {LdapAuthMechanism.GSSAPI} | {LdapAuthMechanism.SIMPLE}. ");
            }

            _bound = true;
        }

        public void SetOption(LdapOption option, int value)
        {
            ThrowIfNotBound();
            ThrowIfError(ldap_set_option(_ld, (int)option, ref value),nameof(ldap_set_option));
        }
        
        public void SetOption(LdapOption option, string value)
        {
            ThrowIfNotBound();
            ThrowIfError(ldap_set_option(_ld, (int)option, ref value),nameof(ldap_set_option));
        }
        
        public void SetOption(LdapOption option, IntPtr valuePtr)
        {
            ThrowIfNotBound();
            ThrowIfError(ldap_set_option(_ld, (int)option, valuePtr),nameof(ldap_set_option));
        }
        
        public IList<LdapEntry> Search(string @base, string filter, LdapSearchScope scope = LdapSearchScope.LDAP_SCOPE_SUBTREE)
        {
            ThrowIfNotBound();
            var msg = Marshal.AllocHGlobal(IntPtr.Size);

            var res = ldap_search_ext_s(
                _ld, 
                @base, 
                (int)scope,
                filter,
                null,
                (int)LdapSearchAttributesOnly.False,
                IntPtr.Zero, 
                IntPtr.Zero, 
                IntPtr.Zero, 
                (int)LdapSizeLimit.LDAP_NO_LIMIT,
                ref msg);

            
            if (res != (int)LdapResultCode.LDAP_SUCCESS)
            {
                Marshal.FreeHGlobal(msg);
                ThrowIfError(_ld, res,nameof(ldap_search_ext_s));
            }

            var ber = Marshal.AllocHGlobal(IntPtr.Size);

            var ldapEntries = GetLdapEntries(_ld, msg, ber).ToList();

            Marshal.FreeHGlobal(ber);
            ldap_msgfree(msg);

            return ldapEntries;
        }

        public void Add(LdapEntry entry)
        {
            ThrowIfNotBound();
            if (string.IsNullOrWhiteSpace(entry.Dn))
            {
                throw new ArgumentNullException(nameof(entry.Dn));
            }

            if (entry.Attributes == null)
            {
                entry.Attributes = new Dictionary<string, List<string>>();
            }

            var attrs = entry.Attributes.Select(ToLdapMod).ToList();
            
            var ptr = Marshal.AllocHGlobal(IntPtr.Size*(attrs.Count+1)); // alloc memory for list with last element null
            MarshalUtils.StructureArrayToPtr(attrs,ptr, true);

            try
            {
                ThrowIfError(_ld, ldap_add_ext_s(_ld,
                    entry.Dn,
                    ptr,                
                    IntPtr.Zero, 
                    IntPtr.Zero 
                ), nameof(ldap_add_ext_s));

            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
                attrs.ForEach(_ => { Marshal.FreeHGlobal(_.mod_vals_u.modv_strvals); });
            }
        }

        public void Modify(LdapModifyEntry entry)
        {
            ThrowIfNotBound();
            
            if (string.IsNullOrWhiteSpace(entry.Dn))
            {
                throw new ArgumentNullException(nameof(entry.Dn));
            }
            
            if (entry.Attributes == null)
            {
                entry.Attributes = new List<LdapModifyAttribute>();
            }
            
            var attrs = entry.Attributes.Select(ToLdapMod).ToList();
            
            var ptr = Marshal.AllocHGlobal(IntPtr.Size*(attrs.Count+1)); // alloc memory for list with last element null
            MarshalUtils.StructureArrayToPtr(attrs,ptr, true);

            try
            {
                ThrowIfError(_ld, ldap_modify_ext_s(_ld,
                    entry.Dn,
                    ptr,                
                    IntPtr.Zero, 
                    IntPtr.Zero 
                ), nameof(ldap_modify_ext_s));

            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
                attrs.ForEach(_ => { Marshal.FreeHGlobal(_.mod_vals_u.modv_strvals); });
            }
        }

        public void Dispose()
        {
            if (_ld != IntPtr.Zero)
            {
                TraceIfError(ldap_unbind_s(_ld),nameof(ldap_unbind_s));
            }
        }

        public IntPtr GetNativeLdapPtr()
        {
            return _ld;
        }


        public void Delete(string dn)
        {
            ThrowIfNotBound();
            if (string.IsNullOrWhiteSpace(dn))
            {
                throw new ArgumentNullException(nameof(dn));
            }
            ThrowIfError(_ld, ldap_delete_ext_s(_ld,
                dn,
                IntPtr.Zero, 
                IntPtr.Zero 
            ), nameof(ldap_delete_ext_s));
        }

        public void Rename(string dn, string newRdn, string newParent, bool isDeleteOldRdn)
        {
            ThrowIfNotBound();
            if (dn == null)
            {
                throw new ArgumentNullException(nameof(dn));
            }
            ThrowIfError(_ld, ldap_rename_s(_ld,
                dn,
                newRdn,
                newParent,
                isDeleteOldRdn?1:0,
                IntPtr.Zero, 
                IntPtr.Zero 
            ), nameof(ldap_rename_s));
        }
    }
}