using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using LdapForNet.Utils;
using static LdapForNet.Native.Native;

namespace LdapForNet
{
    public partial class LdapConnection
    {
        private IntPtr _ld = IntPtr.Zero;
        private bool _bound;
        
        
        private static List<string> GetModValue(List<string> values)
        {
            var res = values??new List<string>();
            res.Add(null);
            return res;
        }
        
        private static LDAPMod ToLdapMod(KeyValuePair<string, List<string>> attribute)
        {
            return ToLdapMod(new LdapModifyAttribute
            {
                Type = attribute.Key,
                LdapModOperation = LdapModOperation.LDAP_MOD_ADD,
                Values = attribute.Value
            });
        }
        
        private static LDAPMod ToLdapMod(LdapModifyAttribute attribute)
        {
            var modValue = GetModValue(attribute.Values);
            var modValuePtr = Marshal.AllocHGlobal(IntPtr.Size * (modValue.Count));
            MarshalUtils.StringArrayToPtr(modValue, modValuePtr);
            return new LDAPMod
            {
                mod_op = (int) attribute.LdapModOperation,
                mod_type = attribute.Type,
                mod_vals_u = new LDAPMod.mod_vals
                {
                    modv_strvals = modValuePtr,
                },
                mod_next = IntPtr.Zero
            };
        }
        
        private void GssApiBind()
        {
            var defaults = GetSaslDefaults(_ld);
            var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(defaults));
            Marshal.StructureToPtr(defaults, ptr, false);

            var res = ldap_sasl_interactive_bind_s(_ld, null, LdapAuthMechanism.GSSAPI, IntPtr.Zero, IntPtr.Zero,
                (uint)LdapInteractionFlags.LDAP_SASL_QUIET, (l, flags, d, interact) => (int)LdapResultCode.LDAP_SUCCESS, ptr);

            ThrowIfError(_ld, res,nameof(ldap_sasl_interactive_bind_s));
        }

        private static LdapSaslDefaults GetSaslDefaults(IntPtr ld)
        {
            var defaults = new LdapSaslDefaults { mech = LdapAuthMechanism.GSSAPI };
            ThrowIfError(ldap_get_option(ld, (int)LdapOption.LDAP_OPT_X_SASL_REALM, ref defaults.realm),nameof(ldap_get_option));
            ThrowIfError(ldap_get_option(ld, (int)LdapOption.LDAP_OPT_X_SASL_AUTHCID, ref defaults.authcid),nameof(ldap_get_option));
            ThrowIfError(ldap_get_option(ld, (int)LdapOption.LDAP_OPT_X_SASL_AUTHZID, ref defaults.authzid),nameof(ldap_get_option));
            return defaults;
        }
        
        private void SimpleBind(string userDn, string password)
        {
            ThrowIfError(
                _ld,
                ldap_simple_bind_s(_ld, userDn, password)
                ,nameof(ldap_simple_bind_s)
            );
        }

        private static IEnumerable<LdapEntry> GetLdapEntries(IntPtr ld, IntPtr msg, IntPtr ber)
        {
            for (var entry = ldap_first_entry(ld, msg); entry != IntPtr.Zero;
                entry = ldap_next_entry(ld, entry))
            {
                yield return new LdapEntry
                {
                    Dn = GetLdapDn(ld, entry),
                    Attributes = GetLdapAttributes(ld, entry, ref ber)
                };
            }
        }

        private static string GetLdapDn(IntPtr ld, IntPtr entry)
        {
            var ptr = ldap_get_dn(ld, entry);
            var dn = Marshal.PtrToStringAnsi(ptr);
            ldap_memfree(ptr);
            return dn;
        }

        private static Dictionary<string, List<string>> GetLdapAttributes(IntPtr ld, IntPtr entry, ref IntPtr ber)
        {
            var dict = new Dictionary<string, List<string>>();
            for (var attr = ldap_first_attribute(ld, entry, ref ber);
                attr != IntPtr.Zero;
                attr = ldap_next_attribute(ld, entry, ber))
            {
                var vals = ldap_get_values(ld, entry, attr);
                if (vals != IntPtr.Zero)
                {
                    var attrName = Marshal.PtrToStringAnsi(attr);
                    if (attrName != null)
                    {
                        dict.Add(attrName, MarshalUtils.PtrToStringArray(vals));
                    }
                    ldap_value_free(vals);
                }

                ldap_memfree(attr);
            }

            return dict;
        }
        
        private void ThrowIfNotInitialized()
        {
            if (_ld == IntPtr.Zero)
            {
                throw new LdapException($"Not initialized connection. Please invoke {nameof(Connect)} method before.");
            }
        }

        private void ThrowIfNotBound()
        {
            ThrowIfNotInitialized();
            if (_bound == false)
            {
                throw new LdapException($"Not bound. Please invoke {nameof(Bind)} method before.");
            }
        }

        private static void ThrowIfError(int res, string method)
        {
            if (res != (int)LdapResultCode.LDAP_SUCCESS)
            {
                throw new LdapException(LdapError2String(res), method, res);
            }
        }

        private static void ThrowIfError(IntPtr ld, int res, string method)
        {
            if (res != (int)LdapResultCode.LDAP_SUCCESS)
            {
                var error = LdapError2String(res);
                var info = GetAdditionalErrorInfo(ld);
                var message = !string.IsNullOrWhiteSpace(info)? $"{error}. {info}": error;
                throw new LdapException(message, method, res);
            }
        }

        private static void TraceIfError(int res, string method)
        {
            if (res != (int)LdapResultCode.LDAP_SUCCESS)
            {
                Trace.TraceError($"Error {method}: {LdapError2String(res)} ({res}).");
            }
        }
    }
}
