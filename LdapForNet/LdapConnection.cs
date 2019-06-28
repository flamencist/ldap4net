using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using LdapForNet.Utils;
using Microsoft.Win32.SafeHandles;
using static LdapForNet.Native.Native;

namespace LdapForNet
{
    public partial class LdapConnection
    {
        private SafeHandle _ld;
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
            var saslDefaults = GetSaslDefaults(_ld);
            var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(saslDefaults));
            Marshal.StructureToPtr(saslDefaults, ptr, false);

            var res = ldap_sasl_interactive_bind_s(_ld, null, LdapAuthMechanism.GSSAPI, IntPtr.Zero, IntPtr.Zero,
                (uint)LdapInteractionFlags.LDAP_SASL_QUIET, (l, flags, d, interact) => (int)LdapResultCode.LDAP_SUCCESS, ptr);

            ThrowIfError(_ld, res,nameof(ldap_sasl_interactive_bind_s), new Dictionary<string, string>
            {
                [nameof(saslDefaults)] = saslDefaults.ToString()
            });
        }

        private static LdapSaslDefaults GetSaslDefaults(SafeHandle ld)
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

        private static IEnumerable<LdapEntry> GetLdapEntries(SafeHandle ld, IntPtr msg, IntPtr ber)
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

        private static string GetLdapDn(SafeHandle ld, IntPtr entry)
        {
            var ptr = ldap_get_dn(ld, entry);
            var dn = Marshal.PtrToStringAnsi(ptr);
            ldap_memfree(ptr);
            return dn;
        }

        private static Dictionary<string, List<string>> GetLdapAttributes(SafeHandle ld, IntPtr entry, ref IntPtr ber)
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
            if (_ld == null || _ld.IsInvalid)
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

        private static void ThrowIfError(int res, string method, IDictionary<string,string> details = default)
        {
            if (res != (int)LdapResultCode.LDAP_SUCCESS)
            {
                if (details != default)
                {
                    throw new LdapException(LdapError2String(res), method, res, DetailsToString(details));
                }
                throw new LdapException(LdapError2String(res), method, res);
            }
        }

        private static string DetailsToString(IDictionary<string,string> details)
        {
            return string.Join(Environment.NewLine, details.Select(_ => $"{_.Key}:{_.Value}"));
        }

        private static void ThrowIfError(SafeHandle ld, int res, string method, IDictionary<string,string> details = default)
        {
            if (res != (int)LdapResultCode.LDAP_SUCCESS)
            {
                var error = LdapError2String(res);
                var info = GetAdditionalErrorInfo(ld);
                var message = !string.IsNullOrWhiteSpace(info)? $"{error}. {info}": error;
                if (details != default)
                {
                    throw new LdapException(message, method, res, DetailsToString(details));
                }
                throw new LdapException(message, method, res);
            }
        }

        private static void TraceIfError(int res, string method, IDictionary<string,string> details = default)
        {
            if (res != (int)LdapResultCode.LDAP_SUCCESS)
            {
                var message = $"Error {method}: {LdapError2String(res)} ({res}).";
                if (details != default)
                {
                    message += $" Details: {DetailsToString(details)}";
                }
                Trace.TraceError(message);
            }
        }
    }

    public class LdapHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public LdapHandle(IntPtr handle) : base(true)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            return ldap_unbind_s(handle) == (int) LdapResultCode.LDAP_SUCCESS;
        }
    }
}
