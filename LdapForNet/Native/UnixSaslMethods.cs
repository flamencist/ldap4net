using System;
using System.Runtime.InteropServices;
using LdapForNet.Utils;

namespace LdapForNet.Native
{
    internal static class UnixSaslMethods
    {
        internal static IntPtr GetSaslCredentials(LdapCredential ldapCredential, Native.LdapSaslDefaults saslDefaults)
        {
            if (!string.IsNullOrWhiteSpace(ldapCredential?.UserName))
            {
                saslDefaults.authcid = ldapCredential.UserName;
            }

            if (!string.IsNullOrWhiteSpace(ldapCredential?.Password))
            {
                saslDefaults.passwd = ldapCredential.Password;
            }

            if (!string.IsNullOrWhiteSpace(ldapCredential?.AuthorizationId))
            {
                saslDefaults.authzid = ldapCredential?.AuthorizationId;
            }

            var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(saslDefaults));
            Marshal.StructureToPtr(saslDefaults, ptr, false);
            return ptr;
        }

        internal static int SaslInteractionProcedure(IntPtr ld, uint flags, IntPtr d, IntPtr @in)
        {
            var ptr = @in;
            var interact = Marshal.PtrToStructure<Native.SaslInteract>(ptr);
            if (ld == IntPtr.Zero)
            {
                return (int) Native.ResultCode.LDAP_PARAM_ERROR;
            }

            var defaults = Marshal.PtrToStructure<Native.LdapSaslDefaults>(d);

            while (interact.id != (int) Native.SaslCb.SASL_CB_LIST_END)
            {
                var rc = SaslInteraction(flags, interact, defaults);
                if (rc != (int) Native.ResultCode.Success)
                {
                    return rc;
                }

                Marshal.StructureToPtr(interact, ptr, false);
                ptr = IntPtr.Add(ptr, Marshal.SizeOf<Native.SaslInteract>());
                interact = Marshal.PtrToStructure<Native.SaslInteract>(ptr);
            }

            return (int) Native.ResultCode.Success;
        }

        private static int SaslInteraction(uint flags, Native.SaslInteract interact, Native.LdapSaslDefaults defaults)
        {
            var noecho = false;
            switch (interact.id)
            {
                case (int) Native.SaslCb.SASL_CB_GETREALM:
                    if (!defaults.IsEmpty())
                    {
                        interact.defresult = defaults.realm;
                    }

                    break;
                case (int) Native.SaslCb.SASL_CB_AUTHNAME:
                    if (!defaults.IsEmpty())
                    {
                        interact.defresult = defaults.authcid;
                    }

                    break;
                case (int) Native.SaslCb.SASL_CB_PASS:
                    if (!defaults.IsEmpty())
                    {
                        interact.defresult = defaults.passwd;
                    }

                    break;
                case (int) Native.SaslCb.SASL_CB_USER:
                    if (!defaults.IsEmpty())
                    {
                        interact.defresult = defaults.authzid;
                    }

                    break;
                case (int) Native.SaslCb.SASL_CB_NOECHOPROMPT:
                    noecho = true;
                    break;
                case (int) Native.SaslCb.SASL_CB_ECHOPROMPT:
                    break;
            }

            if (flags != (uint) Native.LdapInteractionFlags.LDAP_SASL_INTERACTIVE &&
                (interact.id == (int) Native.SaslCb.SASL_CB_USER || !string.IsNullOrEmpty(interact.defresult)))
            {
                interact.result = Encoder.Instance.StringToPtr(interact.defresult);
                interact.len = interact.defresult != null ? (uint) interact.defresult.Length : 0;
                return (int) Native.ResultCode.Success;
            }

            if (flags == (int) Native.LdapInteractionFlags.LDAP_SASL_QUIET)
            {
                return (int) Native.ResultCode.Other;
            }

            if (noecho)
            {
                interact.result = Encoder.Instance.StringToPtr(interact.prompt);
                interact.len = (ushort) interact.prompt.Length;
            }
            else
            {
                return (int) Native.ResultCode.LDAP_NOT_SUPPORTED;
            }

            if (interact.len > 0)
            {
                /*
                 * 
                 */
            }
            else
            {
                interact.result = Encoder.Instance.StringToPtr(interact.defresult);
                interact.len = interact.defresult != null ? (ushort) interact.defresult.Length : (ushort) 0;
            }

            return (int) Native.ResultCode.Success;
        }
    }
}