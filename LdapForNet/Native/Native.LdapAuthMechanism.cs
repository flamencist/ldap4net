// ReSharper disable InconsistentNaming

using System;

namespace LdapForNet.Native
{
    public static partial class Native
    {
        public static class LdapAuthMechanism
        {
            public const string GSSAPI = "GSSAPI";
            public const string Kerberos = "GSSAPI";
            public const string SIMPLE = "SIMPLE";
            internal const string Digest = "DIGEST-MD5";
            internal const string External = "EXTERNAL";
            internal const string Anonymous = "ANONYMOUS";

            public static LdapAuthType ToAuthType(string mechanism)
            {
                if (SIMPLE.Equals(mechanism, StringComparison.OrdinalIgnoreCase))
                {
                    return LdapAuthType.Simple;
                }

                if (Kerberos.Equals(mechanism, StringComparison.OrdinalIgnoreCase))
                {
                    return LdapAuthType.Negotiate;
                }
                
                if (Digest.Equals(mechanism, StringComparison.OrdinalIgnoreCase))
                {
                    return LdapAuthType.Digest;
                }

                if (External.Equals(mechanism, StringComparison.OrdinalIgnoreCase))
                {
                    return LdapAuthType.External;
                }
                
                if (Anonymous.Equals(mechanism, StringComparison.OrdinalIgnoreCase))
                {
                    return LdapAuthType.Anonymous;
                }
                
                return LdapAuthType.Unknown;
            }

            internal static string FromAuthType(LdapAuthType authType)
            {
                switch (authType)
                {
                    case LdapAuthType.Simple:
                        return SIMPLE;
                    case LdapAuthType.Negotiate:
                        return Kerberos;
                    case LdapAuthType.GssApi:
                        return GSSAPI;
                    case LdapAuthType.Digest:
                        return Digest;
                    case LdapAuthType.External:
                    case LdapAuthType.ExternalAd:
                        return External;
                    case LdapAuthType.Anonymous:
                        return Anonymous;
                    case LdapAuthType.Unknown:
                        return string.Empty;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(authType), authType, null);
                }
            }

            internal static BindMethod ToBindMethod(LdapAuthType authType)
            {
                switch (authType)
                {
                    case LdapAuthType.Simple:
                        return BindMethod.LDAP_AUTH_SIMPLE;
                    case LdapAuthType.Anonymous:
                        return BindMethod.LDAP_AUTH_SIMPLE;
                    case LdapAuthType.Negotiate:
                        return BindMethod.LDAP_AUTH_NEGOTIATE;
                    case LdapAuthType.GssApi:
                        return BindMethod.LDAP_AUTH_NEGOTIATE;
                    case LdapAuthType.Digest:
                        return BindMethod.LDAP_AUTH_NEGOTIATE;
                    case LdapAuthType.External:
                    case LdapAuthType.ExternalAd:
                        return BindMethod.LDAP_AUTH_EXTERNAL;
                    case LdapAuthType.Unknown:
                        return BindMethod.LDAP_AUTH_OTHERKIND;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(authType), authType, null);
                }
            }
        }

        public enum LdapAuthType
        {
            Anonymous = 12,
            //Basic = 1,
            Simple = 10,
            Negotiate = 2,
            GssApi=11,
            ExternalAd = 9,
            //Ntlm = 3,
            Digest = 4,
            //Sicily = 5,
            //Dpa = 6,
            //Msn = 7,
            External = 8,
            //Kerberos = 9,
            Unknown=0
        }
    }
}