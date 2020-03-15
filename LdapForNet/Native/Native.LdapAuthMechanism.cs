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
                    case LdapAuthType.Unknown:
                        return string.Empty;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(authType), authType, null);
                }
            }
        }

        public enum LdapAuthType
        {
            //Anonymous = 12,
            //Basic = 1,
            Simple = 10,
            Negotiate = 2,
            GssApi=11,
            //Ntlm = 3,
            Digest = 4,
            //Sicily = 5,
            //Dpa = 6,
            //Msn = 7,
            //External = 8,
            //Kerberos = 9,
            Unknown=0
        }
    }
}