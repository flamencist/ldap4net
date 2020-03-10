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

                return LdapAuthType.Unknown;
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
            //Digest = 4,
            //Sicily = 5,
            //Dpa = 6,
            //Msn = 7,
            //External = 8,
            //Kerberos = 9,
            Unknown=0
        }
    }
}