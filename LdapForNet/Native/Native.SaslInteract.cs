using System;
using System.Runtime.InteropServices;

namespace LdapForNet.Native
{
    /// <summary>
    /// list of client interactions with user for caller to fill in
    /// https://gist.github.com/avsej/2322061#file-sasl-h-L880
    /// </summary>
    public static partial class Native
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct SaslInteract
        {
            public uint id;
            public string challenge;
            public string promt;
            public string defresult;
            public IntPtr result;
            public ushort len;
        }

        public enum SaslCb
        {
            SASL_CB_LIST_END = 0,
            SASL_CB_GETOPT = 1,
            SASL_CB_LOG = 2,
            SASL_CB_GETPATH = 3,
            SASL_CB_VERIFYFILE = 4,
            SASL_CB_GETCONFPATH = 5,
            SASL_CB_USER = 0x4001,
            SASL_CB_AUTHNAME = 0x4002,
            SASL_CB_LANGUAGE = 0x4003,
            SASL_CB_PASS = 0x4004,
            SASL_CB_ECHOPROMPT = 0x4005,
            SASL_CB_NOECHOPROMPT = 0x4006,
            SASL_CB_CNONCE = 0x4007,
            SASL_CB_GETREALM = 0x4008,
            SASL_CB_PROXY_POLICY = 0x8001,
        }
        
    }
}