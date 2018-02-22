using System.Runtime.InteropServices;

namespace LdapForNet.Native
{
    public static partial class Native
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct LdapSaslDefaults
        {
            public string mech;
            public string realm;
            public string authcid;
            public string passwd;
            public string authzid;
        }
    }
}