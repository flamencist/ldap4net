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

            public override string ToString() => $"{nameof(mech)}={mech}#{nameof(realm)}={realm}#{nameof(authcid)}={authcid}#{nameof(authzid)}={authzid} #has {nameof(passwd)} {!string.IsNullOrWhiteSpace(passwd)}";
            public bool IsEmpty() => string.IsNullOrEmpty(mech);
        }
    }
}