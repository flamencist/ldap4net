using System.Runtime.InteropServices;

namespace LdapForNet.Native
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public sealed class SEC_WINNT_AUTH_IDENTITY_EX
    {
        public int version;
        public int length;
        public string user;
        public int userLength;
        public string domain;
        public int domainLength;
        public string password;
        public int passwordLength;
        public int flags;
        public string packageList;
        public int packageListLength;
    }
}