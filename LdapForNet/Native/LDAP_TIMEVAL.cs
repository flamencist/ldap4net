using System.Runtime.InteropServices;

namespace LdapForNet.Native
{
    [StructLayout(LayoutKind.Sequential)]
    public sealed class LDAP_TIMEVAL
    {
        public int tv_sec;
        public int tv_usec;
    }
}