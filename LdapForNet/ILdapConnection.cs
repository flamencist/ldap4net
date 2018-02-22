using System;
using System.Collections.Generic;

namespace LdapForNet
{
    public interface ILdapConnection : IDisposable
    {
        void Connect(string hostname, int port = (int)Native.Native.LdapPort.LDAP, Native.Native.LdapVersion version = Native.Native.LdapVersion.LDAP_VERSION3);
        void Bind(string mechanism = Native.Native.LdapAuthMechanism.GSSAPI, string userDn = null, string password = null);
        void SetOption(Native.Native.LdapOption option, int value);
        void SetOption(Native.Native.LdapOption option, string value);
        void SetOption(Native.Native.LdapOption option, IntPtr valuePtr);
        IList<LdapEntry> Search(string @base, string filter, Native.Native.LdapSearchScope scope = Native.Native.LdapSearchScope.LDAP_SCOPE_SUBTREE);
    }
}