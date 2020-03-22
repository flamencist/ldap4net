using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using static LdapForNet.Native.Native;

namespace LdapForNet
{
    public interface ILdapConnection : IDisposable
    {
        void Connect(Uri uri, LdapVersion version = Native.Native.LdapVersion.LDAP_VERSION3);
        void Connect(string hostname, int port = (int)LdapPort.LDAP, LdapVersion version = LdapVersion.LDAP_VERSION3);
        void Bind(LdapAuthType authType, LdapCredential ldapCredential);
        void Bind(string mechanism = LdapAuthMechanism.GSSAPI, string userDn = null, string password = null);
        Task BindAsync(LdapAuthType authType, LdapCredential ldapCredential);
        Task BindAsync(string mechanism = LdapAuthMechanism.GSSAPI, string userDn = null, string password = null);
        void SetOption(LdapOption option, int value);
        void SetOption(LdapOption option, string value);
        void SetOption(LdapOption option, IntPtr valuePtr);
        IList<LdapEntry> Search(string @base, string filter, LdapSearchScope scope = LdapSearchScope.LDAP_SCOPE_SUBTREE);
        Task<IList<LdapEntry>> SearchAsync(string @base, string filter, LdapSearchScope scope = LdapSearchScope.LDAP_SCOPE_SUBTREE, CancellationToken token = default);
        void Add(LdapEntry entry);
        void Modify(LdapModifyEntry entry);
        void Delete(string dn);
        void Rename(string dn, string newRdn,string newParent, bool isDeleteOldRdn);
        Task<DirectoryResponse> SendRequestAsync(DirectoryRequest directoryRequest, CancellationToken token = default);
        DirectoryResponse SendRequest(DirectoryRequest directoryRequest);
    }
}