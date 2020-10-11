using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using static LdapForNet.Native.Native;

namespace LdapForNet
{
    public interface ILdapConnection : IDisposable
    {
	    TimeSpan Timeout { get; set; }
	    void Connect(string url, LdapVersion version = LdapVersion.LDAP_VERSION3);
        void Bind(LdapAuthType authType, LdapCredential ldapCredential);
        void Bind(string mechanism = LdapAuthMechanism.GSSAPI, string userDn = null, string password = null);
        Task BindAsync(LdapAuthType authType, LdapCredential ldapCredential);
        Task BindAsync(string mechanism = LdapAuthMechanism.GSSAPI, string userDn = null, string password = null);
        void SetOption(LdapOption option, int value, bool global = false);
        void SetOption(LdapOption option, string value, bool global = false);
        void SetOption(LdapOption option, IntPtr valuePtr, bool global = false);

        T GetOption<T>(LdapOption option);

        IList<LdapEntry> Search(string @base, string filter, string[] attributes = default,
            LdapSearchScope scope = LdapSearchScope.LDAP_SCOPE_SUBTREE);

        Task<IList<LdapEntry>> SearchAsync(string @base, string filter, string[] attributes = default,
            LdapSearchScope scope = LdapSearchScope.LDAP_SCOPE_SUBTREE, CancellationToken token = default);

        void Add(LdapEntry entry);
        Task AddAsync(LdapEntry entry, CancellationToken token = default);
        void Modify(LdapModifyEntry entry);
        Task ModifyAsync(LdapModifyEntry entry, CancellationToken token = default);
        void Delete(string dn);
        Task DeleteAsync(string dn, CancellationToken cancellationToken = default);
        void Rename(string dn, string newRdn,string newParent, bool isDeleteOldRdn);
        Task RenameAsync(string dn, string newRdn, string newParent, bool isDeleteOldRdn,
            CancellationToken cancellationToken = default);
        void Abandon(AbandonRequest abandonRequest);
        Task<DirectoryResponse> SendRequestAsync(DirectoryRequest directoryRequest, CancellationToken token = default);
        DirectoryResponse SendRequest(DirectoryRequest directoryRequest);
        void StartTransportLayerSecurity(bool trustAll = false);
        void TrustAllCertificates();
        void SetClientCertificate(X509Certificate2 certificate);
    }
}