using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using LdapForNet.Native;
using LdapForNet.Utils;
using static LdapForNet.Native.Native;

namespace LdapForNet
{
    public partial class LdapConnection: ILdapConnection
    {
        private readonly LdapNative _native = LdapNative.Instance;
        public void Connect(string hostname, int port = (int)LdapPort.LDAP, LdapVersion version = LdapVersion.LDAP_VERSION3)
        {
            var details = new Dictionary<string, string>
            {
                [nameof(hostname)]=hostname,
                [nameof(port)] = port.ToString(),
                [nameof(version)] = version.ToString()
            };
            var nativeHandle = IntPtr.Zero;
            _native.ThrowIfError(
                _native.Init(ref nativeHandle, hostname,port),
                nameof(_native.Init),
                details
            );
            _ld = new LdapHandle(nativeHandle);
            var ldapVersion = (int)version;

            _native.ThrowIfError(
                _native.ldap_set_option(_ld, (int)LdapOption.LDAP_OPT_PROTOCOL_VERSION, ref ldapVersion),
                nameof(_native.ldap_set_option),
                details
            );
        }

        public void Bind(string mechanism = LdapAuthMechanism.GSSAPI, string userDn = null, string password = null)
        {
            ThrowIfNotInitialized();
            if (LdapAuthMechanism.SIMPLE.Equals(mechanism,StringComparison.OrdinalIgnoreCase))
            {
                _native.BindSimple(_ld, userDn, password);
            }
            else if (LdapAuthMechanism.GSSAPI.Equals(mechanism,StringComparison.OrdinalIgnoreCase))
            {
                _native.BindKerberos(_ld);
            }
            else
            {
                throw new LdapException($"Not implemented mechanism: {mechanism}. Available: {LdapAuthMechanism.GSSAPI} | {LdapAuthMechanism.SIMPLE}. ");
            }

            _bound = true;
        }

        public async Task BindAsync(string mechanism = LdapAuthMechanism.GSSAPI, string userDn = null, string password = null)
        {
            ThrowIfNotInitialized();
            IntPtr result;
            if (LdapAuthMechanism.SIMPLE.Equals(mechanism,StringComparison.OrdinalIgnoreCase))
            {
                result = await _native.BindSimpleAsync(_ld, userDn, password);
            }
            else if (LdapAuthMechanism.GSSAPI.Equals(mechanism,StringComparison.OrdinalIgnoreCase))
            {
                result = await _native.BindKerberosAsync(_ld);
            }
            else
            {
                throw new LdapException($"Not implemented mechanism: {mechanism}. Available: {LdapAuthMechanism.GSSAPI} | {LdapAuthMechanism.SIMPLE}. ");
            }

            if (result != IntPtr.Zero)
            {
                ThrowIfParseResultError(result);
            }
            
            _bound = true;
        }

        public void SetOption(LdapOption option, int value)
        {
            ThrowIfNotBound();
            _native.ThrowIfError(_native.ldap_set_option(_ld, (int)option, ref value),nameof(_native.ldap_set_option));
        }
        
        public void SetOption(LdapOption option, string value)
        {
            ThrowIfNotBound();
            _native.ThrowIfError(_native.ldap_set_option(_ld, (int)option, ref value),nameof(_native.ldap_set_option));
        }
        
        public void SetOption(LdapOption option, IntPtr valuePtr)
        {
            ThrowIfNotBound();
            _native.ThrowIfError(_native.ldap_set_option(_ld, (int)option, valuePtr),nameof(_native.ldap_set_option));
        }

        public IList<LdapEntry> Search(string @base, string filter,
            LdapSearchScope scope = LdapSearchScope.LDAP_SCOPE_SUBTREE)
        {
            var response = (SearchResponse)SendRequest(new SearchRequest(@base, filter, scope));
            return response.Entries;
        }
        
        public async Task<IList<LdapEntry>> SearchAsync(string @base, string filter,
            LdapSearchScope scope = LdapSearchScope.LDAP_SCOPE_SUBTREE, CancellationToken token = default)
        {
            var response = (SearchResponse)await SendRequestAsync(new SearchRequest(@base, filter, scope), token);
            return response.Entries;
        }

        public void Add(LdapEntry entry) => SendRequest(new AddRequest(entry));

        public async Task<DirectoryResponse> SendRequestAsync(DirectoryRequest directoryRequest, CancellationToken token = default)
        {
            if (token.IsCancellationRequested)
            {
                return default;
            }

            ThrowIfNotBound();
            
            var requestHandler = SendRequest(directoryRequest, out var messageId);

            return await Task.Factory.StartNew(() => ProcessResponse(directoryRequest, requestHandler, messageId, token), token).ConfigureAwait(false);
        }

        public DirectoryResponse SendRequest(DirectoryRequest directoryRequest)
        {
            ThrowIfNotBound();
            var requestHandler = SendRequest(directoryRequest, out var messageId);
            return ProcessResponse(directoryRequest, requestHandler, messageId, CancellationToken.None);
        }

        private DirectoryResponse ProcessResponse(DirectoryRequest directoryRequest,
            IRequestHandler requestHandler, int messageId,
            CancellationToken token)
        {
            var status = LdapResultCompleteStatus.Unknown;
            var msg = Marshal.AllocHGlobal(IntPtr.Size);

            DirectoryResponse response = default;

            while (status != LdapResultCompleteStatus.Complete && !token.IsCancellationRequested)
            {
                var resType = _native.ldap_result(_ld, messageId, 0, IntPtr.Zero, ref msg);
                ThrowIfResultError(directoryRequest, resType);

                status = requestHandler.Handle(_ld, resType, msg, out response);

                if (status == LdapResultCompleteStatus.Unknown)
                {
                    throw new LdapException($"Unknown search type {resType}", nameof(_native.ldap_result), 1);
                }

                if (status == LdapResultCompleteStatus.Complete)
                {
                    ThrowIfParseResultError(msg);
                }
            }

            return response;
        }

        private IRequestHandler SendRequest(DirectoryRequest directoryRequest, out int messageId)
        {
            var operation = GetLdapOperation(directoryRequest);
            var requestHandler = GetSendRequestHandler(operation);
            messageId = 0;
            _native.ThrowIfError(_ld, requestHandler.SendRequest(_ld, directoryRequest, ref messageId), requestHandler.GetType().Name);
            return requestHandler;
        }

        private void ThrowIfResultError(DirectoryRequest directoryRequest, LdapResultType resType)
        {
            switch (resType)
            {
                case LdapResultType.LDAP_ERROR:
                    _native.ThrowIfError(1, directoryRequest.GetType().Name);
                    break;
                case LdapResultType.LDAP_TIMEOUT:
                    throw new LdapException("Timeout exceeded", nameof(_native.ldap_result), 1);
            }
        }

        private static IRequestHandler GetSendRequestHandler(LdapOperation operation)
        {
            switch (operation)
            {
                case LdapOperation.LdapAdd:
                    return new AddRequestHandler();
                case LdapOperation.LdapModify:
                    return new ModifyRequestHandler();
                case LdapOperation.LdapSearch:
                    return new SearchRequestHandler();
                case LdapOperation.LdapDelete:
                    return new DeleteRequestHandler();
                case LdapOperation.LdapModifyDn:
                    return new ModifyDnRequestHandler();
//                case LdapOperation.LdapCompare:
//                    break;
//                case LdapOperation.LdapExtendedRequest:
//                    break;
                default:
                    throw new LdapException("Not supported operation: " + operation);
            }
        }

        public async Task AddAsync(LdapEntry entry, CancellationToken token = default) => await SendRequestAsync(new AddRequest(entry), token);

        private void ThrowIfParseResultError(IntPtr msg)
        {
            var matchedMessage = string.Empty;
            var errorMessage = string.Empty;
            var res = 0;
            var referrals = IntPtr.Zero;
            var serverctrls = IntPtr.Zero;
            _native.ThrowIfError(_ld, _native.ldap_parse_result(_ld, msg, ref res, ref matchedMessage, ref errorMessage,
                ref referrals, ref serverctrls, 1), nameof(_native.ldap_parse_result));
            _native.ThrowIfError(_ld, res, nameof(_native.ldap_parse_result), new Dictionary<string, string>
            {
                [nameof(errorMessage)] = errorMessage,
                [nameof(matchedMessage)] = matchedMessage
            });
        }

        public async Task ModifyAsync(LdapModifyEntry entry, CancellationToken token = default) => await SendRequestAsync(new ModifyRequest(entry), token);

        public void Modify(LdapModifyEntry entry) => SendRequest(new ModifyRequest(entry));


        public void Dispose()
        {
            _ld?.Dispose();
        }

        public IntPtr GetNativeLdapPtr()
        {
            return _ld.DangerousGetHandle();
        }


        public async Task DeleteAsync(string dn, CancellationToken cancellationToken = default) => await SendRequestAsync(new DeleteRequest(dn), cancellationToken);
        public void Delete(string dn) => SendRequest(new DeleteRequest(dn));
        
        public async Task RenameAsync(string dn, string newRdn, string newParent, bool isDeleteOldRdn, CancellationToken cancellationToken = default) => 
            await SendRequestAsync(new ModifyDNRequest(dn,newParent,newRdn){DeleteOldRdn = isDeleteOldRdn}, cancellationToken);
        public void Rename(string dn, string newRdn, string newParent, bool isDeleteOldRdn) =>  SendRequest(new ModifyDNRequest(dn,newParent,newRdn){DeleteOldRdn = isDeleteOldRdn});

    }
}