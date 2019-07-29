using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using LdapForNet.Native;

namespace LdapForNet
{
    public class LdapConnection:ILdapConnection
    {
        private readonly LdapNative _native = LdapNative.Instance;
        private SafeHandle _ld;
        private bool _bound;

        public void Connect(string hostname, int port = (int) Native.Native.LdapPort.LDAP,
            Native.Native.LdapVersion version = Native.Native.LdapVersion.LDAP_VERSION3)
        {
            var details = new Dictionary<string, string>
            {
                [nameof(hostname)] = hostname,
                [nameof(port)] = port.ToString(),
                [nameof(version)] = version.ToString()
            };
            var nativeHandle = IntPtr.Zero;
            _native.ThrowIfError(
                _native.Init(ref nativeHandle, hostname, port),
                nameof(_native.Init),
                details
            );
            _ld = new LdapHandle(nativeHandle);
            var ldapVersion = (int) version;

            _native.ThrowIfError(
                _native.ldap_set_option(_ld, (int) Native.Native.LdapOption.LDAP_OPT_PROTOCOL_VERSION, ref ldapVersion),
                nameof(_native.ldap_set_option),
                details
            );

//            var noLimit = (int)Native.Native.LdapSizeLimit.LDAP_NO_LIMIT;
//            _native.ThrowIfError(
//                _native.ldap_set_option(_ld, (int) Native.Native.LdapOption.LDAP_OPT_SIZELIMIT, ref noLimit),
//                nameof(_native.ldap_set_option),
//                details
//            );
        }

        public void Bind(string mechanism = Native.Native.LdapAuthMechanism.GSSAPI, string userDn = null,
            string password = null)
        {
            ThrowIfNotInitialized();
            if (Native.Native.LdapAuthMechanism.SIMPLE.Equals(mechanism, StringComparison.OrdinalIgnoreCase))
            {
                _native.ThrowIfError(_ld, _native.BindSimple(_ld, userDn, password), nameof(_native.BindSimple));
            }
            else if (Native.Native.LdapAuthMechanism.GSSAPI.Equals(mechanism, StringComparison.OrdinalIgnoreCase))
            {
                _native.ThrowIfError(_ld, _native.BindKerberos(_ld), nameof(_native.BindKerberos));
            }
            else
            {
                throw new LdapException(
                    $"Not implemented mechanism: {mechanism}. Available: {Native.Native.LdapAuthMechanism.GSSAPI} | {Native.Native.LdapAuthMechanism.SIMPLE}. ");
            }

            _bound = true;
        }

        public async Task BindAsync(string mechanism = Native.Native.LdapAuthMechanism.GSSAPI, string userDn = null,
            string password = null)
        {
            ThrowIfNotInitialized();
            IntPtr result;
            if (Native.Native.LdapAuthMechanism.SIMPLE.Equals(mechanism, StringComparison.OrdinalIgnoreCase))
            {
                result = await _native.BindSimpleAsync(_ld, userDn, password);
            }
            else if (Native.Native.LdapAuthMechanism.GSSAPI.Equals(mechanism, StringComparison.OrdinalIgnoreCase))
            {
                result = await _native.BindKerberosAsync(_ld);
            }
            else
            {
                throw new LdapException(
                    $"Not implemented mechanism: {mechanism}. Available: {Native.Native.LdapAuthMechanism.GSSAPI} | {Native.Native.LdapAuthMechanism.SIMPLE}. ");
            }

            if (result != IntPtr.Zero)
            {
                ThrowIfParseResultError(result);
            }

            _bound = true;
        }

        public void SetOption(Native.Native.LdapOption option, int value)
        {
            ThrowIfNotBound();
            _native.ThrowIfError(_native.ldap_set_option(_ld, (int) option, ref value),
                nameof(_native.ldap_set_option));
        }

        public void SetOption(Native.Native.LdapOption option, string value)
        {
            ThrowIfNotBound();
            _native.ThrowIfError(_native.ldap_set_option(_ld, (int) option, ref value),
                nameof(_native.ldap_set_option));
        }

        public void SetOption(Native.Native.LdapOption option, IntPtr valuePtr)
        {
            ThrowIfNotBound();
            _native.ThrowIfError(_native.ldap_set_option(_ld, (int) option, valuePtr), nameof(_native.ldap_set_option));
        }

        public IList<LdapEntry> Search(string @base, string filter,
            Native.Native.LdapSearchScope scope = Native.Native.LdapSearchScope.LDAP_SCOPE_SUBTREE)
        {
            var response = (SearchResponse) SendRequest(new SearchRequest(@base, filter, scope));
            return response.Entries;
        }

        public async Task<IList<LdapEntry>> SearchAsync(string @base, string filter,
            Native.Native.LdapSearchScope scope = Native.Native.LdapSearchScope.LDAP_SCOPE_SUBTREE,
            CancellationToken token = default)
        {
            var response = (SearchResponse) await SendRequestAsync(new SearchRequest(@base, filter, scope), token);
            return response.Entries;
        }

        public void Add(LdapEntry entry) => SendRequest(new AddRequest(entry));

        public async Task<DirectoryResponse> SendRequestAsync(DirectoryRequest directoryRequest,
            CancellationToken token = default)
        {
            if (token.IsCancellationRequested)
            {
                return default;
            }

            ThrowIfNotBound();

            var requestHandler = SendRequest(directoryRequest, out var messageId);

            return await Task.Factory
                .StartNew(() => ProcessResponse(directoryRequest, requestHandler, messageId, token), token)
                .ConfigureAwait(false);
        }

        public DirectoryResponse SendRequest(DirectoryRequest directoryRequest)
        {
            ThrowIfNotBound();
            var requestHandler = SendRequest(directoryRequest, out var messageId);
            return ProcessResponse(directoryRequest, requestHandler, messageId, CancellationToken.None);
        }


        public async Task ModifyAsync(LdapModifyEntry entry, CancellationToken token = default) =>
            await SendRequestAsync(new ModifyRequest(entry), token);

        public void Modify(LdapModifyEntry entry) => SendRequest(new ModifyRequest(entry));


        public void Dispose()
        {
            _ld?.Dispose();
        }

        public IntPtr GetNativeLdapPtr()
        {
            return _ld.DangerousGetHandle();
        }


        public async Task DeleteAsync(string dn, CancellationToken cancellationToken = default) =>
            await SendRequestAsync(new DeleteRequest(dn), cancellationToken);

        public void Delete(string dn) => SendRequest(new DeleteRequest(dn));

        public async Task RenameAsync(string dn, string newRdn, string newParent, bool isDeleteOldRdn,
            CancellationToken cancellationToken = default) =>
            await SendRequestAsync(new ModifyDNRequest(dn, newParent, newRdn) {DeleteOldRdn = isDeleteOldRdn},
                cancellationToken);

        public void Rename(string dn, string newRdn, string newParent, bool isDeleteOldRdn) =>
            SendRequest(new ModifyDNRequest(dn, newParent, newRdn) {DeleteOldRdn = isDeleteOldRdn});

        public async Task AddAsync(LdapEntry entry, CancellationToken token = default) =>
            await SendRequestAsync(new AddRequest(entry), token);


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
            _native.ThrowIfError(_ld, requestHandler.SendRequest(_ld, directoryRequest, ref messageId),
                requestHandler.GetType().Name);
            return requestHandler;
        }

        private void ThrowIfResultError(DirectoryRequest directoryRequest, Native.Native.LdapResultType resType)
        {
            switch (resType)
            {
                case Native.Native.LdapResultType.LDAP_ERROR:
                    _native.ThrowIfError(1, directoryRequest.GetType().Name);
                    break;
                case Native.Native.LdapResultType.LDAP_TIMEOUT:
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


        private void ThrowIfParseResultError(IntPtr msg)
        {
            var matchedMessage = IntPtr.Zero;
            var errorMessage = IntPtr.Zero;
            var res = 0;
            var referrals = IntPtr.Zero;
            var serverctrls = IntPtr.Zero;
            _native.ThrowIfError(_ld, _native.ldap_parse_result(_ld, msg, ref res, ref matchedMessage, ref errorMessage,
                ref referrals, ref serverctrls, 1), nameof(_native.ldap_parse_result));
            _native.ThrowIfError(_ld, res, nameof(_native.ldap_parse_result), new Dictionary<string, string>
            {
                [nameof(errorMessage)] = Marshal.PtrToStringAnsi(errorMessage),
                [nameof(matchedMessage)] = Marshal.PtrToStringAnsi(matchedMessage)
            });
        }


        private IEnumerable<LdapEntry> GetLdapReferences(SafeHandle ld, IntPtr msg)
        {
            string[] refs = null;
            var ctrls = IntPtr.Zero;
            var rc = _native.ldap_parse_reference(ld, msg, ref refs, ref ctrls, 0);
            _native.ThrowIfError(ld, rc, nameof(_native.ldap_parse_reference));
            if (refs != null)
            {
            }

            if (ctrls != IntPtr.Zero)
            {
                _native.ldap_controls_free(ctrls);
            }

            return default;
        }

        private void ThrowIfNotInitialized()
        {
            if (_ld == null || _ld.IsInvalid)
            {
                throw new LdapException($"Not initialized connection. Please invoke {nameof(Connect)} method before.");
            }
        }

        private void ThrowIfNotBound()
        {
            ThrowIfNotInitialized();
            if (_bound == false)
            {
                throw new LdapException($"Not bound. Please invoke {nameof(Bind)} method before.");
            }
        }

        private static LdapOperation GetLdapOperation(DirectoryRequest request)
        {
            LdapOperation operation;
            switch (request)
            {
                case DeleteRequest _:
                    operation = LdapOperation.LdapDelete;
                    break;
                case AddRequest _:
                    operation = LdapOperation.LdapAdd;
                    break;
                case ModifyRequest _:
                    operation = LdapOperation.LdapModify;
                    break;
                case SearchRequest _:
                    operation = LdapOperation.LdapSearch;
                    break;
                case ModifyDNRequest _:
                    operation = LdapOperation.LdapModifyDn;
                    break;
                default:
                    throw new LdapException($"Unknown ldap operation for {request.GetType()}");
            }

            return operation;
        }
    }
}