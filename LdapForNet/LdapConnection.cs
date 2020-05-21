﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using LdapForNet.Native;
using LdapForNet.RequestHandlers;
using LdapForNet.Utils;

namespace LdapForNet
{
    public class LdapConnection : ILdapConnection
    {
        private readonly LdapNative _native = LdapNative.Instance;
        private SafeHandle _ld;
        private bool _bound;

        public void Connect(string url, Native.Native.LdapVersion version = Native.Native.LdapVersion.LDAP_VERSION3)
        {
            var details = new Dictionary<string, string>
            {
                [nameof(url)] = url,
                [nameof(version)] = version.ToString()
            };
            var nativeHandle = IntPtr.Zero;

            _native.ThrowIfError(
                _native.Init(ref nativeHandle, url),
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
        }

        public void Bind(Native.Native.LdapAuthType authType, LdapCredential credential)
        {
            ThrowIfNotInitialized();
            if (authType == Native.Native.LdapAuthType.Simple)
            {
                _native.ThrowIfError(_ld, _native.BindSimple(_ld, credential.UserName, credential.Password),
                    nameof(_native.BindSimple));
            }
            else if (authType == Native.Native.LdapAuthType.Anonymous)
            {
                _native.BindSimple(_ld, null, null);
            }
            else if (authType == Native.Native.LdapAuthType.ExternalAd)
            {
                _native.LdapConnect(_ld);
            }
            else if (authType != Native.Native.LdapAuthType.Unknown)
            {
                _native.ThrowIfError(_ld, _native.BindSasl(_ld, authType, credential), nameof(_native.BindSasl));
            }
            else
            {
                throw new LdapException(
                    $"Not implemented mechanism: {authType.ToString()}. Available: {Native.Native.LdapAuthType.Simple.ToString()} | {Native.Native.LdapAuthType.GssApi}. ");
            }

            _bound = true;
        }

        public async Task BindAsync(Native.Native.LdapAuthType authType, LdapCredential ldapCredential)
        {
            ThrowIfNotInitialized();
            var result = IntPtr.Zero;
            if (authType == Native.Native.LdapAuthType.Simple)
            {
                result = await _native.BindSimpleAsync(_ld, ldapCredential.UserName, ldapCredential.Password);
            }
            else if (authType == Native.Native.LdapAuthType.Anonymous)
            {
                result = await _native.BindSimpleAsync(_ld, null, null);
            }
            else if (authType == Native.Native.LdapAuthType.ExternalAd)
            {
                _native.LdapConnect(_ld);
            }
            else if (authType != Native.Native.LdapAuthType.Unknown)
            {
                result = await _native.BindSaslAsync(_ld, authType, ldapCredential);
            }
            else
            {
                throw new LdapException(
                    $"Not implemented mechanism: {authType.ToString()}. Available: {Native.Native.LdapAuthType.Simple.ToString()} | {Native.Native.LdapAuthType.GssApi}. ");
            }

            if (result != IntPtr.Zero)
            {
                ThrowIfParseResultError(result);
            }

            _bound = true;
        }

        public void Bind(string mechanism = Native.Native.LdapAuthMechanism.Kerberos, string userDn = null,
            string password = null)
        {
            Bind(Native.Native.LdapAuthMechanism.ToAuthType(mechanism), new LdapCredential
            {
                UserName = userDn,
                Password = password
            });
        }

        public async Task BindAsync(string mechanism = Native.Native.LdapAuthMechanism.Kerberos, string userDn = null,
            string password = null)
        {
            await BindAsync(Native.Native.LdapAuthMechanism.ToAuthType(mechanism), new LdapCredential
            {
                UserName = userDn,
                Password = password
            });
        }

        public void SetOption(Native.Native.LdapOption option, int value, bool global = false)
        {
            ThrowIfNotInitialized();
            _native.ThrowIfError(_native.ldap_set_option(GetLdapHandle(global), (int) option, ref value),
                nameof(_native.ldap_set_option));
        }

        public void SetOption(Native.Native.LdapOption option, string value, bool global = false)
        {
            ThrowIfNotInitialized();
            _native.ThrowIfError(_native.ldap_set_option(GetLdapHandle(global), (int) option, value),
                nameof(_native.ldap_set_option));
        }

        public void SetOption(Native.Native.LdapOption option, IntPtr valuePtr, bool global = false)
        {
            ThrowIfNotInitialized();
            _native.ThrowIfError(_native.ldap_set_option(GetLdapHandle(global), (int) option, valuePtr),
                nameof(_native.ldap_set_option));
        }

        public T GetOption<T>(Native.Native.LdapOption option)
        {
	        ThrowIfNotInitialized();
	        ThrowIfWrongOutputType<T>();

            var type = typeof(T);
	        object output = default;
	        var rc = -1;
	        var ldapHandle = GetLdapHandle(false);

	        if (type == typeof(string))
	        {
		        string value = default;
		        rc = _native.ldap_get_option(ldapHandle, (int)option, ref value);
		        output = value;
	        }

	        if (type == typeof(int))
	        {
		        int value = default;
		        rc = _native.ldap_get_option(ldapHandle, (int)option, ref value);
                output = value;
	        }

	        if (type == typeof(IntPtr))
	        {
		        IntPtr value = default;
		        rc = _native.ldap_get_option(ldapHandle, (int)option, ref value);
                output = value;
	        }

            _native.ThrowIfError(rc, nameof(_native.ldap_get_option));
	        return (T) output;
        }

        private static void ThrowIfWrongOutputType<T>()
        {
	        var type = typeof(T);
	        if (type != typeof(string) && type != typeof(int) && type != typeof(IntPtr))
	        {
		        throw new ArgumentException(
			        $"The type {type} of return value is not valid. Valid types: {nameof(String)}, {nameof(Int32)}, {nameof(IntPtr)}");
            }
        }

        private SafeHandle GetLdapHandle(bool global) => global ? new LdapHandle(IntPtr.Zero) : _ld;

        public IList<LdapEntry> Search(string @base, string filter, string[] attributes = default,
            Native.Native.LdapSearchScope scope = Native.Native.LdapSearchScope.LDAP_SCOPE_SUBTREE)
        {
            var response = (SearchResponse) SendRequest(new SearchRequest(@base, filter, scope, attributes));
            if (response.ResultCode != Native.Native.ResultCode.Success && !response.Entries.Any())
            {
                ThrowIfResponseError(response);
            }

            return response.Entries
                .Select(_ => _.ToLdapEntry())
                .ToList();
        }

        public async Task<IList<LdapEntry>> SearchAsync(string @base, string filter, string[] attributes = default,
            Native.Native.LdapSearchScope scope = Native.Native.LdapSearchScope.LDAP_SCOPE_SUBTREE,
            CancellationToken token = default)
        {
            var response =
                (SearchResponse) await SendRequestAsync(new SearchRequest(@base, filter, scope, attributes), token);
            if (response.ResultCode != Native.Native.ResultCode.Success && !response.Entries.Any())
            {
                ThrowIfResponseError(response);
            }

            return response.Entries
                .Select(_ => _.ToLdapEntry())
                .ToList();
        }

        public void Add(LdapEntry entry) => ThrowIfResponseError(SendRequest(new AddRequest(entry)));

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

        public void StartTransportLayerSecurity(bool trustAll = false)
        {
            ThrowIfNotInitialized();
            if (trustAll)
            {
                TrustAllCertificates();
            }

            SendRequest(new TransportLayerSecurityRequest(), out _);
        }

        public void TrustAllCertificates()
        {
            _native.ThrowIfError(_native.TrustAllCertificates(_ld), nameof(_native.TrustAllCertificates));
        }

        public void SetClientCertificate(X509Certificate2 certificate)
        {
            ThrowIfNotInitialized();
            _native.ThrowIfError(_native.SetClientCertificate(_ld, certificate), nameof(_native.SetClientCertificate));
        }


        public async Task ModifyAsync(LdapModifyEntry entry, CancellationToken token = default) =>
            ThrowIfResponseError(await SendRequestAsync(new ModifyRequest(entry), token));

        public void Modify(LdapModifyEntry entry) => ThrowIfResponseError(SendRequest(new ModifyRequest(entry)));

        public void Dispose()
        {
            _native.Dispose(_ld);
            _ld?.Dispose();
        }

        [Obsolete]
        public IntPtr GetNativeLdapPtr()
        {
            return _ld.DangerousGetHandle();
        }

        public async Task DeleteAsync(string dn, CancellationToken cancellationToken = default) =>
            ThrowIfResponseError(await SendRequestAsync(new DeleteRequest(dn), cancellationToken));

        public void Delete(string dn) => ThrowIfResponseError(SendRequest(new DeleteRequest(dn)));

        public async Task RenameAsync(string dn, string newRdn, string newParent, bool isDeleteOldRdn,
            CancellationToken cancellationToken = default) =>
            ThrowIfResponseError(await SendRequestAsync(
                new ModifyDNRequest(dn, newParent, newRdn) {DeleteOldRdn = isDeleteOldRdn},
                cancellationToken));

        public void Rename(string dn, string newRdn, string newParent, bool isDeleteOldRdn) =>
            ThrowIfResponseError(
                SendRequest(new ModifyDNRequest(dn, newParent, newRdn) {DeleteOldRdn = isDeleteOldRdn}));


        public async Task AddAsync(LdapEntry entry, CancellationToken token = default) =>
            ThrowIfResponseError(await SendRequestAsync(new AddRequest(entry), token));


        private DirectoryResponse ProcessResponse(DirectoryRequest directoryRequest,
            RequestHandler requestHandler, int messageId,
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
                    var res = ParseResultError(msg, out var errorMessage, out _);
                    response.ResultCode = (Native.Native.ResultCode) res;
                    response.ErrorMessage = errorMessage;
                }
            }

            return response;
        }

        private RequestHandler SendRequest(DirectoryRequest directoryRequest, out int messageId)
        {
            var requestHandler = GetSendRequestHandler(directoryRequest);
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
                    _native.ThrowIfError(_native.LdapGetLastError(_ld), directoryRequest.GetType().Name);
                    break;
                case Native.Native.LdapResultType.LDAP_TIMEOUT:
                    throw new LdapException("Timeout exceeded", nameof(_native.ldap_result), 1);
            }
        }

        private static RequestHandler GetSendRequestHandler(DirectoryRequest request)
        {
            switch (request)
            {
                case AddRequest _:
                    return new AddRequestHandler();
                case ModifyRequest _:
                    return new ModifyRequestHandler();
                case SearchRequest _:
                    return new SearchRequestHandler();
                case DeleteRequest _:
                    return new DeleteRequestHandler();
                case ModifyDNRequest _:
                    return new ModifyDnRequestHandler();
                case CompareRequest _:
                    return new CompareRequestHandler();
                case ExtendedRequest _:
                    return new ExtendedRequestHandler();
                case TransportLayerSecurityRequest _:
                    return new TransportLayerSecurityRequestHandler();
                default:
                    throw new LdapException("Not supported operation of request: " + request?.GetType());
            }
        }

        private void ThrowIfParseResultError(IntPtr msg)
        {
            var res = ParseResultError(msg, out var errorMessage, out var matchedMessage);
            _native.ThrowIfError(_ld, res, nameof(_native.ldap_parse_result), new Dictionary<string, string>
            {
                [nameof(errorMessage)] = errorMessage,
                [nameof(matchedMessage)] = matchedMessage
            });
        }

        private int ParseResultError(IntPtr msg, out string errorMessage, out string matchedMessage)
        {
            var matchedMessagePtr = IntPtr.Zero;
            var errorMessagePtr = IntPtr.Zero;
            var res = 0;
            var referrals = IntPtr.Zero;
            var serverctrls = IntPtr.Zero;
            _native.ThrowIfError(_ld, _native.ldap_parse_result(_ld, msg, ref res, ref matchedMessagePtr,
                ref errorMessagePtr,
                ref referrals, ref serverctrls, 1), nameof(_native.ldap_parse_result));
            errorMessage = Encoder.Instance.PtrToString(errorMessagePtr);
            matchedMessage = Encoder.Instance.PtrToString(matchedMessagePtr);

            return res;
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

        private void ThrowIfResponseError(DirectoryResponse response)
        {
            _native.ThrowIfError(_ld, (int) response.ResultCode, nameof(_native.ldap_parse_result),
                new Dictionary<string, string>
                {
                    [nameof(response.ErrorMessage)] = response.ErrorMessage,
                });
        }
    }
}