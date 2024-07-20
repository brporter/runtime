// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.IO;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Sources;
using SafeWinHttpHandle = Interop.WinHttp.SafeWinHttpHandle;

namespace System.Net.Http
{
    /// <summary>
    /// TODO: This was a hack, playing with ideas. Do not check this in.
    /// </summary>
    internal sealed class WinHttpAsyncWrapper
        : IValueTaskSource<bool>, IValueTaskSource<int>, IValueTaskSource<long>
    {
        // TODO: localize
        private static void ThrowIncorrectTokenException() => throw new InvalidOperationException("Incorrect Token");

        private readonly ManualResetValueTaskSourceCore<bool> _mrvtsc;
        private readonly Interop.WinHttp.WINHTTP_STATUS_CALLBACK _callbackDelegate;

        public WinHttpAsyncWrapper()
        {
            _mrvtsc = new ManualResetValueTaskSourceCore<bool> { RunContinuationsAsynchronously = true };
            _callbackDelegate = new Interop.WinHttp.WINHTTP_STATUS_CALLBACK(WinHttpCallback);
        }

        private bool BoolResult { get; set; }

        private int IntResult { get; set; }

        private long LongResult { get; set; }

        public ValueTask<bool> WinHttpSendRequestAsync(
            SafeWinHttpHandle requestHandle,
            IntPtr headers,
            uint headersLength,
            IntPtr optional,
            uint optionalLength,
            uint totalLength,
            IntPtr context)
        {
            var result = Interop.WinHttp.WinHttpSendRequest(
                requestHandle,
                headers,
                headersLength,
                optional,
                optionalLength,
                totalLength,
                context
                );

            if (result == false)
            {
                return new ValueTask<bool>(false);
            }

            return new ValueTask<bool>(this, _mrvtsc.Version);
        }

        public ValueTask<bool> WinHttpReceiveResponseAsync(
            SafeWinHttpHandle requestHandle,
            IntPtr reserved)
        {
            var result = Interop.WinHttp.WinHttpReceiveResponse(requestHandle, reserved);

            if (result == false)
            {
                return new ValueTask<bool>(false);
            }

            return new ValueTask<bool>(this, _mrvtsc.Version);
        }

        public ValueTask<int> WinHttpQueryDataAvailableAsync(
            SafeWinHttpHandle requestHandle,
            IntPtr parameterIgnoredAndShouldBeNullForAsync)
        {
            _ = Interop.WinHttp.WinHttpQueryDataAvailable(requestHandle, parameterIgnoredAndShouldBeNullForAsync);

            return new ValueTask<int>(this, _mrvtsc.Version);
        }

        public ValueTask<long> WinHttpReadDataAsync(
            SafeWinHttpHandle requestHandle,
            IntPtr buffer,
            uint bufferSize,
            IntPtr parameterIgnoredAndShouldBeNullForAsync)
        {
            _ = Interop.WinHttp.WinHttpReadData(requestHandle, buffer, bufferSize, parameterIgnoredAndShouldBeNullForAsync);

            return new ValueTask<long>(this, _mrvtsc.Version);
        }

        public ValueTask<long> WinHttpReadDataExAsync(
            SafeWinHttpHandle requestHandle,
            IntPtr buffer,
            uint bufferSize,
            IntPtr parameterIgnoredAndShouldBeNullForAsync,
            ulong ullFlags,
            uint ignored,
            IntPtr reservedAndShouldBeIntPtrZero)
        {
            _ = Interop.WinHttp.WinHttpReadDataEx(
                requestHandle,
                buffer,
                bufferSize,
                parameterIgnoredAndShouldBeNullForAsync,
                ullFlags,
                ignored,
                reservedAndShouldBeIntPtrZero);

            return new ValueTask<long>(this, _mrvtsc.Version);
        }

        public ValueTask<bool> WinHttpWriteDataAsync(
            SafeWinHttpHandle requestHandle,
            IntPtr buffer,
            uint bufferSize,
            IntPtr parameterIgnoredAndShouldBeNullForAsync)
        {
            _ = Interop.WinHttp.WinHttpWriteData(requestHandle, buffer, bufferSize, parameterIgnoredAndShouldBeNullForAsync);

            return new ValueTask<bool>(this, _mrvtsc.Version);
        }

        private void WinHttpCallback(
            IntPtr handle,
            IntPtr context,
            uint internetStatus,
            IntPtr statusInformation,
            uint statusInformationLength)
        {
            if (NetEventSource.Log.IsEnabled()) WinHttpTraceHelper.TraceCallbackStatus(null, handle, context, internetStatus);

            if (Environment.HasShutdownStarted)
            {
                if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(null, "Environment.HasShutdownStarted returned True");
                return;
            }

            if (context == IntPtr.Zero)
            {
                return;
            }

            WinHttpRequestState? state = WinHttpRequestState.FromIntPtr(context);
            Debug.Assert(state != null, "WinHttpCallback must have a non-null state object");

            RequestCallback(state, internetStatus, statusInformation, statusInformationLength);
        }

        private void RequestCallback(
            WinHttpRequestState state,
            uint internetStatus,
            IntPtr statusInformation,
            uint statusInformationLength)
        {
            try
            {
                switch (internetStatus)
                {
                    case Interop.WinHttp.WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING:
                        OnRequestHandleClosing(state);
                        return;

                    case Interop.WinHttp.WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE:
                        OnRequestSendRequestComplete(state);
                        return;

                    case Interop.WinHttp.WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE:
                        Debug.Assert(statusInformationLength == sizeof(int));
                        int bytesAvailable = Marshal.ReadInt32(statusInformation);
                        OnRequestDataAvailable(state, bytesAvailable);
                        return;

                    case Interop.WinHttp.WINHTTP_CALLBACK_STATUS_READ_COMPLETE:
                        OnRequestReadComplete(state, statusInformationLength);
                        return;

                    case Interop.WinHttp.WINHTTP_CALLBACK_STATUS_WRITE_COMPLETE:
                        OnRequestWriteComplete();
                        return;

                    case Interop.WinHttp.WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE:
                        OnRequestReceiveResponseHeadersComplete();
                        return;

                    case Interop.WinHttp.WINHTTP_CALLBACK_STATUS_REDIRECT:
                        var redirectUri = new Uri(Marshal.PtrToStringUni(statusInformation)!);
                        OnRequestRedirect(state, redirectUri);
                        return;

                    case Interop.WinHttp.WINHTTP_CALLBACK_STATUS_SENDING_REQUEST:
                        OnRequestSendingRequest(state);
                        return;

                    case Interop.WinHttp.WINHTTP_CALLBACK_STATUS_REQUEST_ERROR:
                        Debug.Assert(
                            statusInformationLength == Marshal.SizeOf<Interop.WinHttp.WINHTTP_ASYNC_RESULT>(),
                            "RequestCallback: statusInformationLength=" + statusInformationLength +
                            " must be sizeof(WINHTTP_ASYNC_RESULT)=" + Marshal.SizeOf<Interop.WinHttp.WINHTTP_ASYNC_RESULT>());

                        var asyncResult = Marshal.PtrToStructure<Interop.WinHttp.WINHTTP_ASYNC_RESULT>(statusInformation);
                        OnRequestError(state, asyncResult);
                        return;

                    default:
                        return;
                }
            }
            catch (Exception ex)
            {
                state.SavedException = ex;

                // Since we got a fatal error processing the request callback,
                // we need to close the WinHttp request handle in order to
                // abort the currently executing WinHttp async operation.
                //
                // We must always call Dispose() against the SafeWinHttpHandle
                // wrapper and never close directly the raw WinHttp handle.
                // The SafeWinHttpHandle wrapper is thread-safe and guarantees
                // calling the underlying WinHttpCloseHandle() function only once.
                state.RequestHandle?.Dispose();
            }
        }

        private static void OnRequestHandleClosing(WinHttpRequestState state)
        {
            Debug.Assert(state != null, "OnRequestSendRequestComplete: state is null");

            // This is the last notification callback that WinHTTP will send. Therefore, we can
            // now explicitly dispose the state object which will free its corresponding GCHandle.
            // This will then allow the state object to be garbage collected.
            state.Dispose();
        }

        private void OnRequestSendRequestComplete(WinHttpRequestState state)
        {
            Debug.Assert(state != null, "OnRequestSendRequestComplete: state is null");
            Debug.Assert(state.LifecycleAwaitable != null, "OnRequestSendRequestComplete: LifecycleAwaitable is null");

            _mrvtsc.SetResult(true);
        }

        private void OnRequestDataAvailable(WinHttpRequestState state, int bytesAvailable)
        {
            Debug.Assert(state != null, "OnRequestDataAvailable: state is null");

            _mrvtsc.SetResult(true);

            IntResult = bytesAvailable;
        }

        private void OnRequestReadComplete(WinHttpRequestState state, uint bytesRead)
        {
            Debug.Assert(state != null, "OnRequestReadComplete: state is null");

            // If we read to the end of the stream and we're using 'Content-Length' semantics on the response body,
            // then verify we read at least the number of bytes required.
            if (bytesRead == 0
                && state.ExpectedBytesToRead.HasValue
                && state.CurrentBytesRead < state.ExpectedBytesToRead.Value)
            {
                _mrvtsc.SetException(new IOException(SR.Format(
                    SR.net_http_io_read_incomplete,
                    state.ExpectedBytesToRead.Value,
                    state.CurrentBytesRead)));
            }
            else
            {
                _mrvtsc.SetResult(true);
                LongResult += (long)bytesRead;
            }
        }

        private void OnRequestWriteComplete()
        {
            _mrvtsc.SetResult(true);
        }

        private void OnRequestReceiveResponseHeadersComplete()
        {
            _mrvtsc.SetResult(true);
        }

        private static void OnRequestRedirect(WinHttpRequestState state, Uri redirectUri)
        {
            Debug.Assert(state != null, "OnRequestRedirect: state is null");
            Debug.Assert(state.Handler != null, "OnRequestRedirect: state.Handler is null");
            Debug.Assert(state.RequestMessage != null, "OnRequestRedirect: state.RequestMessage is null");
            Debug.Assert(redirectUri != null, "OnRequestRedirect: redirectUri is null");

            // If we're manually handling cookies, we need to reset them based on the new URI.
            if (state.Handler.CookieUsePolicy == CookieUsePolicy.UseSpecifiedCookieContainer)
            {
                // Add any cookies that may have arrived with redirect response.
                WinHttpCookieContainerAdapter.AddResponseCookiesToContainer(state);

                // Reset cookie request headers based on redirectUri.
                WinHttpCookieContainerAdapter.ResetCookieRequestHeaders(state, redirectUri);
            }

            state.RequestMessage.RequestUri = redirectUri;

            // Redirection to a new uri may require a new connection through a potentially different proxy.
            // If so, we will need to respond to additional 407 proxy auth demands and re-attach any
            // proxy credentials. The ProcessResponse() method looks at the state.LastStatusCode
            // before attaching proxy credentials and marking the HTTP request to be re-submitted.
            // So we need to reset the LastStatusCode remembered. Otherwise, it will see additional 407
            // responses as an indication that proxy auth failed and won't retry the HTTP request.
            if (state.LastStatusCode == HttpStatusCode.ProxyAuthenticationRequired)
            {
                state.LastStatusCode = 0;
            }

            // For security reasons, we drop the server credential if it is a
            // NetworkCredential.  But we allow credentials in a CredentialCache
            // since they are specifically tied to URI's.
            if (!(state.ServerCredentials is CredentialCache))
            {
                state.ServerCredentials = null;
            }

            // Similarly, we need to clear any Auth headers that were added to the request manually or
            // through the default headers.
            ResetAuthRequestHeaders(state);
        }

        private static void OnRequestSendingRequest(WinHttpRequestState state)
        {
            Debug.Assert(state != null, "OnRequestSendingRequest: state is null");
            Debug.Assert(state.RequestMessage != null, "OnRequestSendingRequest: state.RequestMessage is null");
            Debug.Assert(state.RequestMessage.RequestUri != null, "OnRequestSendingRequest: state.RequestMessage.RequestUri is null");

            if (state.RequestMessage.RequestUri.Scheme != UriScheme.Https || state.RequestHandle == null)
            {
                // Not SSL/TLS or request already gone
                return;
            }

            // Grab the channel binding token (CBT) information from the request handle and put it into
            // the TransportContext object.
            state.TransportContext.SetChannelBinding(state.RequestHandle);

            if (state.ServerCertificateValidationCallback != null)
            {
                IntPtr certHandle = IntPtr.Zero;
                uint certHandleSize = (uint)IntPtr.Size;

                if (!Interop.WinHttp.WinHttpQueryOption(
                    state.RequestHandle,
                    Interop.WinHttp.WINHTTP_OPTION_SERVER_CERT_CONTEXT,
                    ref certHandle,
                    ref certHandleSize))
                {
                    int lastError = Marshal.GetLastWin32Error();
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Error(state, $"Error getting WINHTTP_OPTION_SERVER_CERT_CONTEXT, {lastError}");

                    if (lastError == Interop.WinHttp.ERROR_WINHTTP_INCORRECT_HANDLE_STATE)
                    {
                        // Not yet an SSL/TLS connection. This occurs while connecting thru a proxy where the
                        // CONNECT verb hasn't yet been processed due to the proxy requiring authentication.
                        // We need to ignore this notification. Another notification will be sent once the final
                        // connection thru the proxy is completed.
                        return;
                    }

                    throw WinHttpException.CreateExceptionUsingError(lastError, "WINHTTP_CALLBACK_STATUS_SENDING_REQUEST/WinHttpQueryOption");
                }

                // Get any additional certificates sent from the remote server during the TLS/SSL handshake.
                X509Certificate2Collection remoteCertificateStore = new X509Certificate2Collection();
                UnmanagedCertificateContext.GetRemoteCertificatesFromStoreContext(certHandle, remoteCertificateStore);

                // Create a managed wrapper around the certificate handle. Since this results in duplicating
                // the handle, we will close the original handle after creating the wrapper.
                var serverCertificate = new X509Certificate2(certHandle);
                Interop.Crypt32.CertFreeCertificateContext(certHandle);

                X509Chain? chain = null;
                SslPolicyErrors sslPolicyErrors;
                bool result = false;

                try
                {
                    WinHttpCertificateHelper.BuildChain(
                        serverCertificate,
                        remoteCertificateStore,
                        state.RequestMessage.RequestUri.Host,
                        state.CheckCertificateRevocationList,
                        out chain,
                        out sslPolicyErrors);

                    result = state.ServerCertificateValidationCallback(
                        state.RequestMessage,
                        serverCertificate,
                        chain,
                        sslPolicyErrors);
                }
                catch (Exception ex)
                {
                    throw WinHttpException.CreateExceptionUsingError(
                        (int)Interop.WinHttp.ERROR_WINHTTP_SECURE_FAILURE, "X509Chain.Build", ex);
                }
                finally
                {
                    chain?.Dispose();
                    serverCertificate.Dispose();
                }

                if (!result)
                {
                    throw WinHttpException.CreateExceptionUsingError(
                        (int)Interop.WinHttp.ERROR_WINHTTP_SECURE_FAILURE, "ServerCertificateValidationCallback");
                }
            }
        }

        private void OnRequestError(WinHttpRequestState state, Interop.WinHttp.WINHTTP_ASYNC_RESULT asyncResult)
        {
            Debug.Assert(state != null, "OnRequestError: state is null");

            if (NetEventSource.Log.IsEnabled()) WinHttpTraceHelper.TraceAsyncError(state, asyncResult);

            Exception innerException = WinHttpException.CreateExceptionUsingError(unchecked((int)asyncResult.dwError), "WINHTTP_CALLBACK_STATUS_REQUEST_ERROR");

            switch (unchecked((uint)asyncResult.dwResult.ToInt32()))
            {
                case Interop.WinHttp.API_SEND_REQUEST:
                    _mrvtsc.SetException(innerException);
                    break;

                case Interop.WinHttp.API_RECEIVE_RESPONSE:
                    if (asyncResult.dwError == Interop.WinHttp.ERROR_WINHTTP_RESEND_REQUEST)
                    {
                        state.RetryRequest = true;
                    }
                    else if (asyncResult.dwError == Interop.WinHttp.ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED)
                    {
                        // WinHttp will automatically drop any client SSL certificates that we
                        // have pre-set into the request handle including the NULL certificate
                        // (which means we have no certs to send). For security reasons, we don't
                        // allow the certificate to be re-applied. But we need to tell WinHttp
                        // explicitly that we don't have any certificate to send.
                        Debug.Assert(state.RequestHandle != null, "OnRequestError: state.RequestHandle is null");
                        WinHttpHandler.SetNoClientCertificate(state.RequestHandle);
                        state.RetryRequest = true;
                    }
                    else if (asyncResult.dwError == Interop.WinHttp.ERROR_WINHTTP_OPERATION_CANCELLED)
                    {
                        _mrvtsc.SetException(new OperationCanceledException(state.CancellationToken));
                    }
                    else
                    {
                        _mrvtsc.SetException(innerException);
                    }
                    break;

                case Interop.WinHttp.API_QUERY_DATA_AVAILABLE:
                    if (asyncResult.dwError == Interop.WinHttp.ERROR_WINHTTP_OPERATION_CANCELLED)
                    {
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Error(state, "QUERY_DATA_AVAILABLE - ERROR_WINHTTP_OPERATION_CANCELLED");
                        _mrvtsc.SetException(new OperationCanceledException(state.CancellationToken));
                    }
                    else
                    {
                        _mrvtsc.SetException(new IOException(SR.net_http_io_read, innerException));
                    }
                    break;

                case Interop.WinHttp.API_READ_DATA:
                    if (asyncResult.dwError == Interop.WinHttp.ERROR_WINHTTP_OPERATION_CANCELLED)
                    {
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Error(state, "API_READ_DATA - ERROR_WINHTTP_OPERATION_CANCELLED");
                        _mrvtsc.SetException(new OperationCanceledException(state.CancellationToken));
                    }
                    else
                    {
                        _mrvtsc.SetException(new IOException(SR.net_http_io_read, innerException));
                    }
                    break;

                case Interop.WinHttp.API_WRITE_DATA:
                    Debug.Assert(state.TcsInternalWriteDataToRequestStream != null);
                    if (asyncResult.dwError == Interop.WinHttp.ERROR_WINHTTP_OPERATION_CANCELLED)
                    {
                        if (NetEventSource.Log.IsEnabled()) NetEventSource.Error(state, "API_WRITE_DATA - ERROR_WINHTTP_OPERATION_CANCELLED");
                        _mrvtsc.SetException(new OperationCanceledException(state.CancellationToken));
                    }
                    else
                    {
                        _mrvtsc.SetException(new IOException(SR.net_http_io_write, innerException));
                    }
                    break;

                default:
                    Debug.Fail(
                        "OnRequestError: Result (" + asyncResult.dwResult + ") is not expected.",
                        "Error code: " + asyncResult.dwError + " (" + innerException.Message + ")");
                    break;
            }
        }

        private static void ResetAuthRequestHeaders(WinHttpRequestState state)
        {
            const string AuthHeaderNameWithColon = "Authorization:";
            SafeWinHttpHandle? requestHandle = state.RequestHandle;
            Debug.Assert(requestHandle != null);

            // Clear auth headers.
            if (!Interop.WinHttp.WinHttpAddRequestHeaders(
                requestHandle,
                AuthHeaderNameWithColon,
                (uint)AuthHeaderNameWithColon.Length,
                Interop.WinHttp.WINHTTP_ADDREQ_FLAG_REPLACE))
            {
                int lastError = Marshal.GetLastWin32Error();
                if (lastError != Interop.WinHttp.ERROR_WINHTTP_HEADER_NOT_FOUND)
                {
                    throw WinHttpException.CreateExceptionUsingError(lastError, "WINHTTP_CALLBACK_STATUS_REDIRECT/WinHttpAddRequestHeaders");
                }
            }
        }

        private void ReleaseForAsyncCompletion()
        {
            _mrvtsc.Reset();

            BoolResult = false;
            IntResult = 0;
            LongResult = 0;
        }

        bool IValueTaskSource<bool>.GetResult(short token)
        {
            if (token != _mrvtsc.Version)
            {
                ThrowIncorrectTokenException();
            }

            ReleaseForAsyncCompletion();

            // TODO: if async result is false, call GetLastError and throw?
            return BoolResult;
        }

        int IValueTaskSource<int>.GetResult(short token)
        {
            if (token != _mrvtsc.Version)
            {
                ThrowIncorrectTokenException();
            }

            ReleaseForAsyncCompletion();

            return IntResult;
        }

        long IValueTaskSource<long>.GetResult(short token)
        {
            if (token != _mrvtsc.Version)
            {
                ThrowIncorrectTokenException();
            }

            ReleaseForAsyncCompletion();

            return LongResult;
        }

        ValueTaskSourceStatus IValueTaskSource<bool>.GetStatus(short token)
            => _mrvtsc.GetStatus(token);

        void IValueTaskSource<bool>.OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags)
            => _mrvtsc.OnCompleted(continuation, state, token, flags);

        ValueTaskSourceStatus IValueTaskSource<int>.GetStatus(short token)
            => _mrvtsc.GetStatus(token);

        void IValueTaskSource<int>.OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags)
            => _mrvtsc.OnCompleted(continuation, state, token, flags);

        ValueTaskSourceStatus IValueTaskSource<long>.GetStatus(short token)
            => _mrvtsc.GetStatus(token);

        void IValueTaskSource<long>.OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags)
            => _mrvtsc.OnCompleted(continuation, state, token, flags);
    }
}
