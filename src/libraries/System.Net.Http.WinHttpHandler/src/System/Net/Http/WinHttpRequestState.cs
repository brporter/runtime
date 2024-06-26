// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net.Security;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Sources;
using SafeWinHttpHandle = Interop.WinHttp.SafeWinHttpHandle;

namespace System.Net.Http
{
    internal sealed class ResettableValueTaskSource<T>
        : IValueTaskSource<T>, IValueTaskSource
    {
        private ManualResetValueTaskSourceCore<T> _waitSource;
        private CancellationTokenRegistration _waitSourceCancellation;
        private int _hasWaiter;

        public ResettableValueTaskSource()
            => Reset();

        public T GetResult(short token)
        {
            Debug.Assert(_hasWaiter == 0);
            _waitSourceCancellation.Dispose();
            _waitSourceCancellation = default;

            var result = _waitSource.GetResult(token);

            Reset();

            return result;
        }

        void IValueTaskSource.GetResult(short token)
            => GetResult(token);

        public ValueTaskSourceStatus GetStatus(short token) => _waitSource.GetStatus(token);

        public void OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags)
            => _waitSource.OnCompleted(continuation, state, token, flags);

        public void SignalWaiter(T result)
        {
            if (Interlocked.Exchange(ref _hasWaiter, 0) == 1)
            {
                _waitSource.SetResult(result);
            }
        }

        public void SignalWaiter(Exception e)
        {

            if (Interlocked.Exchange(ref _hasWaiter, 0) == 1)
            {
                _waitSource.SetException(e);
            }
        }

        public void SignalWaiter(CancellationToken token)
            => CancelWaiter(token);

        private void CancelWaiter(CancellationToken cancellationToken)
        {
            Debug.Assert(cancellationToken.IsCancellationRequested);

            if (Interlocked.Exchange(ref _hasWaiter, 0) == 1)
            {
#if NETFRAMEWORK
                _waitSource.SetException(new OperationCanceledException(cancellationToken));
#else
                _waitSource.SetException(ExceptionDispatchInfo.SetCurrentStackTrace(new OperationCanceledException(cancellationToken)));
#endif
            }
        }

        private void Reset()
        {
            if (_hasWaiter != 0)
            {
                throw new InvalidOperationException("Concurrent use is not supported");
            }

            _waitSource.Reset();
            Volatile.Write(ref _hasWaiter, 1);
        }

        public ValueTask<T> WaitAsync(CancellationToken cancellationToken)
        {
            _waitSource.RunContinuationsAsynchronously = true;

#if NETFRAMEWORK
            var callBack = (object? s) => ((ResettableValueTaskSource<T>)s!).CancelWaiter(cancellationToken);
            _waitSourceCancellation = cancellationToken.Register(callBack, this);
#else
            _waitSourceCancellation = cancellationToken.UnsafeRegister(static (s, token) => ((ResettableValueTaskSource<T>)s!).CancelWaiter(token), this);
#endif

            return new ValueTask<T>(this, _waitSource.Version);
        }
    }

    internal sealed class WinHttpRequestState : IDisposable
    {
#if DEBUG
        private static int s_dbg_allocated;
        private static int s_dbg_pin;
        private static int s_dbg_clearSendRequestState;
        private static int s_dbg_callDispose;
        private static int s_dbg_operationHandleFree;

        private IntPtr s_dbg_requestHandle;
#endif

        // A GCHandle for this operation object.
        // This is owned by the callback and will be deallocated when the sessionHandle has been closed.
        private GCHandle _operationHandle;
        private WinHttpTransportContext? _transportContext;
        private volatile bool _disposed; // To detect redundant calls.

        public WinHttpRequestState()
        {
#if DEBUG
            Interlocked.Increment(ref s_dbg_allocated);
#endif
        }

        public void Pin()
        {
            if (!_operationHandle.IsAllocated)
            {
#if DEBUG
                Interlocked.Increment(ref s_dbg_pin);
#endif
                _operationHandle = GCHandle.Alloc(this);
            }
        }

        public static WinHttpRequestState? FromIntPtr(IntPtr gcHandle)
        {
            GCHandle stateHandle = GCHandle.FromIntPtr(gcHandle);
            return (WinHttpRequestState?)stateHandle.Target;
        }

        public IntPtr ToIntPtr()
        {
            return GCHandle.ToIntPtr(_operationHandle);
        }

        // The current locking mechanism doesn't allow any two WinHttp functions executing at
        // the same time for the same handle. Enhance locking to prevent only WinHttpCloseHandle being called
        // during other API execution. E.g. using a Reader/Writer model or, even better, Interlocked functions.
        // The lock object must be used during the execution of any WinHttp function to ensure no race conditions with
        // calling WinHttpCloseHandle.
        public object Lock => this;

        public void ClearSendRequestState()
        {
#if DEBUG
            Interlocked.Increment(ref s_dbg_clearSendRequestState);
#endif
            // Since WinHttpRequestState has a self-referenced strong GCHandle, we
            // need to clear out object references to break cycles and prevent leaks.
            Tcs = null;
            TcsInternalWriteDataToRequestStream = null;
            CancellationToken = default(CancellationToken);
            RequestMessage = null;
            Handler = null;
            ServerCertificateValidationCallback = null;
            TransportContext = null;
            Proxy = null;
            ServerCredentials = null;
            DefaultProxyCredentials = null;

            if (RequestHandle != null)
            {
                RequestHandle.Dispose();
                RequestHandle = null;
            }
        }

        public TaskCompletionSource<HttpResponseMessage>? Tcs { get; set; }

        public CancellationToken CancellationToken { get; set; }

        public HttpRequestMessage? RequestMessage { get; set; }

        public WinHttpHandler? Handler { get; set; }

        private SafeWinHttpHandle? _requestHandle;
        public SafeWinHttpHandle? RequestHandle
        {
            get
            {
                return _requestHandle;
            }

            set
            {
#if DEBUG
                if (value != null)
                {
                    s_dbg_requestHandle = value.DangerousGetHandle();
                }
#endif
                _requestHandle = value;
            }
        }

        public Exception? SavedException { get; set; }

        public bool CheckCertificateRevocationList { get; set; }

        public Func<HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool>? ServerCertificateValidationCallback { get; set; }

        [AllowNull]
        public WinHttpTransportContext TransportContext
        {
            get { return _transportContext ??= new WinHttpTransportContext(); }
            set { _transportContext = value; }
        }

        public WindowsProxyUsePolicy WindowsProxyUsePolicy { get; set; }

        public IWebProxy? Proxy { get; set; }

        public ICredentials? ServerCredentials { get; set; }

        public ICredentials? DefaultProxyCredentials { get; set; }

        public bool PreAuthenticate { get; set; }

        public HttpStatusCode LastStatusCode { get; set; }

        public bool RetryRequest { get; set; }

        public ResettableValueTaskSource<int> LifecycleAwaitable { get; set; } = new();

        public TaskCompletionSource<bool>? TcsInternalWriteDataToRequestStream { get; set; }

        public bool AsyncReadInProgress { get; set; }

        // WinHttpResponseStream state.
        public long? ExpectedBytesToRead { get; set; }
        public long CurrentBytesRead { get; set; }

        private GCHandle _cachedReceivePinnedBuffer;
        private GCHandle _cachedSendPinnedBuffer;

        public void PinReceiveBuffer(byte[] buffer)
        {
            if (!_cachedReceivePinnedBuffer.IsAllocated || _cachedReceivePinnedBuffer.Target != buffer)
            {
                if (_cachedReceivePinnedBuffer.IsAllocated)
                {
                    _cachedReceivePinnedBuffer.Free();
                }

                _cachedReceivePinnedBuffer = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            }
        }

        private MemoryHandle _cachedReceiveBufferMemoryHandle;

        public unsafe nint PinReceiveBuffer(Memory<byte> buffer)
        {
            if (_cachedReceiveBufferMemoryHandle.Pointer != null)
            {
                _cachedReceiveBufferMemoryHandle.Dispose();
            }

            _cachedReceiveBufferMemoryHandle = buffer.Pin();

            return (nint)_cachedReceiveBufferMemoryHandle.Pointer;
        }

        public void PinSendBuffer(byte[] buffer)
        {
            if (!_cachedSendPinnedBuffer.IsAllocated || _cachedSendPinnedBuffer.Target != buffer)
            {
                if (_cachedSendPinnedBuffer.IsAllocated)
                {
                    _cachedSendPinnedBuffer.Free();
                }

                _cachedSendPinnedBuffer = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            }
        }

        #region IDisposable Members
        private void Dispose(bool disposing)
        {
#if DEBUG
            Interlocked.Increment(ref s_dbg_callDispose);
#endif
            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info(this, $"GCHandle=0x{ToIntPtr():X}, disposed={_disposed}, disposing={disposing}");

            // Since there is no finalizer and this class is sealed, the disposing parameter should be TRUE.
            Debug.Assert(disposing, "WinHttpRequestState.Dispose() should have disposing=TRUE");

            if (_disposed)
            {
                return;
            }

            _disposed = true;

            if (_operationHandle.IsAllocated)
            {
                // This method only gets called when the WinHTTP request handle is fully closed and thus all
                // async operations are done. So, it is safe at this point to unpin the buffers and release
                // the strong GCHandle for the pinned buffers.
                if (_cachedReceivePinnedBuffer.IsAllocated)
                {
                    _cachedReceivePinnedBuffer.Free();
                    _cachedReceivePinnedBuffer = default(GCHandle);
                }

                if (_cachedSendPinnedBuffer.IsAllocated)
                {
                    _cachedSendPinnedBuffer.Free();
                    _cachedSendPinnedBuffer = default(GCHandle);
                }
#if DEBUG
                Interlocked.Increment(ref s_dbg_operationHandleFree);
#endif
                _operationHandle.Free();
                _operationHandle = default(GCHandle);
            }
        }

        public void Dispose()
        {
            // No need to suppress finalization since the finalizer is not overridden and the class is sealed.
            Dispose(true);
        }
        #endregion
    }
}
