// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

using SafeWinHttpHandle = Interop.WinHttp.SafeWinHttpHandle;

#pragma warning disable CA1844 // lack of ReadAsync(Memory) override in .NET Standard 2.1 build

namespace System.Net.Http
{
    internal sealed class WinHttpResponseStream : Stream
    {
        private volatile bool _disposed;
        private readonly WinHttpRequestState _state;
        private readonly HttpResponseMessage _responseMessage;
        private SafeWinHttpHandle _requestHandle;
        private bool _readTrailingHeaders;

        internal WinHttpResponseStream(SafeWinHttpHandle requestHandle, WinHttpRequestState state, HttpResponseMessage responseMessage)
        {
            _state = state;
            _responseMessage = responseMessage;
            _requestHandle = requestHandle;
        }

        public override bool CanRead
        {
            get
            {
                return !_disposed;
            }
        }

        public override bool CanSeek
        {
            get
            {
                return false;
            }
        }

        public override bool CanWrite
        {
            get
            {
                return false;
            }
        }

        public override long Length
        {
            get
            {
                CheckDisposed();
                throw new NotSupportedException();
            }
        }

        public override long Position
        {
            get
            {
                CheckDisposed();
                throw new NotSupportedException();
            }

            set
            {
                CheckDisposed();
                throw new NotSupportedException();
            }
        }

        public override void Flush()
        {
            // Nothing to do.
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            return cancellationToken.IsCancellationRequested ?
                Task.FromCanceled(cancellationToken) :
                Task.CompletedTask;
        }

        public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
        {
            // Validate arguments as would base CopyToAsync
            StreamHelpers.ValidateCopyToArgs(this, destination, bufferSize);

            // Check that there are no other pending read operations
            if (_state.AsyncReadInProgress)
            {
                throw new InvalidOperationException(SR.net_http_no_concurrent_io_allowed);
            }

            // Early check for cancellation
            if (cancellationToken.IsCancellationRequested)
            {
                return Task.FromCanceled(cancellationToken);
            }

            // Check out a buffer and start the copy
            return CopyToAsyncCore(destination, ArrayPool<byte>.Shared.Rent(bufferSize), cancellationToken);
        }

        private async Task CopyToAsyncCore(Stream destination, byte[] buffer, CancellationToken cancellationToken)
        {
            Memory<byte> memory = new Memory<byte>(buffer);

            try
            {
                // Loop until there's no more data to be read
                while (true)
                {
                    var readTask = ReadAsyncCore(memory, cancellationToken);

                    var bytesRead = 0;

                    if (readTask.IsCompletedSuccessfully)
                    {
                        bytesRead = readTask.Result;
                    }
                    else
                    {
                        bytesRead = await readTask.ConfigureAwait(false);
                    }

                    if (bytesRead == 0)
                    {
                        break;
                    }

                    // Write that data out to the output stream
#if NETSTANDARD2_1 || NETCOREAPP
                    await destination.WriteAsync(memory.Slice(0, bytesRead), cancellationToken).ConfigureAwait(false);
#else
                    await destination.WriteAsync(buffer, 0, bytesRead, cancellationToken).ConfigureAwait(false);
#endif
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token)
        {
            if (buffer is null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }

            if (count < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(count));
            }

            if (count > buffer.Length - offset)
            {
                throw new ArgumentException(SR.net_http_buffer_insufficient_length, nameof(buffer));
            }

            return ReadAsync(buffer.AsMemory(offset, count), token).AsTask();
        }

#if NETFRAMEWORK
        public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
#else
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
#endif
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return new ValueTask<int>(Task.FromCanceled<int>(cancellationToken));
            }

            CheckDisposed();

            if (_state.AsyncReadInProgress)
            {
                throw new InvalidOperationException(SR.net_http_no_concurrent_io_allowed);
            }

            return ReadAsyncCore(buffer, cancellationToken);
        }

        public override IAsyncResult BeginRead(byte[] buffer, int offset, int count, AsyncCallback? callback, object? state) =>
            TaskToAsyncResult.Begin(ReadAsync(buffer, offset, count, CancellationToken.None), callback, state);

        public override int EndRead(IAsyncResult asyncResult) =>
            TaskToAsyncResult.End<int>(asyncResult);

        private async ValueTask<int> ReadAsyncCore(Memory<byte> buffer, CancellationToken token)
        {
            if (buffer.IsEmpty)
            {
                return 0;
            }

            var ptr = _state.PinReceiveBuffer(buffer);
            var ctr = token.Register(s => ((WinHttpResponseStream)s!).CancelPendingResponseStreamReadOperation(), this);
            _state.AsyncReadInProgress = true;

            try
            {
                if (Interop.WinHttp.IsWinHttpReadDataExAvailable)
                {
                    lock (_state.Lock)
                    {
                        var result = Interop.WinHttp.WinHttpReadDataEx(_requestHandle, ptr, (uint)buffer.Length, IntPtr.Zero, 0, 0, IntPtr.Zero);

                        if (Interop.WinHttp.ERROR_IO_PENDING != result
                            && Interop.WinHttp.ERROR_SUCCESS != result)
                        {
                            throw new IOException(SR.net_http_io_read, WinHttpException.CreateExceptionUsingError(result, nameof(Interop.WinHttp.WinHttpReadDataEx)));
                        }
                    }
                }
                else
                {
                    lock (_state.Lock)
                    {
                        Debug.Assert(!_requestHandle.IsInvalid);
                        if (!Interop.WinHttp.WinHttpQueryDataAvailable(_requestHandle, IntPtr.Zero))
                        {
                            throw new IOException(SR.net_http_io_read, WinHttpException.CreateExceptionUsingLastError(nameof(Interop.WinHttp.WinHttpQueryDataAvailable)));
                        }
                    }

                    int bytesAvailable = 0;
                    var bytesAvailableTask = _state.LifecycleAwaitable.WaitAsync(token);

                    if (bytesAvailableTask.IsCompletedSuccessfully)
                    {
                        bytesAvailable = bytesAvailableTask.Result;
                    }
                    else
                    {
                        bytesAvailable = await bytesAvailableTask.ConfigureAwait(false);
                    }

                    lock (_state.Lock)
                    {
                        Debug.Assert(!_requestHandle.IsInvalid);
                        if (!Interop.WinHttp.WinHttpReadData(
                            _requestHandle,
                            ptr,
                            (uint)Math.Min(bytesAvailable, buffer.Length),
                            IntPtr.Zero))
                        {
                            throw new IOException(SR.net_http_io_read, WinHttpException.CreateExceptionUsingLastError(nameof(Interop.WinHttp.WinHttpReadData)));
                        }
                    }
                }

                int bytesRead = 0;
                var bytesReadTask = _state.LifecycleAwaitable.WaitAsync(token);

                if (bytesReadTask.IsCompletedSuccessfully)
                {
                    bytesRead = bytesReadTask.Result;
                }
                else
                {
                    bytesRead = await bytesReadTask.ConfigureAwait(false);
                }

                if (bytesRead == 0)
                {
                    ReadResponseTrailers();
                }

                return bytesRead;
            }
            finally
            {
                _state.AsyncReadInProgress = false;
                ctr.Dispose();
            }
        }

        private void ReadResponseTrailers()
        {
            // Only load response trailers if:
            // 1. WINHTTP_QUERY_FLAG_TRAILERS is supported by the OS
            // 2. HTTP/2 or later (WINHTTP_QUERY_FLAG_TRAILERS does not work with HTTP/1.1)
            // 3. Response trailers not already loaded
            if (!WinHttpTrailersHelper.OsSupportsTrailers || _responseMessage.Version < WinHttpHandler.HttpVersion20 || _readTrailingHeaders)
            {
                return;
            }

            _readTrailingHeaders = true;

            var bufferLength = WinHttpResponseParser.GetResponseHeaderCharBufferLength(_requestHandle, isTrailingHeaders: true);

            if (bufferLength != 0)
            {
                char[] trailersBuffer = ArrayPool<char>.Shared.Rent(bufferLength);
                try
                {
                    WinHttpResponseParser.ParseResponseTrailers(_requestHandle, _responseMessage, trailersBuffer);
                }
                finally
                {
                    ArrayPool<char>.Shared.Return(trailersBuffer);
                }
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return ReadAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            CheckDisposed();
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            CheckDisposed();
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            CheckDisposed();
            throw new NotSupportedException();
        }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                _disposed = true;

                if (disposing)
                {
                    if (_requestHandle != null)
                    {
                        _requestHandle.Dispose();
                        _requestHandle = null!;
                    }
                }
            }

            base.Dispose(disposing);
        }

        private void CheckDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
        }

        // The only way to abort pending async operations in WinHTTP is to close the request handle.
        // This causes WinHTTP to cancel any pending I/O and accelerating its callbacks on the handle.
        // This causes our related TaskCompletionSource objects to move to a terminal state.
        //
        // We only want to dispose the handle if we are actually waiting for a pending WinHTTP I/O to complete,
        // meaning that we are await'ing for a Task to complete. While we could simply call dispose without
        // a pending operation, it would cause random failures in the other threads when we expect a valid handle.
        private void CancelPendingResponseStreamReadOperation()
        {
            lock (_state.Lock)
            {
                if (_state.AsyncReadInProgress)
                {
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info("before dispose");
                    _requestHandle?.Dispose(); // null check necessary to handle race condition between stream disposal and cancellation
                    if (NetEventSource.Log.IsEnabled()) NetEventSource.Info("after dispose");
                }
            }
        }
    }
}
