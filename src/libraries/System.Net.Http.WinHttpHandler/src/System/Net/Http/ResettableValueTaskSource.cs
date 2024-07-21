// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Sources;

namespace System.Net.Http
{
    internal sealed class ResettableValueTaskSource<T>
        : IValueTaskSource<T>, IValueTaskSource
    {
        private ManualResetValueTaskSourceCore<T> _waitSource;
        private CancellationTokenRegistration _waitSourceCancellation;
        private int _hasWaiter;

        public ResettableValueTaskSource()
        {
            _waitSource = new() {  RunContinuationsAsynchronously = true };
            Reset();
        }

        public T GetResult(short token)
        {
            if (token != _waitSource.Version)
            {
                ThrowIncorrectTokenException();
            }

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

        public void SetResult(T result)
        {
            if (Interlocked.Exchange(ref _hasWaiter, 0) == 1)
            {
                _waitSource.SetResult(result);
            }
        }

        public void SetResult(Exception e)
        {
            if (Interlocked.Exchange(ref _hasWaiter, 0) == 1)
            {
                _waitSource.SetException(e);
            }
        }

        public void SetResult(CancellationToken token)
            => CancelWaiter(token);

        public ValueTask ToValueTask(CancellationToken cancellationToken)
        {
#if NETFRAMEWORK
            var callBack = (object? s) => ((ResettableValueTaskSource<T>)s!).CancelWaiter(cancellationToken);
            _waitSourceCancellation = cancellationToken.Register(callBack, this);
#else
            _waitSourceCancellation = cancellationToken.UnsafeRegister(static (s, token) => ((ResettableValueTaskSource<T>)s!).CancelWaiter(token), this);
#endif

            return new ValueTask(this, _waitSource.Version);
        }

        public ValueTask<T> ToResultValueTask(CancellationToken cancellationToken)
        {
#if NETFRAMEWORK
            var callBack = (object? s) => ((ResettableValueTaskSource<T>)s!).CancelWaiter(cancellationToken);
            _waitSourceCancellation = cancellationToken.Register(callBack, this);
#else
            _waitSourceCancellation = cancellationToken.UnsafeRegister(static (s, token) => ((ResettableValueTaskSource<T>)s!).CancelWaiter(token), this);
#endif

            return new ValueTask<T>(this, _waitSource.Version);
        }

        public void Reset()
            => Reset(force: true);

        private void Reset(bool force)
        {
            if (!force
                && _hasWaiter != 0)
            {
                throw new InvalidOperationException("Concurrent use is not supported");
            }

            _waitSource.Reset();
            Volatile.Write(ref _hasWaiter, 1);
        }

        // TODO: localize
        private static void ThrowIncorrectTokenException() => throw new InvalidOperationException("Incorrect Token");

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
    }
}
