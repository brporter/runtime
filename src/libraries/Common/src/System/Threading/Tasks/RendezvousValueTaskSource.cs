// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks.Sources;

namespace System.Threading.Tasks
{
    internal sealed class RendezvousValueTaskSource<TResult> : IValueTaskSource<TResult>, IValueTaskSource
    {
        // Licensed to the .NET Foundation under one or more agreements.
        // The .NET Foundation licenses this file to you under the MIT license.

        private ManualResetValueTaskSourceCore<TResult> _source;
        private ExceptionDispatchInfo? _error;
        private TResult? _result;

        public bool RunContinuationsAsynchronously
        {
            get => _source.RunContinuationsAsynchronously;
            set => _source.RunContinuationsAsynchronously = value;
        }

        public short Version => _source.Version;

        public ValueTask<TResult> ValueTask => new ValueTask<TResult>(this, _source.Version);

        public TResult GetResult(short token)
        {
            _source.GetResult(token);
            _error?.Throw();
            return _result!;
        }

        public ValueTaskSourceStatus GetStatus(short token) => _source.GetStatus(token);

        public void OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags)
        {
            _source.OnCompleted(continuation, state, token, flags);
        }

        public void Reset()
        {
            _source.Reset();
            _error = null;
            _result = default;
        }

        public void SetResult(TResult result)
        {
            _result = result;
            _source.SetResult(result);
        }

        public void SetCanceled(CancellationToken token = default)
        {
            SetException(token.IsCancellationRequested ? new OperationCanceledException(token) : new OperationCanceledException());
        }

        public void SetException(Exception exception)
        {
            Debug.Assert(exception != null);
            _error = ExceptionDispatchInfo.Capture(exception);
            _source.SetException(exception);
        }

        void IValueTaskSource.GetResult(short token) => GetResult(token);
    }
}
