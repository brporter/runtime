// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Threading.Tasks;
using Xunit.Abstractions;
using Xunit;

#nullable enable

namespace Wasm.Build.Tests.AspNetCore;

public class SignalRClientTests : SignalRTestsBase
{
    public SignalRClientTests(ITestOutputHelper output, SharedBuildPerTestClassFixture buildContext)
        : base(output, buildContext)
    {
    }

    [ActiveIssue("https://github.com/dotnet/runtime/issues/106807")]
    [ConditionalTheory(typeof(BuildTestBase), nameof(IsWorkloadWithMultiThreadingForDefaultFramework))]
    [InlineData(Configuration.Debug, "LongPolling")]
    [InlineData(Configuration.Release, "LongPolling")]
    [InlineData(Configuration.Debug, "WebSockets")]
    [InlineData(Configuration.Release, "WebSockets")]
    public async Task SignalRPassMessageWasmBrowser(Configuration config, string transport) =>
        await SignalRPassMessage("wasmclient", config, transport);
}
