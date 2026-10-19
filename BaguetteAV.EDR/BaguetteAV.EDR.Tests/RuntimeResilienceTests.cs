using System.Reflection;
using System.Threading.Channels;
using BaguetteAV.EDR.Core.Models;
using BaguetteAV.EDR.Core.Policy;
using BaguetteAV.EDR.Core.Services;
using Xunit;

namespace BaguetteAV.EDR.Tests;

public sealed class RuntimeResilienceTests : IDisposable
{
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "b-edr-resilience-tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task WorkerLoopSurvivesThrowingStateSubscriber()
    {
        using var runtime = new EdrRuntime(new PolicyRepository(_root));
        var injectedFailures = 0;
        Action throwingSubscriber = () =>
        {
            Interlocked.Increment(ref injectedFailures);
            throw new InvalidOperationException("subscriber failure injected by test");
        };
        runtime.Start();
        try
        {
            Assert.True(runtime.IsRunning);
            runtime.StateChanged += throwingSubscriber;

            var channel = GetTelemetryChannel(runtime);
            const int events = 45;
            for (var i = 0; i < events; i++)
            {
                Assert.True(channel.Writer.TryWrite(ProcessEvent(800000 + i)));
            }

            var deadline = DateTime.UtcNow.AddSeconds(15);
            while (DateTime.UtcNow < deadline && runtime.EventCount < events)
            {
                await Task.Delay(50);
            }

            Assert.True(
                runtime.EventCount >= events,
                $"worker stalled at {runtime.EventCount} events");
            Assert.True(
                Volatile.Read(ref injectedFailures) > 0,
                "throwing subscriber was never invoked, guard was not exercised");
            Assert.True(runtime.IsRunning);
        }
        finally
        {
            runtime.StateChanged -= throwingSubscriber;
            runtime.Stop();
        }
    }

    private static Channel<TelemetryEvent> GetTelemetryChannel(EdrRuntime runtime)
    {
        var field = typeof(EdrRuntime).GetField(
            "_channel",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(field);
        var channel = field!.GetValue(runtime) as Channel<TelemetryEvent>;
        Assert.NotNull(channel);
        return channel!;
    }

    private static TelemetryEvent ProcessEvent(int processId) => new()
    {
        Kind = TelemetryKind.ProcessCreate,
        EventId = 1,
        ProcessId = processId,
        ParentProcessId = 4,
        Image = @"C:\Windows\System32\notepad.exe",
        ParentImage = @"C:\Windows\System32\services.exe",
        CommandLine = "notepad.exe",
        User = "resilience-test",
        Source = "test"
    };

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }
}
