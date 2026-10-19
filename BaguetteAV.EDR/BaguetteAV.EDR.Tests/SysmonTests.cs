using BaguetteAV.EDR.Core.Services;

namespace BaguetteAV.EDR.Tests;

public sealed class SysmonTests
{
    [Fact]
    public void MissingChannelReportsFailureAndEnablesPollingFallback()
    {
        using var reader = new SysmonEventReader(
            string.Concat("B-EDR-Test-", Guid.NewGuid().ToString("N")));
        using var statusChanged = new ManualResetEventSlim();
        var status = string.Empty;
        reader.StatusChanged += value =>
        {
            status = value;
            statusChanged.Set();
        };

        reader.Start();

        Assert.True(statusChanged.Wait(TimeSpan.FromSeconds(3)));
        Assert.False(reader.IsRunning);
        Assert.Contains("重试", status);
    }
}
