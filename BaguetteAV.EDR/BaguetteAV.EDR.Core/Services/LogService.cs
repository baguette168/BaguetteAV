namespace BaguetteAV.EDR.Core.Services;

public sealed class LogService
{
    private readonly object _gate = new();
    private readonly Queue<string> _recent = new();
    private readonly int _limit;

    public LogService(string? path = null, int limit = 1000)
    {
        LogPath = path ?? Path.Combine(SettingsStore.DataDirectory, "edr.log");
        _limit = limit;
    }

    public string LogPath { get; }
    public event Action<string>? LineWritten;

    public IReadOnlyList<string> Recent
    {
        get { lock (_gate) return _recent.ToArray(); }
    }

    public void Info(string message) => Write("INFO", message);
    public void Warn(string message) => Write("WARN", message);
    public void Error(string message) => Write("ERROR", message);

    public void Ingest(string line)
    {
        if (string.IsNullOrWhiteSpace(line)) return;
        lock (_gate)
        {
            if (_recent.Contains(line)) return;
            _recent.Enqueue(line);
            while (_recent.Count > _limit) _recent.Dequeue();
        }
        try { LineWritten?.Invoke(line); } catch { }
    }

    private void Write(string level, string message)
    {
        var line = string.Concat(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), " [", level, "] ", message);
        lock (_gate)
        {
            _recent.Enqueue(line);
            while (_recent.Count > _limit) _recent.Dequeue();
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(LogPath) ?? SettingsStore.DataDirectory);
                File.AppendAllText(LogPath, line + Environment.NewLine);
            }
            catch
            {
                // Logging must never crash the protection loop.
            }
        }
        try { LineWritten?.Invoke(line); } catch { }
    }
}
