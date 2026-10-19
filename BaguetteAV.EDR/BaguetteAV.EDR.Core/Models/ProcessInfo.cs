namespace BaguetteAV.EDR.Core.Models;

public sealed class ProcessInfo
{
    public int ProcessId { get; init; }
    public int ParentProcessId { get; init; }
    public string Name { get; init; } = string.Empty;
    public string ImagePath { get; init; } = string.Empty;
    public string ParentName { get; init; } = string.Empty;
    public bool IsSigned { get; init; }
    public string Signer { get; init; } = string.Empty;
    public string Sha256 { get; init; } = string.Empty;
    public bool IsUserWritable { get; init; }
    public int Score { get; set; }
    public string LastRule { get; set; } = string.Empty;
}

public sealed class ProcessContext
{
    public int ProcessId { get; init; }
    public int ParentProcessId { get; init; }
    public string Image { get; init; } = string.Empty;
    public string ImagePath { get; init; } = string.Empty;
    public string ParentImage { get; init; } = string.Empty;
    public string CommandLine { get; init; } = string.Empty;
    public string User { get; init; } = string.Empty;
    public string Sha256 { get; init; } = string.Empty;
    public bool IsSigned { get; init; }
    public string Signer { get; init; } = string.Empty;
    public bool IsUserWritable { get; init; }
    public bool FileExists { get; init; }

    public string FileName
    {
        get
        {
            var value = !string.IsNullOrWhiteSpace(ImagePath) ? ImagePath : Image;
            if (string.IsNullOrWhiteSpace(value)) return string.Empty;
            try { return Path.GetFileName(value); }
            catch { return value; }
        }
    }
}
