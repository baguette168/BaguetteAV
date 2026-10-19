using BaguetteAV.EDR.Core.Rules;

namespace BaguetteAV.EDR.Core.Policy;

public interface IEdrPlugin
{
    string Id { get; }
    string Name { get; }
    string Version { get; }
    IEnumerable<PolicyPack> GetPolicyPacks();
    IEnumerable<DetectionRule> GetRules();
}

public sealed record PluginDescriptor(string Id, string Name, string Version, string File, string Sha256, int PolicyCount, int RuleCount);

public sealed class PluginLoadResult
{
    public List<IEdrPlugin> Plugins { get; } = new();
    public List<PolicyPack> Packs { get; } = new();
    public List<DetectionRule> Rules { get; } = new();
    public List<PolicyLoadError> Errors { get; } = new();
    public List<PluginDescriptor> Descriptors { get; } = new();
}
