using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using BaguetteAV.EDR.Core.Models;

namespace BaguetteAV.EDR.Core.Policy;

public static class PolicyValidator
{
    public const string EngineVersion = "2.0.0";
    public const int MaxPolicyBytes = 2 * 1024 * 1024;
    public const int MaxRules = 512;
    public const int MaxConditionDepth = 10;
    public const int MaxConditionNodes = 256;

    private static readonly Regex IdPattern = new("^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$", RegexOptions.CultureInvariant);
    private static readonly Regex VersionPattern = new("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", RegexOptions.CultureInvariant);
    private static readonly HashSet<string> Operators = new(StringComparer.OrdinalIgnoreCase)
    {
        "eq", "equals", "ne", "notequals", "contains", "notcontains", "startswith", "endswith",
        "regex", "in", "notin", "gt", "gte", "lt", "lte", "exists", "missing"
    };
    private static readonly HashSet<string> Kinds = new(Enum.GetNames<TelemetryKind>(), StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> ResponseNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "inherit", "alert", "terminate", "terminate_process", "quarantine", "quarantine_file",
        "block", "block_destination", "contain"
    };

    public static PolicyValidationResult Validate(PolicyPack pack)
    {
        var result = new PolicyValidationResult();
        if (pack.SchemaVersion != 1)
            result.Error("schemaVersion", "仅支持 schemaVersion = 1");
        ValidateId(pack.Id, "id", result);
        if (string.IsNullOrWhiteSpace(pack.Name)) result.Error("name", "策略包名称不能为空");
        if (pack.Name.Length > 120) result.Error("name", "策略包名称不能超过 120 字符");
        if (!VersionPattern.IsMatch(pack.Version ?? string.Empty)) result.Error("version", "版本号格式无效");
        if (pack.Description.Length > 2000) result.Error("description", "描述不能超过 2000 字符");
        if (!Version.TryParse(pack.MinEngineVersion, out var minEngineVersion))
            result.Error("minEngineVersion", "最低引擎版本格式无效");
        else if (minEngineVersion > Version.Parse(EngineVersion))
            result.Error("minEngineVersion", string.Concat("策略要求引擎版本 ", pack.MinEngineVersion, "，当前引擎为 ", EngineVersion));
        if (pack.Rules.Count == 0) result.Error("rules", "策略包至少需要一条规则");
        if (pack.Rules.Count > MaxRules) result.Error("rules", string.Concat("规则数量不能超过 ", MaxRules));

        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < pack.Rules.Count; i++)
        {
            var rule = pack.Rules[i];
            var path = string.Concat("rules[", i, "]");
            ValidateId(rule.Id, string.Concat(path, ".id"), result);
            if (!ids.Add(rule.Id)) result.Error(string.Concat(path, ".id"), "规则 ID 在同一策略包内重复");
            if (string.IsNullOrWhiteSpace(rule.Name)) result.Error(string.Concat(path, ".name"), "规则名称不能为空");
            if (rule.Score is < 1 or > 100) result.Error(string.Concat(path, ".score"), "score 必须在 1..100 之间");
            if (!Enum.TryParse<Severity>(rule.Severity, true, out _)) result.Error(string.Concat(path, ".severity"), "severity 必须是 Low/Medium/High/Critical");
            if (!ResponseNames.Contains(rule.Response ?? string.Empty))
                result.Error(string.Concat(path, ".response"), "response 必须是 inherit/alert/terminate/quarantine/block_destination/contain");
            if (rule.EventKinds.Count == 0) result.Warn(string.Concat(path, ".eventKinds"), "未限制事件类型，规则会评估所有遥测事件");
            foreach (var kind in rule.EventKinds)
                if (!Kinds.Contains(kind)) result.Error(string.Concat(path, ".eventKinds"), string.Concat("未知事件类型：", kind));
            if (rule.Mitre.Length > 200) result.Error(string.Concat(path, ".mitre"), "MITRE 字段过长");
            if (rule.Description.Length > 2000) result.Error(string.Concat(path, ".description"), "描述不能超过 2000 字符");

            var nodes = 0;
            ValidateCondition(rule.Condition, string.Concat(path, ".condition"), result, 1, ref nodes);
        }

        return result;
    }

    public static PolicyValidationResult ValidateJson(string json, out PolicyPack? pack)
    {
        pack = null;
        var result = new PolicyValidationResult();
        if (System.Text.Encoding.UTF8.GetByteCount(json) > MaxPolicyBytes)
        {
            result.Error("policy", "策略文件超过 2 MB 限制");
            return result;
        }

        try
        {
            pack = JsonSerializer.Deserialize<PolicyPack>(json, PolicyJson.Options);
            if (pack is null)
            {
                result.Error("policy", "策略文件为空或格式无效");
                return result;
            }
            var validation = Validate(pack);
            result.Issues.AddRange(validation.Issues);
            return result;
        }
        catch (JsonException ex)
        {
            result.Error("json", string.Concat("JSON 解析失败：", ex.Message));
            return result;
        }
    }

    private static void ValidateCondition(PolicyCondition? condition, string path, PolicyValidationResult result, int depth, ref int nodes)
    {
        if (condition is null)
        {
            result.Error(path, "条件不能为空");
            return;
        }
        if (depth > MaxConditionDepth)
        {
            result.Error(path, string.Concat("条件嵌套超过 ", MaxConditionDepth, " 层"));
            return;
        }
        if (++nodes > MaxConditionNodes)
        {
            result.Error(path, string.Concat("条件节点超过 ", MaxConditionNodes, " 个"));
            return;
        }

        var groups = 0;
        if (condition.All is not null) groups++;
        if (condition.Any is not null) groups++;
        if (condition.Not is not null) groups++;
        if (groups > 0)
        {
            if (groups > 1) result.Error(path, "同一层只能使用 all、any、not 中的一种");
            if (!string.IsNullOrWhiteSpace(condition.Field) || !string.IsNullOrWhiteSpace(condition.Op) || condition.Value is not null)
                result.Error(path, "组合条件不能再声明 field/op/value");
            if (condition.All is { Count: 0 }) result.Error(path, "all 不能为空数组");
            if (condition.Any is { Count: 0 }) result.Error(path, "any 不能为空数组");
            foreach (var child in condition.All ?? new List<PolicyCondition>())
                ValidateCondition(child, string.Concat(path, ".all"), result, depth + 1, ref nodes);
            foreach (var child in condition.Any ?? new List<PolicyCondition>())
                ValidateCondition(child, string.Concat(path, ".any"), result, depth + 1, ref nodes);
            if (condition.Not is not null)
                ValidateCondition(condition.Not, string.Concat(path, ".not"), result, depth + 1, ref nodes);
            return;
        }

        if (string.IsNullOrWhiteSpace(condition.Field)) result.Error(path, "叶子条件缺少 field");
        else if (!condition.Field.StartsWith("field.", StringComparison.OrdinalIgnoreCase) && !PolicyFields.KnownFields.Contains(condition.Field, StringComparer.OrdinalIgnoreCase))
            result.Error(path, string.Concat("未知字段，请使用 field.<name> 声明自定义遥测：", condition.Field));
        if (string.IsNullOrWhiteSpace(condition.Op)) result.Error(path, "叶子条件缺少 op");
        else if (!Operators.Contains(condition.Op)) result.Error(path, string.Concat("未知操作符：", condition.Op));

        var op = (condition.Op ?? string.Empty).ToLowerInvariant();
        if (op is "in" or "notin")
        {
            if (condition.Value is null || condition.Value.Value.ValueKind != JsonValueKind.Array)
                result.Error(path, "in/notIn 的 value 必须是数组");
        }
        else if (op == "regex")
        {
            if (condition.Value is null || condition.Value.Value.ValueKind != JsonValueKind.String)
                result.Error(path, "regex 的 value 必须是字符串");
            else
            {
                try { _ = new Regex(condition.Value.Value.GetString() ?? string.Empty, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)); }
                catch (ArgumentException ex) { result.Error(path, string.Concat("正则无效：", ex.Message)); }
            }
        }
        else if (op is not "exists" and not "missing")
        {
            if (condition.Value is null) result.Error(path, "条件缺少 value");
        }
    }

    private static void ValidateId(string id, string path, PolicyValidationResult result)
    {
        if (!IdPattern.IsMatch(id ?? string.Empty))
            result.Error(path, "ID 必须以字母或数字开头，仅允许字母、数字、点、下划线和短横线，长度 3..64");
    }
}

public static class PolicyJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        MaxDepth = 64,
        Converters = { new JsonStringEnumConverter() }
    };
}
