using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using BaguetteAV.EDR.Core.Models;

namespace BaguetteAV.EDR.Core.Policy;

public static class PolicyConditionEvaluator
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);

    public static bool Evaluate(PolicyCondition condition, TelemetryEvent e, ProcessContext ctx, out string detail)
    {
        if (!TryEvaluate(condition, e, ctx, out detail, out var error))
            throw new InvalidOperationException(error);
        return true;
    }

    public static bool Matches(PolicyCondition condition, TelemetryEvent e, ProcessContext ctx, out string detail)
    {
        if (TryEvaluate(condition, e, ctx, out detail, out _)) return true;
        return false;
    }

    private static bool TryEvaluate(PolicyCondition condition, TelemetryEvent e, ProcessContext ctx, out string detail, out string error)
    {
        detail = string.Empty;
        error = string.Empty;

        if (condition.All is { Count: > 0 })
        {
            var parts = new List<string>();
            foreach (var child in condition.All)
            {
                if (!TryEvaluate(child, e, ctx, out var childDetail, out error)) return false;
                if (!string.IsNullOrWhiteSpace(childDetail)) parts.Add(childDetail);
            }
            detail = string.Join(" 且 ", parts);
            return true;
        }

        if (condition.Any is { Count: > 0 })
        {
            foreach (var child in condition.Any)
            {
                if (TryEvaluate(child, e, ctx, out var childDetail, out _))
                {
                    detail = childDetail;
                    return true;
                }
            }
            detail = "任一子条件均未满足";
            return false;
        }

        if (condition.Not is not null)
        {
            if (TryEvaluate(condition.Not, e, ctx, out _, out error)) return false;
            detail = "取反条件成立";
            return true;
        }

        if (string.IsNullOrWhiteSpace(condition.Field) || string.IsNullOrWhiteSpace(condition.Op))
        {
            error = "条件缺少 field 或 op";
            return false;
        }

        var actual = PolicyFields.Resolve(condition.Field, e, ctx);
        var op = condition.Op.Trim().ToLowerInvariant();
        var ignoreCase = condition.IgnoreCase;
        var expected = condition.Value;

        if (op is "exists" or "missing")
        {
            var exists = !string.IsNullOrWhiteSpace(actual);
            var ok = op == "exists" ? exists : !exists;
            detail = string.Concat(condition.Field, " ", op, " (", exists ? "存在" : "不存在", ")");
            return ok;
        }

        if (actual is null)
        {
            detail = string.Concat(condition.Field, " 不存在");
            return false;
        }

        switch (op)
        {
            case "eq" or "equals":
                return CompareEquals(actual, expected, ignoreCase, condition.Field, out detail);
            case "ne" or "notequals":
                return !CompareEquals(actual, expected, ignoreCase, condition.Field, out detail) && SetDetail(condition, actual, out detail);
            case "contains":
                return CompareString(actual, expected, ignoreCase, condition.Field, "包含", (a, b) => a.Contains(b, ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal), out detail);
            case "notcontains":
                return CompareString(actual, expected, ignoreCase, condition.Field, "不包含", (a, b) => !a.Contains(b, ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal), out detail);
            case "startswith":
                return CompareString(actual, expected, ignoreCase, condition.Field, "前缀", (a, b) => a.StartsWith(b, ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal), out detail);
            case "endswith":
                return CompareString(actual, expected, ignoreCase, condition.Field, "后缀", (a, b) => a.EndsWith(b, ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal), out detail);
            case "regex":
                return CompareRegex(actual, expected, ignoreCase, condition.Field, out detail);
            case "in":
                return CompareIn(actual, expected, ignoreCase, condition.Field, true, out detail);
            case "notin":
                return CompareIn(actual, expected, ignoreCase, condition.Field, false, out detail);
            case "gt" or "gte" or "lt" or "lte":
                return CompareNumber(actual, expected, op, condition.Field, out detail);
            default:
                error = string.Concat("未知操作符：", op);
                return false;
        }
    }

    private static bool SetDetail(PolicyCondition condition, string actual, out string detail)
    {
        detail = string.Concat(condition.Field, " = ", Trim(actual));
        return true;
    }

    private static bool CompareEquals(string actual, JsonElement? expected, bool ignoreCase, string? field, out string detail)
    {
        detail = string.Empty;
        if (expected is null) return false;
        if (expected.Value.ValueKind == JsonValueKind.Array)
            return CompareIn(actual, expected, ignoreCase, field, true, out detail);
        var text = ElementText(expected.Value);
        var ok = string.Equals(actual, text, ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
        if (ok) detail = string.Concat(field, " = ", Trim(actual));
        return ok;
    }

    private static bool CompareString(string actual, JsonElement? expected, bool ignoreCase, string? field, string label, Func<string, string, bool> predicate, out string detail)
    {
        detail = string.Empty;
        if (expected is null) return false;
        var text = ElementText(expected.Value);
        var ok = predicate(actual, text);
        if (ok) detail = string.Concat(field, " ", label, " \"", Trim(text), "\"");
        return ok;
    }

    private static bool CompareRegex(string actual, JsonElement? expected, bool ignoreCase, string? field, out string detail)
    {
        detail = string.Empty;
        if (expected is null) return false;
        var pattern = ElementText(expected.Value);
        try
        {
            var options = RegexOptions.CultureInvariant | (ignoreCase ? RegexOptions.IgnoreCase : RegexOptions.None);
            var ok = Regex.IsMatch(actual, pattern, options, RegexTimeout);
            if (ok) detail = string.Concat(field, " 匹配 /", Trim(pattern), "/");
            return ok;
        }
        catch (RegexMatchTimeoutException)
        {
            detail = string.Concat(field, " 正则匹配超时");
            return false;
        }
        catch (ArgumentException)
        {
            detail = string.Concat(field, " 正则无效");
            return false;
        }
    }

    private static bool CompareIn(string actual, JsonElement? expected, bool ignoreCase, string? field, bool positive, out string detail)
    {
        detail = string.Empty;
        if (expected is null || expected.Value.ValueKind != JsonValueKind.Array) return false;
        var comparison = ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var found = expected.Value.EnumerateArray().Any(item => string.Equals(actual, ElementText(item), comparison));
        var ok = positive ? found : !found;
        if (ok) detail = string.Concat(field, positive ? " 属于集合" : " 不属于集合");
        return ok;
    }

    private static bool CompareNumber(string actual, JsonElement? expected, string op, string? field, out string detail)
    {
        detail = string.Empty;
        if (expected is null) return false;
        if (!double.TryParse(actual, NumberStyles.Any, CultureInfo.InvariantCulture, out var a) ||
            !double.TryParse(ElementText(expected.Value), NumberStyles.Any, CultureInfo.InvariantCulture, out var b))
            return false;
        var ok = op switch
        {
            "gt" => a > b,
            "gte" => a >= b,
            "lt" => a < b,
            _ => a <= b
        };
        if (ok) detail = string.Concat(field, " ", op, " ", b.ToString(CultureInfo.InvariantCulture));
        return ok;
    }

    private static string ElementText(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.String => element.GetString() ?? string.Empty,
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        JsonValueKind.Null or JsonValueKind.Undefined => string.Empty,
        _ => element.GetRawText()
    };

    private static string Trim(string value) => value.Length <= 120 ? value : string.Concat(value.AsSpan(0, 117), "...");
}
