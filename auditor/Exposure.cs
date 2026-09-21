using System.Text.Json;
using Amazon.S3.Model;

namespace Auditor;

internal sealed record PolicyRead(string? Policy, bool Failed);

internal sealed record AclRead(List<S3Grant> Grants, bool Failed);

/// <summary>
/// Works out whether a bucket is reachable by anyone on the internet, from its
/// policy and ACL filtered through the Public Access Block settings that
/// actually apply to them:
///   RestrictPublicBuckets  makes a public policy ineffective
///   IgnorePublicAcls       makes public ACL grants ineffective
/// A missing Public Access Block applies neither.
/// </summary>
internal sealed class Exposure
{
    public const string AllUsersUri = "http://acs.amazonaws.com/groups/global/AllUsers";
    public const string AuthenticatedUsersUri = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers";

    // Condition keys that pin a statement to known networks, accounts or
    // callers. AWS does not treat a statement restricted by one of these as
    // public; any other condition leaves it public.
    private static readonly HashSet<string> RestrictingConditionKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "aws:SourceIp", "aws:SourceVpc", "aws:SourceVpce", "aws:SourceAccount", "aws:SourceArn",
        "aws:SourceOwner", "aws:PrincipalAccount", "aws:PrincipalArn", "aws:PrincipalOrgID",
        "aws:PrincipalOrgPaths", "aws:userid", "aws:username", "s3:DataAccessPointAccount",
        "s3:DataAccessPointArn"
    };

    public List<string> Factors { get; } = new();
    public List<string> Warnings { get; } = new();
    public bool IsPublic => Factors.Count > 0;

    public static Exposure Evaluate(Amazon.S3.Model.PublicAccessBlockConfiguration? block, PolicyRead policy, AclRead acl)
    {
        var result = new Exposure();
        var restrictPublicBuckets = block?.RestrictPublicBuckets ?? false;
        var ignorePublicAcls = block?.IgnorePublicAcls ?? false;

        if (!restrictPublicBuckets && IsPublicPolicy(policy.Policy))
        {
            result.Factors.Add("PUBLIC_BUCKET_POLICY");
        }

        if (!ignorePublicAcls)
        {
            var (read, write) = PublicAclAccess(acl.Grants);
            if (read) result.Factors.Add("PUBLIC_ACL_READ");
            if (write) result.Factors.Add("PUBLIC_ACL_WRITE");
        }

        if (policy.Failed) result.Warnings.Add("POLICY_UNREADABLE");
        if (acl.Failed) result.Warnings.Add("ACL_UNREADABLE");
        return result;
    }

    internal static bool IsPublicPolicy(string? policyJson)
    {
        if (string.IsNullOrWhiteSpace(policyJson)) return false;

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(policyJson);
        }
        catch (JsonException)
        {
            return false;
        }

        using (doc)
        {
            if (!doc.RootElement.TryGetProperty("Statement", out var statements)) return false;
            var list = statements.ValueKind == JsonValueKind.Array
                ? statements.EnumerateArray().ToList()
                : new List<JsonElement> { statements };

            return list.Any(s =>
                s.TryGetProperty("Effect", out var effect) &&
                string.Equals(effect.GetString(), "Allow", StringComparison.OrdinalIgnoreCase) &&
                s.TryGetProperty("Principal", out var principal) &&
                IsEveryone(principal) &&
                !IsRestrictedByCondition(s));
        }
    }

    private static bool IsEveryone(JsonElement principal)
    {
        if (principal.ValueKind == JsonValueKind.String) return principal.GetString() == "*";
        if (principal.ValueKind != JsonValueKind.Object) return false;
        if (!principal.TryGetProperty("AWS", out var aws)) return false;
        return aws.ValueKind switch
        {
            JsonValueKind.String => aws.GetString() == "*",
            JsonValueKind.Array => aws.EnumerateArray().Any(a => a.GetString() == "*"),
            _ => false
        };
    }

    private static bool IsRestrictedByCondition(JsonElement statement)
    {
        if (!statement.TryGetProperty("Condition", out var condition) ||
            condition.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        foreach (var op in condition.EnumerateObject())
        {
            if (op.Value.ValueKind != JsonValueKind.Object) continue;
            if (op.Value.EnumerateObject().Any(k => RestrictingConditionKeys.Contains(k.Name))) return true;
        }
        return false;
    }

    internal static (bool Read, bool Write) PublicAclAccess(IEnumerable<S3Grant> grants)
    {
        bool read = false, write = false;
        foreach (var grant in grants)
        {
            var uri = grant.Grantee?.URI;
            if (uri != AllUsersUri && uri != AuthenticatedUsersUri) continue;

            var permission = grant.Permission?.Value;
            if (permission == "READ" || permission == "READ_ACP" || permission == "FULL_CONTROL") read = true;
            if (permission == "WRITE" || permission == "WRITE_ACP" || permission == "FULL_CONTROL") write = true;
        }
        return (read, write);
    }
}
