using System.Diagnostics;
using Amazon.Lambda.Core;
using Amazon.S3;
using Amazon.S3.Model;

// camelCase output is required by the Step Functions definition, which reads
// $.Payload.vulnerabilitiesFound etc. The default serializer keeps PascalCase.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.CamelCaseLambdaJsonSerializer))]

namespace Auditor;

/// <summary>
/// CloudSentinel Auditor - Scans S3 buckets for public access misconfigurations
/// </summary>
public class Function
{
    public const string CloudProvider = "aws";

    /// <summary>Buckets scanned in parallel unless AUDITOR_MAX_CONCURRENCY says otherwise.</summary>
    public const int DefaultMaxConcurrency = 16;

    /// <summary>Source for trace spans; a no-op unless a tracer provider listens.</summary>
    public static readonly ActivitySource Tracing = new("CloudSentinel.Auditor");

    private readonly IAmazonS3 _s3Client;
    private readonly int _maxConcurrency;

    public Function() : this(Program.CreateS3Client())
    {
    }

    public Function(IAmazonS3 s3Client, int? maxConcurrency = null)
    {
        _s3Client = s3Client;
        _maxConcurrency = Math.Max(1, maxConcurrency ?? ConcurrencyFromEnvironment());
    }

    private static int ConcurrencyFromEnvironment() =>
        int.TryParse(Environment.GetEnvironmentVariable("AUDITOR_MAX_CONCURRENCY"), out var n) && n > 0
            ? n
            : DefaultMaxConcurrency;

    /// <summary>Lambda entry point, invoked by Step Functions.</summary>
    public Task<AuditResponse> FunctionHandler(object input, ILambdaContext context)
    {
        return RunAuditAsync(new LambdaAuditLog(context.Logger));
    }

    /// <summary>Runs one full scan of every bucket visible to the credentials.</summary>
    public async Task<AuditResponse> RunAuditAsync(IAuditLog log)
    {
        using var auditSpan = Tracing.StartActivity("s3.audit");
        var stopwatch = Stopwatch.StartNew();

        log.Info("CloudSentinel Auditor: Starting S3 bucket security scan");

        var auditTimestamp = DateTime.UtcNow.ToString("o");
        List<BucketRiskInfo> atRiskBuckets;
        int totalBucketsScanned;

        try
        {
            var listBucketsResponse = await _s3Client.ListBucketsAsync();
            var buckets = listBucketsResponse.Buckets ?? new List<S3Bucket>();
            totalBucketsScanned = buckets.Count;

            log.Info($"Found {totalBucketsScanned} buckets to scan ({_maxConcurrency} in parallel)");

            // Each bucket costs one to three S3 round trips. Scanned one after
            // another, a 1,000-bucket account took ~48 s at 40 ms per call -
            // past the 30 s Lambda timeout. Scan a bounded number at once;
            // results keep the ListBuckets order.
            using var gate = new SemaphoreSlim(_maxConcurrency);
            var scans = buckets.Select(async bucket =>
            {
                await gate.WaitAsync();
                try
                {
                    return await ScanBucketAsync(bucket, log);
                }
                finally
                {
                    gate.Release();
                }
            });
            var results = await Task.WhenAll(scans);
            atRiskBuckets = results.Where(r => r != null).Select(r => r!).ToList();
        }
        catch (Exception ex)
        {
            auditSpan?.SetStatus(ActivityStatusCode.Error, ex.Message);
            log.Error($"Fatal error during audit: {ex.Message}");
            throw;
        }

        stopwatch.Stop();

        var response = new AuditResponse
        {
            VulnerabilitiesFound = atRiskBuckets.Count > 0,
            AtRiskBuckets = atRiskBuckets,
            TotalBucketsScanned = totalBucketsScanned,
            AuditTimestamp = auditTimestamp,
            ScanDurationSeconds = Math.Round(stopwatch.Elapsed.TotalSeconds, 3),
            CloudProvider = CloudProvider
        };

        auditSpan?.SetTag("cloudsentinel.buckets_scanned", totalBucketsScanned);
        auditSpan?.SetTag("cloudsentinel.buckets_at_risk", atRiskBuckets.Count);

        log.Info($"Audit complete: {atRiskBuckets.Count}/{totalBucketsScanned} buckets at risk");

        return response;
    }

    private async Task<BucketRiskInfo?> ScanBucketAsync(S3Bucket bucket, IAuditLog log)
    {
        using var span = Tracing.StartActivity("s3.scan_bucket");
        span?.SetTag("aws.s3.bucket", bucket.BucketName);

        PublicAccessBlockConfiguration? config;
        try
        {
            var publicAccessResponse = await _s3Client.GetPublicAccessBlockAsync(
                new GetPublicAccessBlockRequest { BucketName = bucket.BucketName });
            config = publicAccessResponse.PublicAccessBlockConfiguration;
        }
        catch (AmazonS3Exception ex) when (ex.ErrorCode == "NoSuchPublicAccessBlockConfiguration")
        {
            config = null;
        }
        catch (AmazonS3Exception ex)
        {
            span?.SetStatus(ActivityStatusCode.Error, ex.Message);
            log.Error($"Error scanning bucket {bucket.BucketName}: {ex.Message}");
            return null;
        }

        if (config != null && IsFullyBlocked(config))
        {
            // All four settings on: no policy or ACL can make the bucket public.
            return null;
        }

        // The Public Access Block only says what S3 would stop. Whether the
        // bucket is actually public depends on its policy and ACL, so read
        // both (in parallel) and work out the effective exposure.
        var policyTask = ReadPolicyAsync(bucket.BucketName, log);
        var aclTask = ReadAclAsync(bucket.BucketName, log);
        var exposure = Exposure.Evaluate(config, await policyTask, await aclTask);

        var finding = new BucketRiskInfo
        {
            BucketName = bucket.BucketName,
            CreationDate = bucket.CreationDate.ToString("o"),
            RiskFactors = config == null
                ? new List<string> { "NO_PUBLIC_ACCESS_BLOCK_CONFIGURED" }
                : GetRiskFactors(config),
            Severity = config == null ? "CRITICAL" : CalculateSeverity(config)
        };

        if (exposure.IsPublic)
        {
            // Anyone on the internet can reach this bucket right now, whatever
            // the count of disabled settings says.
            finding.Severity = "CRITICAL";
            finding.RiskFactors.AddRange(exposure.Factors);
        }
        finding.RiskFactors.AddRange(exposure.Warnings);

        span?.SetTag("cloudsentinel.severity", finding.Severity);
        log.Warn($"AT RISK ({finding.Severity}): {bucket.BucketName} [{string.Join(", ", finding.RiskFactors)}]");
        return finding;
    }

    private async Task<PolicyRead> ReadPolicyAsync(string bucket, IAuditLog log)
    {
        try
        {
            var response = await _s3Client.GetBucketPolicyAsync(new GetBucketPolicyRequest { BucketName = bucket });
            return new PolicyRead(response.Policy, Failed: false);
        }
        catch (AmazonS3Exception ex) when (ex.ErrorCode == "NoSuchBucketPolicy")
        {
            return new PolicyRead(null, Failed: false);
        }
        catch (AmazonS3Exception ex)
        {
            log.Warn($"Could not read the policy of {bucket}: {ex.Message}");
            return new PolicyRead(null, Failed: true);
        }
    }

    private async Task<AclRead> ReadAclAsync(string bucket, IAuditLog log)
    {
        try
        {
            var response = await _s3Client.GetACLAsync(new GetACLRequest { BucketName = bucket });
            return new AclRead(response.AccessControlList?.Grants ?? new List<S3Grant>(), Failed: false);
        }
        catch (AmazonS3Exception ex)
        {
            log.Warn($"Could not read the ACL of {bucket}: {ex.Message}");
            return new AclRead(new List<S3Grant>(), Failed: true);
        }
    }

    internal static bool IsFullyBlocked(PublicAccessBlockConfiguration config) =>
        config.BlockPublicAcls && config.IgnorePublicAcls && config.BlockPublicPolicy && config.RestrictPublicBuckets;

    internal static List<string> GetRiskFactors(PublicAccessBlockConfiguration config)
    {
        var factors = new List<string>();

        if (!config.BlockPublicAcls) factors.Add("BLOCK_PUBLIC_ACLS_DISABLED");
        if (!config.IgnorePublicAcls) factors.Add("IGNORE_PUBLIC_ACLS_DISABLED");
        if (!config.BlockPublicPolicy) factors.Add("BLOCK_PUBLIC_POLICY_DISABLED");
        if (!config.RestrictPublicBuckets) factors.Add("RESTRICT_PUBLIC_BUCKETS_DISABLED");

        return factors;
    }

    internal static string CalculateSeverity(PublicAccessBlockConfiguration config)
    {
        int disabledCount = 0;
        if (!config.BlockPublicAcls) disabledCount++;
        if (!config.IgnorePublicAcls) disabledCount++;
        if (!config.BlockPublicPolicy) disabledCount++;
        if (!config.RestrictPublicBuckets) disabledCount++;

        return disabledCount switch
        {
            4 => "CRITICAL",
            3 => "HIGH",
            2 => "MEDIUM",
            _ => "LOW"
        };
    }
}

public class AuditResponse
{
    public bool VulnerabilitiesFound { get; set; }
    public List<BucketRiskInfo> AtRiskBuckets { get; set; } = new();
    public int TotalBucketsScanned { get; set; }
    public string AuditTimestamp { get; set; } = string.Empty;
    public double ScanDurationSeconds { get; set; }
    public string CloudProvider { get; set; } = Function.CloudProvider;
}

public class BucketRiskInfo
{
    public string BucketName { get; set; } = string.Empty;
    public string CreationDate { get; set; } = string.Empty;
    public List<string> RiskFactors { get; set; } = new();
    public string Severity { get; set; } = string.Empty;
}
