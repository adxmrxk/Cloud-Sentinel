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

    /// <summary>Source for trace spans; a no-op unless a tracer provider listens.</summary>
    public static readonly ActivitySource Tracing = new("CloudSentinel.Auditor");

    private readonly IAmazonS3 _s3Client;

    public Function() : this(Program.CreateS3Client())
    {
    }

    public Function(IAmazonS3 s3Client)
    {
        _s3Client = s3Client;
    }

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

        var atRiskBuckets = new List<BucketRiskInfo>();
        var auditTimestamp = DateTime.UtcNow.ToString("o");
        int totalBucketsScanned;

        try
        {
            var listBucketsResponse = await _s3Client.ListBucketsAsync();
            var buckets = listBucketsResponse.Buckets ?? new List<S3Bucket>();
            totalBucketsScanned = buckets.Count;

            log.Info($"Found {totalBucketsScanned} buckets to scan");

            foreach (var bucket in buckets)
            {
                var finding = await ScanBucketAsync(bucket, log);
                if (finding != null)
                {
                    atRiskBuckets.Add(finding);
                }
            }
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
        using var span = Tracing.StartActivity("s3.GetPublicAccessBlock");
        span?.SetTag("aws.s3.bucket", bucket.BucketName);

        try
        {
            var publicAccessResponse = await _s3Client.GetPublicAccessBlockAsync(
                new GetPublicAccessBlockRequest { BucketName = bucket.BucketName });
            var config = publicAccessResponse.PublicAccessBlockConfiguration;

            bool isAtRisk = !config.BlockPublicAcls ||
                            !config.IgnorePublicAcls ||
                            !config.BlockPublicPolicy ||
                            !config.RestrictPublicBuckets;

            if (!isAtRisk)
            {
                return null;
            }

            log.Warn($"AT RISK: {bucket.BucketName}");
            return new BucketRiskInfo
            {
                BucketName = bucket.BucketName,
                CreationDate = bucket.CreationDate.ToString("o"),
                RiskFactors = GetRiskFactors(config),
                Severity = CalculateSeverity(config)
            };
        }
        catch (AmazonS3Exception ex) when (ex.ErrorCode == "NoSuchPublicAccessBlockConfiguration")
        {
            log.Warn($"CRITICAL: {bucket.BucketName} has no public access block");
            return new BucketRiskInfo
            {
                BucketName = bucket.BucketName,
                CreationDate = bucket.CreationDate.ToString("o"),
                RiskFactors = new List<string> { "NO_PUBLIC_ACCESS_BLOCK_CONFIGURED" },
                Severity = "CRITICAL"
            };
        }
        catch (AmazonS3Exception ex)
        {
            span?.SetStatus(ActivityStatusCode.Error, ex.Message);
            log.Error($"Error scanning bucket {bucket.BucketName}: {ex.Message}");
            return null;
        }
    }

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
