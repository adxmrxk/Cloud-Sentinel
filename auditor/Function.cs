using Amazon.Lambda.Core;
using Amazon.S3;
using Amazon.S3.Model;
using System.Text.Json;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Auditor;

/// <summary>
/// CloudSentinel Auditor - Scans S3 buckets for public access misconfigurations
/// </summary>
public class Function
{
    private readonly IAmazonS3 _s3Client;

    public Function()
    {
        _s3Client = new AmazonS3Client();
    }

    public Function(IAmazonS3 s3Client)
    {
        _s3Client = s3Client;
    }

    public async Task<AuditResponse> FunctionHandler(object input, ILambdaContext context)
    {
        context.Logger.LogInformation("CloudSentinel Auditor: Starting S3 bucket security scan");

        var atRiskBuckets = new List<BucketRiskInfo>();
        var auditTimestamp = DateTime.UtcNow.ToString("o");
        int totalBucketsScanned = 0;

        try
        {
            var listBucketsResponse = await _s3Client.ListBucketsAsync();
            totalBucketsScanned = listBucketsResponse.Buckets.Count;

            context.Logger.LogInformation($"Found {totalBucketsScanned} buckets to scan");

            foreach (var bucket in listBucketsResponse.Buckets)
            {
                try
                {
                    var publicAccessRequest = new GetPublicAccessBlockRequest
                    {
                        BucketName = bucket.BucketName
                    };

                    var publicAccessResponse = await _s3Client.GetPublicAccessBlockAsync(publicAccessRequest);
                    var config = publicAccessResponse.PublicAccessBlockConfiguration;

                    bool isAtRisk = !config.BlockPublicAcls ||
                                    !config.IgnorePublicAcls ||
                                    !config.BlockPublicPolicy ||
                                    !config.RestrictPublicBuckets;

                    if (isAtRisk)
                    {
                        atRiskBuckets.Add(new BucketRiskInfo
                        {
                            BucketName = bucket.BucketName,
                            CreationDate = bucket.CreationDate.ToString("o"),
                            RiskFactors = GetRiskFactors(config),
                            Severity = CalculateSeverity(config)
                        });

                        context.Logger.LogWarning($"AT RISK: {bucket.BucketName}");
                    }
                }
                catch (AmazonS3Exception ex) when (ex.ErrorCode == "NoSuchPublicAccessBlockConfiguration")
                {
                    atRiskBuckets.Add(new BucketRiskInfo
                    {
                        BucketName = bucket.BucketName,
                        CreationDate = bucket.CreationDate.ToString("o"),
                        RiskFactors = new List<string> { "NO_PUBLIC_ACCESS_BLOCK_CONFIGURED" },
                        Severity = "CRITICAL"
                    });

                    context.Logger.LogWarning($"CRITICAL: {bucket.BucketName} has no public access block");
                }
                catch (AmazonS3Exception ex)
                {
                    context.Logger.LogError($"Error scanning bucket {bucket.BucketName}: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            context.Logger.LogError($"Fatal error during audit: {ex.Message}");
            throw;
        }

        var response = new AuditResponse
        {
            VulnerabilitiesFound = atRiskBuckets.Count > 0,
            AtRiskBuckets = atRiskBuckets,
            TotalBucketsScanned = totalBucketsScanned,
            AuditTimestamp = auditTimestamp
        };

        context.Logger.LogInformation($"Audit complete: {atRiskBuckets.Count}/{totalBucketsScanned} buckets at risk");

        return response;
    }

    private static List<string> GetRiskFactors(PublicAccessBlockConfiguration config)
    {
        var factors = new List<string>();

        if (!config.BlockPublicAcls) factors.Add("BLOCK_PUBLIC_ACLS_DISABLED");
        if (!config.IgnorePublicAcls) factors.Add("IGNORE_PUBLIC_ACLS_DISABLED");
        if (!config.BlockPublicPolicy) factors.Add("BLOCK_PUBLIC_POLICY_DISABLED");
        if (!config.RestrictPublicBuckets) factors.Add("RESTRICT_PUBLIC_BUCKETS_DISABLED");

        return factors;
    }

    private static string CalculateSeverity(PublicAccessBlockConfiguration config)
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
}

public class BucketRiskInfo
{
    public string BucketName { get; set; } = string.Empty;
    public string CreationDate { get; set; } = string.Empty;
    public List<string> RiskFactors { get; set; } = new();
    public string Severity { get; set; } = string.Empty;
}
