using System.Net;
using System.Text;
using System.Text.Json;
using Amazon.Lambda.Serialization.SystemTextJson;
using Amazon.S3;
using Amazon.S3.Model;
using Auditor;
using Moq;
using Xunit;

namespace Auditor.Tests;

public class FunctionTests
{
    private static PublicAccessBlockConfiguration Block(bool acls, bool ignore, bool policy, bool restrict) =>
        new()
        {
            BlockPublicAcls = acls,
            IgnorePublicAcls = ignore,
            BlockPublicPolicy = policy,
            RestrictPublicBuckets = restrict
        };

    private static Mock<IAmazonS3> S3With(params string[] bucketNames)
    {
        var s3 = new Mock<IAmazonS3>(MockBehavior.Strict);
        s3.Setup(x => x.ListBucketsAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ListBucketsResponse
            {
                Buckets = bucketNames
                    .Select(n => new S3Bucket { BucketName = n, CreationDate = new DateTime(2026, 1, 1) })
                    .ToList()
            });
        // By default every bucket is private: no policy, no ACL grants.
        s3.Setup(x => x.GetBucketPolicyAsync(It.IsAny<GetBucketPolicyRequest>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new AmazonS3Exception("none") { ErrorCode = "NoSuchBucketPolicy" });
        s3.Setup(x => x.GetACLAsync(It.IsAny<GetACLRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new GetACLResponse { AccessControlList = new S3AccessControlList() });
        return s3;
    }

    private static void GivenPolicy(Mock<IAmazonS3> s3, string bucket, string policy) =>
        s3.Setup(x => x.GetBucketPolicyAsync(
                It.Is<GetBucketPolicyRequest>(r => r.BucketName == bucket), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new GetBucketPolicyResponse { Policy = policy });

    private static void GivenAcl(Mock<IAmazonS3> s3, string bucket, string granteeUri, S3Permission permission)
    {
        var acl = new S3AccessControlList();
        acl.Grants.Add(new S3Grant { Grantee = new S3Grantee { URI = granteeUri }, Permission = permission });
        s3.Setup(x => x.GetACLAsync(It.Is<GetACLRequest>(r => r.BucketName == bucket), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new GetACLResponse { AccessControlList = acl });
    }

    private const string PublicReadPolicy =
        "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\"," +
        "\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::b/*\"}]}";

    private static void GivenBlock(Mock<IAmazonS3> s3, string bucket, PublicAccessBlockConfiguration config) =>
        s3.Setup(x => x.GetPublicAccessBlockAsync(
                It.Is<GetPublicAccessBlockRequest>(r => r.BucketName == bucket), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new GetPublicAccessBlockResponse { PublicAccessBlockConfiguration = config });

    private static void GivenError(Mock<IAmazonS3> s3, string bucket, string errorCode) =>
        s3.Setup(x => x.GetPublicAccessBlockAsync(
                It.Is<GetPublicAccessBlockRequest>(r => r.BucketName == bucket), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new AmazonS3Exception("boom") { ErrorCode = errorCode });

    private sealed class NullLog : IAuditLog
    {
        public readonly List<string> Errors = new();
        public void Info(string message) { }
        public void Warn(string message) { }
        public void Error(string message) => Errors.Add(message);
    }

    [Fact]
    public async Task FullyBlockedBucket_IsNotReported()
    {
        var s3 = S3With("locked");
        GivenBlock(s3, "locked", Block(true, true, true, true));

        var result = await new Function(s3.Object).RunAuditAsync(new NullLog());

        Assert.False(result.VulnerabilitiesFound);
        Assert.Empty(result.AtRiskBuckets);
        Assert.Equal(1, result.TotalBucketsScanned);
    }

    [Fact]
    public async Task MissingPublicAccessBlock_IsCritical()
    {
        var s3 = S3With("open");
        GivenError(s3, "open", "NoSuchPublicAccessBlockConfiguration");

        var result = await new Function(s3.Object).RunAuditAsync(new NullLog());

        var finding = Assert.Single(result.AtRiskBuckets);
        Assert.Equal("open", finding.BucketName);
        Assert.Equal("CRITICAL", finding.Severity);
        Assert.Equal(new[] { "NO_PUBLIC_ACCESS_BLOCK_CONFIGURED" }, finding.RiskFactors);
        Assert.True(result.VulnerabilitiesFound);
    }

    [Theory]
    [InlineData(false, false, false, false, "CRITICAL", 4)]
    [InlineData(false, false, false, true, "HIGH", 3)]
    [InlineData(false, false, true, true, "MEDIUM", 2)]
    [InlineData(false, true, true, true, "LOW", 1)]
    [InlineData(true, true, true, false, "LOW", 1)]
    public async Task PartialBlock_SeverityMatchesDisabledCount(
        bool acls, bool ignore, bool policy, bool restrict, string severity, int factorCount)
    {
        var s3 = S3With("partial");
        GivenBlock(s3, "partial", Block(acls, ignore, policy, restrict));

        var result = await new Function(s3.Object).RunAuditAsync(new NullLog());

        var finding = Assert.Single(result.AtRiskBuckets);
        Assert.Equal(severity, finding.Severity);
        Assert.Equal(factorCount, finding.RiskFactors.Count);
    }

    [Fact]
    public void RiskFactors_NameEachDisabledProtection()
    {
        var factors = Function.GetRiskFactors(Block(false, true, false, true));

        Assert.Equal(new[] { "BLOCK_PUBLIC_ACLS_DISABLED", "BLOCK_PUBLIC_POLICY_DISABLED" }, factors);
    }

    [Fact]
    public async Task BucketError_IsLoggedAndScanContinues()
    {
        var s3 = S3With("denied", "open");
        GivenError(s3, "denied", "AccessDenied");
        GivenError(s3, "open", "NoSuchPublicAccessBlockConfiguration");
        var log = new NullLog();

        var result = await new Function(s3.Object).RunAuditAsync(log);

        Assert.Equal(2, result.TotalBucketsScanned);
        Assert.Equal("open", Assert.Single(result.AtRiskBuckets).BucketName);
        Assert.Contains(log.Errors, e => e.Contains("denied"));
    }

    [Fact]
    public async Task ListBucketsFailure_Propagates()
    {
        var s3 = new Mock<IAmazonS3>(MockBehavior.Strict);
        s3.Setup(x => x.ListBucketsAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new AmazonS3Exception("no credentials"));

        await Assert.ThrowsAsync<AmazonS3Exception>(
            () => new Function(s3.Object).RunAuditAsync(new NullLog()));
    }

    [Fact]
    public async Task Response_CarriesProviderAndDuration()
    {
        var s3 = S3With();

        var result = await new Function(s3.Object).RunAuditAsync(new NullLog());

        Assert.Equal("aws", result.CloudProvider);
        Assert.True(result.ScanDurationSeconds >= 0);
        Assert.False(string.IsNullOrEmpty(result.AuditTimestamp));
    }

    [Fact]
    public async Task PublicPolicy_IsCriticalEvenWithOnlyTwoSettingsOff()
    {
        // Two settings off scores MEDIUM, but the policy makes it world-readable.
        var s3 = S3With("site");
        GivenBlock(s3, "site", Block(true, true, false, false));
        GivenPolicy(s3, "site", PublicReadPolicy);

        var finding = Assert.Single((await new Function(s3.Object).RunAuditAsync(new NullLog())).AtRiskBuckets);

        Assert.Equal("CRITICAL", finding.Severity);
        Assert.Contains("PUBLIC_BUCKET_POLICY", finding.RiskFactors);
    }

    [Fact]
    public async Task PublicPolicy_NeutralisedByRestrictPublicBuckets_IsNotEscalated()
    {
        var s3 = S3With("site");
        GivenBlock(s3, "site", Block(true, true, false, true));
        GivenPolicy(s3, "site", PublicReadPolicy);

        var finding = Assert.Single((await new Function(s3.Object).RunAuditAsync(new NullLog())).AtRiskBuckets);

        Assert.Equal("LOW", finding.Severity);
        Assert.DoesNotContain("PUBLIC_BUCKET_POLICY", finding.RiskFactors);
    }

    [Fact]
    public async Task PublicWriteAcl_IsCriticalEvenWithOneSettingOff()
    {
        var s3 = S3With("drop");
        GivenBlock(s3, "drop", Block(true, false, true, true));
        GivenAcl(s3, "drop", Exposure.AllUsersUri, S3Permission.WRITE);

        var finding = Assert.Single((await new Function(s3.Object).RunAuditAsync(new NullLog())).AtRiskBuckets);

        Assert.Equal("CRITICAL", finding.Severity);
        Assert.Contains("PUBLIC_ACL_WRITE", finding.RiskFactors);
    }

    [Fact]
    public async Task PublicAcl_IgnoredByIgnorePublicAcls_IsNotEscalated()
    {
        var s3 = S3With("old");
        GivenBlock(s3, "old", Block(false, true, true, true));
        GivenAcl(s3, "old", Exposure.AllUsersUri, S3Permission.READ);

        var finding = Assert.Single((await new Function(s3.Object).RunAuditAsync(new NullLog())).AtRiskBuckets);

        Assert.Equal("LOW", finding.Severity);
    }

    [Fact]
    public async Task FullyBlockedBucket_SkipsPolicyAndAclCalls()
    {
        var s3 = S3With("locked");
        GivenBlock(s3, "locked", Block(true, true, true, true));

        await new Function(s3.Object).RunAuditAsync(new NullLog());

        s3.Verify(x => x.GetBucketPolicyAsync(It.IsAny<GetBucketPolicyRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        s3.Verify(x => x.GetACLAsync(It.IsAny<GetACLRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Theory]
    [InlineData("{\"Statement\":{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"s3:*\"}}", true)]
    [InlineData("{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":[\"arn:aws:iam::1:root\",\"*\"]}}]}", true)]
    [InlineData("{\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\"}]}", false)]
    [InlineData("{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::1:root\"}}]}", false)]
    [InlineData("{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Condition\":{\"IpAddress\":{\"aws:SourceIp\":\"10.0.0.0/8\"}}}]}", false)]
    [InlineData("{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Condition\":{\"StringEquals\":{\"aws:UserAgent\":\"x\"}}}]}", true)]
    [InlineData("not json", false)]
    public void PolicyEvaluation(string policy, bool isPublic)
    {
        Assert.Equal(isPublic, Exposure.IsPublicPolicy(policy));
    }

    [Fact]
    public async Task Buckets_AreScannedConcurrently_WithinTheLimit_InListOrder()
    {
        var names = Enumerable.Range(0, 40).Select(i => $"b{i:00}").ToArray();
        var s3 = S3With(names);
        int inFlight = 0, peak = 0;
        s3.Setup(x => x.GetPublicAccessBlockAsync(It.IsAny<GetPublicAccessBlockRequest>(), It.IsAny<CancellationToken>()))
            .Returns(async () =>
            {
                var now = Interlocked.Increment(ref inFlight);
                InterlockedMax(ref peak, now);
                await Task.Delay(20);
                Interlocked.Decrement(ref inFlight);
                return new GetPublicAccessBlockResponse { PublicAccessBlockConfiguration = Block(true, true, true, false) };
            });

        var result = await new Function(s3.Object, maxConcurrency: 8).RunAuditAsync(new NullLog());

        Assert.Equal(names, result.AtRiskBuckets.Select(b => b.BucketName));
        Assert.True(peak > 1, $"expected parallel scans, peak was {peak}");
        Assert.True(peak <= 8, $"concurrency limit exceeded: {peak}");
    }

    private static void InterlockedMax(ref int target, int value)
    {
        int current;
        while (value > (current = Volatile.Read(ref target)) &&
               Interlocked.CompareExchange(ref target, value, current) != current)
        {
        }
    }

    [Fact]
    public void LambdaSerializer_EmitsCamelCaseForStepFunctions()
    {
        // The state machine reads $.Payload.vulnerabilitiesFound; PascalCase would break it.
        var response = new AuditResponse
        {
            VulnerabilitiesFound = true,
            AtRiskBuckets = { new BucketRiskInfo { BucketName = "b", Severity = "LOW" } }
        };
        using var stream = new MemoryStream();
        new CamelCaseLambdaJsonSerializer().Serialize(response, stream);
        var json = Encoding.UTF8.GetString(stream.ToArray());

        Assert.Contains("\"vulnerabilitiesFound\":true", json);
        Assert.Contains("\"atRiskBuckets\"", json);
        Assert.Contains("\"totalBucketsScanned\"", json);
        Assert.Contains("\"auditTimestamp\"", json);
        Assert.Contains("\"scanDurationSeconds\"", json);
    }

    [Fact]
    public void AssemblyUsesCamelCaseLambdaSerializer()
    {
        var attribute = typeof(Function).Assembly
            .GetCustomAttributes(typeof(Amazon.Lambda.Core.LambdaSerializerAttribute), false)
            .Cast<Amazon.Lambda.Core.LambdaSerializerAttribute>()
            .Single();

        Assert.Equal(typeof(CamelCaseLambdaJsonSerializer), attribute.SerializerType);
    }
}

public class ProgramTests
{
    private sealed class CapturingHandler : HttpMessageHandler
    {
        private readonly Queue<HttpStatusCode?> _responses;
        public HttpRequestMessage? Request;
        public string? Body;
        public readonly List<string> IdempotencyKeys = new();

        // null in the sequence means "connection dropped"; the last entry repeats.
        public CapturingHandler(params HttpStatusCode?[] responses) => _responses = new(responses);

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Request = request;
            Body = request.Content == null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            IdempotencyKeys.Add(request.Headers.GetValues("Idempotency-Key").Single());
            var status = _responses.Count > 1 ? _responses.Dequeue() : _responses.Peek();
            if (status == null) throw new HttpRequestException("connection reset");
            return new HttpResponseMessage(status.Value) { Content = new StringContent("{\"status\":\"ok\"}") };
        }
    }

    private static readonly Program.ReportOptions Fast = new() { BaseDelay = TimeSpan.Zero, ApiKey = "k" };

    private sealed class NullLog : IAuditLog
    {
        public void Info(string message) { }
        public void Warn(string message) { }
        public void Error(string message) { }
    }

    private static AuditResponse SampleResult() => new()
    {
        VulnerabilitiesFound = true,
        TotalBucketsScanned = 2,
        AuditTimestamp = "2026-01-01T00:00:00Z",
        AtRiskBuckets = { new BucketRiskInfo { BucketName = "open", Severity = "CRITICAL" } }
    };

    [Theory]
    [InlineData("http://reporter:8000")]
    [InlineData("http://reporter:8000/")]
    public async Task ReportAsync_PostsCamelCaseJsonToIngest(string baseUrl)
    {
        var handler = new CapturingHandler(HttpStatusCode.Created);
        using var http = new HttpClient(handler);

        await Program.ReportAsync(http, baseUrl, SampleResult(), new NullLog());

        Assert.Equal(HttpMethod.Post, handler.Request!.Method);
        Assert.Equal("http://reporter:8000/ingest", handler.Request.RequestUri!.ToString());
        using var doc = JsonDocument.Parse(handler.Body!);
        Assert.True(doc.RootElement.GetProperty("vulnerabilitiesFound").GetBoolean());
        Assert.Equal("open", doc.RootElement.GetProperty("atRiskBuckets")[0].GetProperty("bucketName").GetString());
    }

    [Fact]
    public async Task ReportAsync_DoesNotRetryAClientError()
    {
        var handler = new CapturingHandler(HttpStatusCode.BadRequest);
        using var http = new HttpClient(handler);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Program.ReportAsync(http, "http://reporter:8000", SampleResult(), new NullLog(), Fast));
        Assert.Single(handler.IdempotencyKeys);
    }

    [Fact]
    public async Task ReportAsync_RetriesTransientFailures_WithOneIdempotencyKey()
    {
        var handler = new CapturingHandler(
            null, HttpStatusCode.ServiceUnavailable, HttpStatusCode.TooManyRequests, HttpStatusCode.Created);
        using var http = new HttpClient(handler);

        await Program.ReportAsync(http, "http://reporter:8000", SampleResult(), new NullLog(), Fast);

        Assert.Equal(4, handler.IdempotencyKeys.Count);
        Assert.Single(handler.IdempotencyKeys.Distinct());
        Assert.Equal("Bearer", handler.Request!.Headers.Authorization!.Scheme);
        Assert.Equal("k", handler.Request.Headers.Authorization.Parameter);
    }

    [Fact]
    public async Task ReportAsync_GivesUpAfterMaxAttempts()
    {
        var handler = new CapturingHandler(HttpStatusCode.BadGateway);
        using var http = new HttpClient(handler);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Program.ReportAsync(http, "http://reporter:8000", SampleResult(), new NullLog(), Fast));
        Assert.Equal(Fast.MaxAttempts, handler.IdempotencyKeys.Count);
        Assert.Contains("after 5 attempts", error.Message);
    }

    [Fact]
    public async Task Main_WithoutFullScanFlag_ReturnsUsageError()
    {
        Assert.Equal(2, await Program.Main(Array.Empty<string>()));
    }
}
