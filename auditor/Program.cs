using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Amazon.S3;
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace Auditor;

/// <summary>
/// Command-line entry point used by the Kubernetes CronJob and local runs.
/// The Lambda runtime never calls this; it invokes Function.FunctionHandler.
///
///   dotnet Auditor.dll --full-scan
///
/// Environment:
///   REPORTER_URL                 base URL of the reporter; findings are POSTed to /ingest
///   INGEST_API_KEY               bearer token the reporter requires on /ingest
///   AUDITOR_MAX_CONCURRENCY      buckets scanned in parallel (default 16)
///   S3_ENDPOINT_URL              optional S3-compatible endpoint (local testing)
///   OTEL_EXPORTER_OTLP_ENDPOINT  optional OTLP/HTTP collector, e.g. http://jaeger:4318
/// </summary>
public static class Program
{
    public const string FullScanFlag = "--full-scan";

    /// <summary>camelCase, matching the Lambda serializer and the reporter's /ingest contract.</summary>
    public static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static async Task<int> Main(string[] args)
    {
        if (!args.Contains(FullScanFlag))
        {
            Console.Error.WriteLine($"usage: dotnet Auditor.dll {FullScanFlag}");
            return 2;
        }

        using var tracerProvider = BuildTracerProvider();
        var log = new ConsoleAuditLog();

        using var run = Function.Tracing.StartActivity("cloudsentinel.full-scan");
        try
        {
            var function = new Function(CreateS3Client());
            var result = await function.RunAuditAsync(log);
            Console.Out.WriteLine(JsonSerializer.Serialize(result, JsonOptions));

            var reporterUrl = Environment.GetEnvironmentVariable("REPORTER_URL");
            if (string.IsNullOrWhiteSpace(reporterUrl))
            {
                log.Warn("REPORTER_URL is not set; findings were not sent to the reporter");
            }
            else
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
                await ReportAsync(http, reporterUrl, result, log);
            }

            return 0;
        }
        catch (Exception ex)
        {
            run?.SetStatus(System.Diagnostics.ActivityStatusCode.Error, ex.Message);
            log.Error($"Audit failed: {ex.Message}");
            return 1;
        }
    }

    /// <summary>Retry settings for delivering findings to the reporter.</summary>
    public sealed class ReportOptions
    {
        public int MaxAttempts { get; init; } = 5;
        public TimeSpan BaseDelay { get; init; } = TimeSpan.FromSeconds(1);
        public string? ApiKey { get; init; } = Environment.GetEnvironmentVariable("INGEST_API_KEY");
    }

    /// <summary>
    /// POSTs the audit result to the reporter's /ingest endpoint.
    ///
    /// A scan is expensive and runs once a day, so one dropped connection or
    /// a reporter restart must not lose it. Transient failures (network
    /// errors, timeouts, 429 and 5xx) are retried with exponential backoff
    /// and jitter. Every attempt carries the same Idempotency-Key, so a retry
    /// after a response was lost cannot store the audit twice.
    /// </summary>
    public static async Task ReportAsync(
        HttpClient http, string reporterUrl, AuditResponse result, IAuditLog log, ReportOptions? options = null)
    {
        options ??= new ReportOptions();
        var target = new Uri(new Uri(reporterUrl.TrimEnd('/') + "/"), "ingest");
        var idempotencyKey = Guid.NewGuid().ToString();

        for (var attempt = 1; ; attempt++)
        {
            string failure;
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, target)
                {
                    Content = JsonContent.Create(result, options: JsonOptions)
                };
                request.Headers.Add("Idempotency-Key", idempotencyKey);
                if (!string.IsNullOrWhiteSpace(options.ApiKey))
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", options.ApiKey);
                }

                using var response = await http.SendAsync(request);
                var body = await response.Content.ReadAsStringAsync();
                if (response.IsSuccessStatusCode)
                {
                    log.Info($"Findings sent to reporter: {body}");
                    return;
                }

                failure = $"HTTP {(int)response.StatusCode} {body}";
                if (!IsTransient(response.StatusCode))
                {
                    throw new InvalidOperationException($"Reporter rejected findings: {failure}");
                }
            }
            catch (HttpRequestException ex)
            {
                failure = ex.Message;
            }
            catch (TaskCanceledException)
            {
                failure = "request timed out";
            }

            if (attempt >= options.MaxAttempts)
            {
                throw new InvalidOperationException(
                    $"Reporter unavailable after {attempt} attempts: {failure}");
            }

            var backoff = options.BaseDelay * Math.Pow(2, attempt - 1);
            var delay = backoff * (0.5 + Random.Shared.NextDouble() / 2);
            log.Warn($"Reporter delivery attempt {attempt} failed ({failure}); retrying in {delay.TotalSeconds:F1}s");
            await Task.Delay(delay);
        }
    }

    private static bool IsTransient(HttpStatusCode status) =>
        status == HttpStatusCode.TooManyRequests || status == HttpStatusCode.RequestTimeout || (int)status >= 500;

    internal static IAmazonS3 CreateS3Client()
    {
        var endpoint = Environment.GetEnvironmentVariable("S3_ENDPOINT_URL");
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            return new AmazonS3Client();
        }

        return new AmazonS3Client(new AmazonS3Config
        {
            ServiceURL = endpoint,
            ForcePathStyle = true,
            AuthenticationRegion = Environment.GetEnvironmentVariable("AWS_REGION") ?? "us-east-1"
        });
    }

    private static TracerProvider? BuildTracerProvider()
    {
        var endpoint = Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT");
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            return null;
        }

        return Sdk.CreateTracerProviderBuilder()
            .SetResourceBuilder(ResourceBuilder.CreateDefault().AddService("cloudsentinel-auditor"))
            .AddSource(Function.Tracing.Name)
            .AddHttpClientInstrumentation()
            .AddOtlpExporter(options =>
            {
                options.Endpoint = new Uri(endpoint.TrimEnd('/') + "/v1/traces");
                options.Protocol = OtlpExportProtocol.HttpProtobuf;
            })
            .Build();
    }
}
