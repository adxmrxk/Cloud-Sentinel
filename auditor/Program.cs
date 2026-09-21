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

    /// <summary>POSTs the audit result to the reporter's /ingest endpoint.</summary>
    public static async Task ReportAsync(HttpClient http, string reporterUrl, AuditResponse result, IAuditLog log)
    {
        var target = new Uri(new Uri(reporterUrl.TrimEnd('/') + "/"), "ingest");
        using var response = await http.PostAsJsonAsync(target, result, JsonOptions);
        var body = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"Reporter rejected findings: HTTP {(int)response.StatusCode} {body}");
        }

        log.Info($"Findings sent to reporter: {body}");
    }

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
