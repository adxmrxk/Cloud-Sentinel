using Amazon.Lambda.Core;

namespace Auditor;

/// <summary>Logging surface shared by the Lambda and command-line entry points.</summary>
public interface IAuditLog
{
    void Info(string message);
    void Warn(string message);
    void Error(string message);
}

internal sealed class LambdaAuditLog : IAuditLog
{
    private readonly ILambdaLogger _logger;

    public LambdaAuditLog(ILambdaLogger logger) => _logger = logger;

    public void Info(string message) => _logger.LogInformation(message);
    public void Warn(string message) => _logger.LogWarning(message);
    public void Error(string message) => _logger.LogError(message);
}

internal sealed class ConsoleAuditLog : IAuditLog
{
    public void Info(string message) => Console.Out.WriteLine($"[INFO] {message}");
    public void Warn(string message) => Console.Out.WriteLine($"[WARN] {message}");
    public void Error(string message) => Console.Error.WriteLine($"[ERROR] {message}");
}
