using System.Diagnostics;

namespace VulnerableOrders.Api.Services;

public sealed class DiagnosticsService
{
    public string Ping(string host)
    {
        // INTENTIONALLY INSECURE: untrusted input reaches a shell command.
        using var process = Process.Start("cmd.exe", "/c ping " + host);
        if (process is null)
        {
            return "failed";
        }
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit(5000);
        return output;
    }
}
