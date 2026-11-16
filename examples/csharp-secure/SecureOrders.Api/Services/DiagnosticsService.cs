using System.Diagnostics;

namespace SecureOrders.Api.Services;

public sealed class DiagnosticsService
{
    public string GetRuntimeVersion()
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "dotnet",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        startInfo.ArgumentList.Add("--version");

        using var process = Process.Start(startInfo);
        if (process is null)
        {
            return "unknown";
        }
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit(5000);
        return output.Trim();
    }
}
