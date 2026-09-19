using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace TurboAntivirus;

public enum ThreatLevel { Clean, Suspicious, Malicious }

public sealed record ScanResult(string Path, ThreatLevel Level, string Detection, string Sha256);

public sealed class ScannerEngine
{
    private static readonly HashSet<string> KnownBadHashes = new(StringComparer.OrdinalIgnoreCase)
    {
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" // EICAR
    };

    private const string Eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    private static readonly Regex EncodedPowerShell = new(@"powershell(?:\.exe)?\s+[^\r\n]{0,200}-(?:enc|encodedcommand)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public async Task<ScanResult> ScanFileAsync(string path, CancellationToken ct = default)
    {
        try
        {
            ct.ThrowIfCancellationRequested();
            await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 128 * 1024, true);
            using var sha = SHA256.Create();
            var hash = Convert.ToHexString(await sha.ComputeHashAsync(fs, ct)).ToLowerInvariant();

            if (KnownBadHashes.Contains(hash))
                return new(path, ThreatLevel.Malicious, "EICAR-Test-File / Known SHA-256 signature", hash);

            fs.Position = 0;
            if (IsTextLike(path))
            {
                using var reader = new StreamReader(fs, Encoding.UTF8, true, 64 * 1024, leaveOpen: true);
                var sample = await reader.ReadToEndAsync(ct);
                if (sample.Contains(Eicar, StringComparison.Ordinal))
                    return new(path, ThreatLevel.Malicious, "EICAR-Test-File", hash);

                if (EncodedPowerShell.IsMatch(sample))
                    return new(path, ThreatLevel.Suspicious, "Suspicious PowerShell encoded-command pattern", hash);
            }

            return new(path, ThreatLevel.Clean, "No known signature detected", hash);
        }
        catch (UnauthorizedAccessException)
        {
            return new(path, ThreatLevel.Suspicious, "Access denied; file could not be fully scanned", "");
        }
        catch (IOException ex)
        {
            return new(path, ThreatLevel.Suspicious, "File unavailable: " + ex.Message, "");
        }
        catch (Exception ex)
        {
            return new(path, ThreatLevel.Suspicious, "Scan error: " + ex.Message, "");
        }
    }

    private static bool IsTextLike(string path)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        return ext is ".txt" or ".ps1" or ".bat" or ".cmd" or ".vbs" or ".js" or ".jse" or ".wsf" or ".hta" or ".html" or ".htm" or ".xml" or ".json" or ".py" or ".psm1";
    }

    public static IEnumerable<string> EnumerateFilesSafe(string root)
    {
        if (File.Exists(root)) { yield return root; yield break; }
        if (!Directory.Exists(root)) yield break;

        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            IEnumerable<string> files = Array.Empty<string>();
            try { files = Directory.EnumerateFiles(dir); } catch { }
            foreach (var file in files) yield return file;

            IEnumerable<string> dirs = Array.Empty<string>();
            try { dirs = Directory.EnumerateDirectories(dir); } catch { }
            foreach (var child in dirs)
            {
                try { stack.Push(child); } catch { }
            }
        }
    }
}
