using System.Text.Json;

namespace TurboAntivirus;

public sealed class QuarantineService
{
    private readonly string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TurboAntivirus", "Quarantine");

    public string Root => root;

    public async Task<string> QuarantineAsync(ScanResult result)
    {
        Directory.CreateDirectory(root);
        var id = $"{DateTime.UtcNow:yyyyMMddHHmmssfff}_{Guid.NewGuid():N}";
        var target = Path.Combine(root, id + ".quarantined");
        File.Move(result.Path, target, false);

        var meta = new
        {
            originalPath = result.Path,
            quarantinedPath = target,
            result.Detection,
            result.Sha256,
            timestampUtc = DateTime.UtcNow
        };
        await File.WriteAllTextAsync(target + ".json", JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true }));
        return target;
    }
}
