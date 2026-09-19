namespace TurboAntivirus;

public sealed class MainForm : Form
{
    private readonly ScannerEngine engine = new();
    private readonly QuarantineService quarantine = new();
    private readonly Button quick = new() { Text = "Hızlı Tarama", Width = 150, Height = 42 };
    private readonly Button full = new() { Text = "Tam Tarama", Width = 150, Height = 42 };
    private readonly Button choose = new() { Text = "Dosya / Klasör Tara", Width = 170, Height = 42 };
    private readonly CheckBox realtime = new() { Text = "Gerçek zamanlı koruma", AutoSize = true };
    private readonly Label status = new() { Text = "Hazır", AutoSize = true };
    private readonly ProgressBar progress = new() { Height = 22, Dock = DockStyle.Fill };
    private readonly ListView results = new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true };
    private FileSystemWatcher? watcher;
    private int scanned, threats;

    public MainForm()
    {
        Text = "TurboAntivirus";
        Width = 1000; Height = 650;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(18, 20, 24);
        ForeColor = Color.White;

        results.Columns.Add("Dosya", 420);
        results.Columns.Add("Durum", 110);
        results.Columns.Add("Tespit", 380);

        var title = new Label { Text = "TurboAntivirus", Font = new Font("Segoe UI", 24, FontStyle.Bold), AutoSize = true };
        var subtitle = new Label { Text = "Windows için yerel dosya tarama ve karantina", AutoSize = true, ForeColor = Color.Silver };

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 65, Padding = new Padding(0, 8, 0, 8) };
        buttons.Controls.AddRange(new Control[] { quick, full, choose, realtime });

        var header = new Panel { Dock = DockStyle.Top, Height = 105, Padding = new Padding(18) };
        header.Controls.Add(title);
        title.Location = new Point(18, 10);
        header.Controls.Add(subtitle);
        subtitle.Location = new Point(20, 52);

        var bottom = new Panel { Dock = DockStyle.Bottom, Height = 65, Padding = new Padding(15) };
        bottom.Controls.Add(status);
        status.Location = new Point(15, 8);
        bottom.Controls.Add(progress);
        progress.Location = new Point(15, 32);
        progress.Width = 930;

        Controls.Add(results);
        Controls.Add(bottom);
        Controls.Add(buttons);
        Controls.Add(header);

        quick.Click += async (_, _) => await ScanPathsAsync(new[] { Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) });
        full.Click += async (_, _) => await ScanPathsAsync(DriveInfo.GetDrives().Where(d => d.IsReady).Select(d => d.RootDirectory.FullName));
        choose.Click += async (_, _) =>
        {
            using var dlg = new OpenFileDialog { Title = "Taranacak dosyayı seç", CheckFileExists = true };
            if (dlg.ShowDialog() == DialogResult.OK)
                await ScanPathsAsync(new[] { dlg.FileName });
        };
        realtime.CheckedChanged += (_, _) => SetRealtime(realtime.Checked);
    }

    private async Task ScanPathsAsync(IEnumerable<string> paths)
    {
        ToggleButtons(false);
        scanned = threats = 0;
        results.Items.Clear();
        var files = paths.SelectMany(ScannerEngine.EnumerateFilesSafe).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        progress.Minimum = 0; progress.Maximum = Math.Max(1, files.Count); progress.Value = 0;
        status.Text = $"{files.Count:N0} dosya taranacak...";

        foreach (var file in files)
        {
            var r = await engine.ScanFileAsync(file);
            scanned++;
            if (r.Level != ThreatLevel.Clean) threats++;
            var item = new ListViewItem(new[] { r.Path, r.Level.ToString(), r.Detection });
            item.ForeColor = r.Level switch { ThreatLevel.Malicious => Color.Red, ThreatLevel.Suspicious => Color.Gold, _ => Color.LightGreen };
            results.Items.Add(item);
            progress.Value = Math.Min(progress.Maximum, scanned);
            status.Text = $"{scanned:N0}/{files.Count:N0} — Tehdit: {threats}";
            Application.DoEvents();

            if (r.Level == ThreatLevel.Malicious)
            {
                var answer = MessageBox.Show($"Zararlı imza bulundu:\n\n{r.Path}\n\nKarantinaya alınsın mı?", "TurboAntivirus", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (answer == DialogResult.Yes)
                {
                    try { await quarantine.QuarantineAsync(r); }
                    catch (Exception ex) { MessageBox.Show("Karantina başarısız: " + ex.Message); }
                }
            }
        }

        status.Text = $"Tamamlandı — {scanned:N0} dosya, {threats:N0} uyarı.";
        ToggleButtons(true);
    }

    private void ToggleButtons(bool enabled)
    {
        quick.Enabled = full.Enabled = choose.Enabled = enabled;
    }

    private void SetRealtime(bool enabled)
    {
        if (enabled)
        {
            watcher?.Dispose();
            watcher = new FileSystemWatcher(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile))
            {
                IncludeSubdirectories = true,
                EnableRaisingEvents = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
            };
            watcher.Created += WatcherEvent;
            watcher.Changed += WatcherEvent;
            status.Text = "Gerçek zamanlı koruma açık.";
        }
        else
        {
            watcher?.Dispose();
            watcher = null;
            status.Text = "Gerçek zamanlı koruma kapalı.";
        }
    }

    private async void WatcherEvent(object sender, FileSystemEventArgs e)
    {
        try
        {
            if (!File.Exists(e.FullPath)) return;
            await Task.Delay(500);
            var r = await engine.ScanFileAsync(e.FullPath);
            if (r.Level != ThreatLevel.Clean)
            {
                BeginInvoke(() =>
                {
                    var item = new ListViewItem(new[] { r.Path, r.Level.ToString(), r.Detection });
                    item.ForeColor = r.Level == ThreatLevel.Malicious ? Color.Red : Color.Gold;
                    results.Items.Add(item);
                    MessageBox.Show($"TurboAntivirus uyarısı:\n\n{r.Detection}\n{r.Path}", "Güvenlik Uyarısı", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                });
            }
        }
        catch { }
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        watcher?.Dispose();
        base.OnFormClosed(e);
    }
}
