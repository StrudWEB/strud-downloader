using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace StrudDownloader;

static class Config
{
    // Anon key herkese açık anahtardır (sitede de görünür), gizli değildir.
    public const string SupabaseUrl = "https://zxnsxueirtsxwxowlkfu.supabase.co";
    public const string AnonKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inp4bnN4dWVpcnRzeHd4b3dsa2Z1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODQ0MjI3NTUsImV4cCI6MjA5OTk5ODc1NX0.jpf11yI3rLR8oyIXAz5Fn3z-Z0sjnuLOwgb4d3U6gRk";
    public const string FunctionName = "strud-download";
}

record Chunk(int I, string Url, long Size, long PlainSize, string Sha256);
record Offer(string Game, string Version, string Exe, string ZipName, long TotalPlain,
             string ZipSha256, string Key, List<Chunk> Chunks);
record InstallInfo(string Version, string Exe);
record GameInfo(string Id, string Title, long Size);
record GameList(List<GameInfo> Games);

class ApiException : Exception
{
    public int Status { get; }
    public ApiException(string message, int status) : base(message) { Status = status; }
}

static class Api
{
    public static readonly HttpClient Http = new() { Timeout = TimeSpan.FromMinutes(5) };
    static readonly JsonSerializerOptions Opt = new(JsonSerializerDefaults.Web);
    static string? access, refresh;

    static string SessionFile => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "STRUD", "session.bin");

    public static bool LoggedIn => access != null;

    static async Task AuthAsync(string grant, object body, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post,
            $"{Config.SupabaseUrl}/auth/v1/token?grant_type={grant}");
        req.Headers.Add("apikey", Config.AnonKey);
        req.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        using var resp = await Http.SendAsync(req, ct);
        var text = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
            throw new ApiException("E-posta veya şifre hatalı.", (int)resp.StatusCode);
        using var doc = JsonDocument.Parse(text);
        access = doc.RootElement.GetProperty("access_token").GetString();
        refresh = doc.RootElement.GetProperty("refresh_token").GetString();
        SaveSession();
    }

    public static Task LoginAsync(string email, string password, CancellationToken ct) =>
        AuthAsync("password", new { email, password }, ct);

    static Task RefreshAsync(CancellationToken ct) =>
        AuthAsync("refresh_token", new { refresh_token = refresh }, ct);

    public static async Task<bool> TryRestoreAsync(CancellationToken ct)
    {
        try
        {
            if (!File.Exists(SessionFile)) return false;
            var raw = ProtectedData.Unprotect(File.ReadAllBytes(SessionFile), null, DataProtectionScope.CurrentUser);
            refresh = Encoding.UTF8.GetString(raw);
            await RefreshAsync(ct);
            return true;
        }
        catch { access = refresh = null; return false; }
    }

    public static void Logout()
    {
        access = refresh = null;
        try { File.Delete(SessionFile); } catch { }
    }

    static void SaveSession()
    {
        if (refresh == null) return;
        Directory.CreateDirectory(Path.GetDirectoryName(SessionFile)!);
        File.WriteAllBytes(SessionFile,
            ProtectedData.Protect(Encoding.UTF8.GetBytes(refresh), null, DataProtectionScope.CurrentUser));
    }

    public static async Task<List<GameInfo>> ListAsync(CancellationToken ct) =>
        (await CallAsync<GameList>(new { action = "list" }, ct)).Games;

    public static Task<Offer> GetOfferAsync(string gameId, CancellationToken ct) =>
        CallAsync<Offer>(new { game = gameId }, ct);

    static async Task<T> CallAsync<T>(object payload, CancellationToken ct)
    {
        if (refresh == null) throw new ApiException("Önce giriş yapmalısın.", 401);
        await RefreshAsync(ct); // taze access token

        using var req = new HttpRequestMessage(HttpMethod.Post,
            $"{Config.SupabaseUrl}/functions/v1/{Config.FunctionName}");
        req.Headers.Add("apikey", Config.AnonKey);
        req.Headers.Add("Authorization", "Bearer " + access);
        req.Content = new StringContent(JsonSerializer.Serialize(payload),
            Encoding.UTF8, "application/json");
        using var resp = await Http.SendAsync(req, ct);
        var text = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
        {
            var msg = (int)resp.StatusCode switch
            {
                401 => "Oturum geçersiz, tekrar giriş yap.",
                404 => "Oyun şu an yayında değil.",
                429 => "Günlük indirme limitine ulaştın, yarın tekrar dene.",
                _ => "Sunucu hatası (" + (int)resp.StatusCode + ")."
            };
            throw new ApiException(msg, (int)resp.StatusCode);
        }
        return JsonSerializer.Deserialize<T>(text, Opt) ?? throw new ApiException("Boş yanıt.", 500);
    }
}

class Installer
{
    readonly string root;
    readonly string gameId;
    readonly string tmp;
    long done;
    readonly Stopwatch clock = new();

    public Installer(string root, string gameId)
    {
        this.root = root;
        this.gameId = gameId;
        tmp = Path.Combine(root, ".strud");
    }

    public static string InfoPath(string root) => Path.Combine(root, "install.json");

    public static InstallInfo? ReadInfo(string root)
    {
        try
        {
            var p = InfoPath(root);
            return File.Exists(p)
                ? JsonSerializer.Deserialize<InstallInfo>(File.ReadAllText(p), new JsonSerializerOptions(JsonSerializerDefaults.Web))
                : null;
        }
        catch { return null; }
    }

    static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    string ChunkFile(Chunk c) => Path.Combine(tmp, $"{c.I:D4}.dat");

    public async Task RunAsync(IProgress<(long done, long total, string text)> progress, CancellationToken ct)
    {
        progress.Report((0, 1, "Sunucuya bağlanılıyor..."));
        var offer = await Api.GetOfferAsync(gameId, ct);

        var info = ReadInfo(root);
        if (info != null && info.Version == offer.Version && File.Exists(Path.Combine(root, "game", info.Exe)))
        {
            progress.Report((1, 1, "Oyun zaten güncel."));
            return;
        }

        Directory.CreateDirectory(tmp);
        var key = Convert.FromBase64String(offer.Key);

        // Daha önce bitmiş parçalar varsa kaldığı yerden devam et.
        done = offer.Chunks.Where(c => File.Exists(ChunkFile(c))).Sum(c => c.PlainSize);
        long startDone = done;
        clock.Restart();

        void Report()
        {
            var secs = Math.Max(clock.Elapsed.TotalSeconds, 0.5);
            var mbps = (Interlocked.Read(ref done) - startDone) / 1048576.0 / secs;
            var pct = offer.TotalPlain == 0 ? 0 : (int)(Interlocked.Read(ref done) * 100 / offer.TotalPlain);
            progress.Report((Interlocked.Read(ref done), offer.TotalPlain, $"İndiriliyor... %{pct}  ({mbps:F1} MB/sn)"));
        }
        Report();

        var gate = new SemaphoreSlim(4);
        var tasks = offer.Chunks.Where(c => !File.Exists(ChunkFile(c))).Select(async c =>
        {
            await gate.WaitAsync(ct);
            try
            {
                await DownloadChunkAsync(c, key, ct);
                Interlocked.Add(ref done, c.PlainSize);
                Report();
            }
            finally { gate.Release(); }
        }).ToList();
        await Task.WhenAll(tasks);

        // Birleştir
        progress.Report((offer.TotalPlain, offer.TotalPlain, "Parçalar birleştiriliyor..."));
        var zipPath = Path.Combine(tmp, offer.ZipName);
        await using (var outFs = File.Create(zipPath))
        {
            foreach (var c in offer.Chunks.OrderBy(c => c.I))
            {
                await using var inFs = File.OpenRead(ChunkFile(c));
                await inFs.CopyToAsync(outFs, ct);
            }
        }

        // Bütünlük (SHA-256)
        progress.Report((offer.TotalPlain, offer.TotalPlain, "Dosya doğrulanıyor (SHA-256)..."));
        string zipHash;
        await using (var zs = File.OpenRead(zipPath))
            zipHash = Hex(await SHA256.HashDataAsync(zs, ct));
        // Siteden yayınlanan oyunlarda her parça GCM + SHA-256 ile zaten doğrulanır; tüm-dosya özeti varsa ayrıca bakılır.
        if (!string.IsNullOrEmpty(offer.ZipSha256) && !zipHash.Equals(offer.ZipSha256, StringComparison.OrdinalIgnoreCase))
        {
            Directory.Delete(tmp, true);
            throw new InvalidDataException("Dosya bozuk çıktı. Tekrar dene.");
        }

        // Aç
        progress.Report((offer.TotalPlain, offer.TotalPlain, "Oyun açılıyor..."));
        var gameDir = Path.Combine(root, "game");
        if (Directory.Exists(gameDir)) Directory.Delete(gameDir, true);
        await Task.Run(() => ZipFile.ExtractToDirectory(zipPath, gameDir, true), ct);

        File.WriteAllText(InfoPath(root), JsonSerializer.Serialize(new InstallInfo(offer.Version, offer.Exe)));
        Directory.Delete(tmp, true);
        progress.Report((offer.TotalPlain, offer.TotalPlain, "Kurulum tamamlandı."));
    }

    // [12 nonce][şifreli veri][16 etiket], AAD = parça numarası (ASCII).
    // Senkron tutuldu: Span, async metotlarda kullanılamaz.
    static byte[] DecryptChunk(byte[] data, byte[] key, int index)
    {
        var nonce = data.AsSpan(0, 12);
        var cipher = data.AsSpan(12, data.Length - 12 - 16);
        var tag = data.AsSpan(data.Length - 16);
        var plain = new byte[cipher.Length];
        using var gcm = new AesGcm(key, 16);
        gcm.Decrypt(nonce, cipher, tag, plain, Encoding.ASCII.GetBytes(index.ToString()));
        return plain;
    }

    async Task DownloadChunkAsync(Chunk c, byte[] key, CancellationToken ct)
    {
        Exception? last = null;
        for (int attempt = 1; attempt <= 3; attempt++)
        {
            try
            {
                using var resp = await Api.Http.GetAsync(c.Url, HttpCompletionOption.ResponseHeadersRead, ct);
                resp.EnsureSuccessStatusCode();
                var data = await resp.Content.ReadAsByteArrayAsync(ct);

                if (!Hex(SHA256.HashData(data)).Equals(c.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException($"Parça {c.I} doğrulanamadı.");

                var plain = DecryptChunk(data, key, c.I);

                var tmpFile = ChunkFile(c) + ".part";
                await File.WriteAllBytesAsync(tmpFile, plain, ct);
                File.Move(tmpFile, ChunkFile(c), true);
                return;
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                last = ex;
                await Task.Delay(1000 * attempt, ct);
            }
        }
        throw new IOException($"Parça {c.I} indirilemedi: {last?.Message}");
    }
}

class MainForm : Form
{
    readonly TextBox email = new() { PlaceholderText = "E-posta" };
    readonly TextBox pass = new() { PlaceholderText = "Şifre", UseSystemPasswordChar = true };
    readonly Button login = new() { Text = "Giriş yap" };
    readonly Button logout = new() { Text = "Çıkış" };
    readonly Button install = new() { Text = "İndir ve kur" };
    readonly Button pause = new() { Text = "Duraklat" };
    readonly Button play = new() { Text = "Oyna" };
    readonly ProgressBar bar = new() { Minimum = 0, Maximum = 1000 };
    readonly Label status = new() { AutoSize = false };
    readonly ComboBox games = new() { DropDownStyle = ComboBoxStyle.DropDownList };
    List<GameInfo> gameList = new();
    readonly Label title = new() { Text = "STRUD Downloader", Font = new Font("Segoe UI", 13f, FontStyle.Bold), AutoSize = true };
    CancellationTokenSource? cts;

    GameInfo? Selected => games.SelectedIndex >= 0 && games.SelectedIndex < gameList.Count ? gameList[games.SelectedIndex] : null;

    string Root
    {
        get
        {
            var name = new string((Selected?.Title ?? "game").Select(ch => Path.GetInvalidFileNameChars().Contains(ch) ? '_' : ch).ToArray());
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "STRUD Games", name);
        }
    }

    public MainForm()
    {
        Text = "STRUD Downloader";
        ClientSize = new Size(440, 270);
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;

        title.Location = new Point(16, 14);
        email.SetBounds(16, 56, 408, 26);
        pass.SetBounds(16, 90, 408, 26);
        login.SetBounds(16, 126, 408, 32);
        logout.SetBounds(344, 12, 80, 26);
        games.SetBounds(16, 52, 408, 26);
        install.SetBounds(16, 92, 200, 38);
        pause.SetBounds(224, 92, 100, 38);
        play.SetBounds(332, 92, 92, 38);
        bar.SetBounds(16, 148, 408, 18);
        status.SetBounds(16, 176, 408, 70);

        Controls.AddRange(new Control[] { title, email, pass, login, logout, games, install, pause, play, bar, status });
        games.SelectedIndexChanged += (_, _) => ShowState();

        login.Click += async (_, _) => await DoLogin();
        pass.KeyDown += async (_, e) => { if (e.KeyCode == Keys.Enter) await DoLogin(); };
        logout.Click += (_, _) => { Api.Logout(); ShowState(); };
        install.Click += async (_, _) => await DoInstall();
        pause.Click += (_, _) => cts?.Cancel();
        play.Click += (_, _) => DoPlay();

        Shown += async (_, _) =>
        {
            status.Text = "Oturum kontrol ediliyor...";
            if (await Api.TryRestoreAsync(CancellationToken.None)) await LoadGames();
            else status.Text = "";
            ShowState();
        };
        ShowState();
    }

    void ShowState()
    {
        bool inn = Api.LoggedIn;
        email.Visible = pass.Visible = login.Visible = !inn;
        logout.Visible = games.Visible = install.Visible = pause.Visible = play.Visible = bar.Visible = inn;
        pause.Enabled = false;
        install.Enabled = Selected != null;
        play.Enabled = Selected != null && Installer.ReadInfo(Root) != null;
    }

    async Task LoadGames()
    {
        try
        {
            gameList = await Api.ListAsync(CancellationToken.None);
            games.Items.Clear();
            foreach (var g in gameList) games.Items.Add($"{g.Title}  ({g.Size / 1048576.0:F0} MB)");
            if (games.Items.Count > 0) games.SelectedIndex = 0;
            status.Text = gameList.Count == 0 ? "Henüz yayınlanmış oyun yok." : "";
        }
        catch (Exception ex) { status.Text = "Liste alınamadı: " + ex.Message; }
    }

    async Task DoLogin()
    {
        login.Enabled = false;
        status.Text = "Giriş yapılıyor...";
        try
        {
            await Api.LoginAsync(email.Text.Trim(), pass.Text, CancellationToken.None);
            pass.Clear();
            status.Text = "";
            await LoadGames();
        }
        catch (Exception ex) { status.Text = ex.Message; }
        login.Enabled = true;
        ShowState();
    }

    async Task DoInstall()
    {
        cts = new CancellationTokenSource();
        install.Enabled = logout.Enabled = play.Enabled = games.Enabled = false;
        pause.Enabled = true;
        var progress = new Progress<(long done, long total, string text)>(p =>
        {
            bar.Value = p.total <= 0 ? 0 : (int)Math.Min(1000, p.done * 1000 / p.total);
            status.Text = p.text;
        });
        try
        {
            Directory.CreateDirectory(Root);
            await new Installer(Root, Selected!.Id).RunAsync(progress, cts.Token);
        }
        catch (OperationCanceledException) { status.Text = "Duraklatıldı. \"İndir ve kur\" ile kaldığı yerden devam eder."; }
        catch (Exception ex) { status.Text = "Hata: " + ex.Message; }
        finally
        {
            logout.Enabled = games.Enabled = true;
            ShowState();
        }
    }

    void DoPlay()
    {
        var info = Installer.ReadInfo(Root);
        if (info == null) return;
        var gameDir = Path.Combine(Root, "game");
        var exe = Path.GetFullPath(Path.Combine(gameDir, info.Exe));
        if (!exe.StartsWith(Path.GetFullPath(gameDir)) || !File.Exists(exe))
        {
            status.Text = "Oyun dosyası bulunamadı. Tekrar kur.";
            return;
        }
        Process.Start(new ProcessStartInfo(exe) { WorkingDirectory = Path.GetDirectoryName(exe)!, UseShellExecute = true });
    }
}

static class Program
{
    [STAThread]
    static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}
