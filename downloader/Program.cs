using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace StrudDownloader
{
    static class Config
    {
        // Anon key herkese açık anahtardır (sitede de görünür), gizli değildir.
        public const string SupabaseUrl = "https://zxnsxueirtsxwxowlkfu.supabase.co";
        public const string AnonKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inp4bnN4dWVpcnRzeHd4b3dsa2Z1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODQ0MjI3NTUsImV4cCI6MjA5OTk5ODc1NX0.jpf11yI3rLR8oyIXAz5Fn3z-Z0sjnuLOwgb4d3U6gRk";
        public const string FunctionName = "dynamic-responder";
    }

    class Chunk { public int I; public string Url; public long Size; public long PlainSize; public string Sha256; }

    class Offer
    {
        public string Game, Version, Exe, ZipName, ZipSha256, Key;
        public long TotalPlain;
        public List<Chunk> Chunks = new List<Chunk>();
    }

    class GameInfo { public string Id; public string Title; public long Size; }
    class InstallInfo { public string Version; public string Exe; }
    class ProgressInfo { public long Done; public long Total; public string Text; }

    class ApiException : Exception
    {
        public int Status;
        public ApiException(string message, int status) : base(message) { Status = status; }
    }

    static class Json
    {
        static readonly JavaScriptSerializer S = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };

        public static string Write(object o) { return S.Serialize(o); }

        public static Dictionary<string, object> Read(string text)
        {
            var d = S.DeserializeObject(text) as Dictionary<string, object>;
            if (d == null) throw new InvalidDataException("Geçersiz sunucu yanıtı.");
            return d;
        }

        public static string Str(Dictionary<string, object> d, string key)
        {
            object v;
            return d.TryGetValue(key, out v) && v != null ? Convert.ToString(v) : "";
        }

        public static long Num(Dictionary<string, object> d, string key)
        {
            object v;
            return d.TryGetValue(key, out v) && v != null ? Convert.ToInt64(v) : 0L;
        }

        public static IEnumerable<Dictionary<string, object>> Items(Dictionary<string, object> d, string key)
        {
            object v;
            var result = new List<Dictionary<string, object>>();
            if (d.TryGetValue(key, out v) && v is System.Collections.IEnumerable && !(v is string))
                foreach (object item in (System.Collections.IEnumerable)v)
                {
                    var dict = item as Dictionary<string, object>;
                    if (dict != null) result.Add(dict);
                }
            return result;
        }
    }

    // AES-256-GCM çözme: .NET Framework'te AesGcm sınıfı yok, Windows'un kendi CNG kütüphanesini (bcrypt.dll) kullanıyoruz.
    static class AesGcmNative
    {
        [StructLayout(LayoutKind.Sequential)]
        struct AuthInfo
        {
            public int cbSize;
            public int dwInfoVersion;
            public IntPtr pbNonce;
            public int cbNonce;
            public IntPtr pbAuthData;
            public int cbAuthData;
            public IntPtr pbTag;
            public int cbTag;
            public IntPtr pbMacContext;
            public int cbMacContext;
            public int cbAAD;
            public long cbData;
            public int dwFlags;
        }

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, int dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        static extern int BCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, int dwFlags);

        [DllImport("bcrypt.dll")]
        static extern int BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, int dwFlags);

        [DllImport("bcrypt.dll")]
        static extern int BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref AuthInfo pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, int dwFlags);

        [DllImport("bcrypt.dll")]
        static extern int BCryptDestroyKey(IntPtr hKey);

        [DllImport("bcrypt.dll")]
        static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, int dwFlags);

        // data = [12 bayt nonce][şifreli veri][16 bayt etiket]; ilk len bayt geçerli.
        public static byte[] Decrypt(byte[] key, byte[] data, int len, byte[] aad)
        {
            if (len < 28) throw new InvalidDataException("Parça çok kısa.");
            var nonce = new byte[12];
            Buffer.BlockCopy(data, 0, nonce, 0, 12);
            var tag = new byte[16];
            Buffer.BlockCopy(data, len - 16, tag, 0, 16);
            int clen = len - 28;
            var cipher = new byte[clen];
            Buffer.BlockCopy(data, 12, cipher, 0, clen);
            var plain = new byte[clen];

            IntPtr hAlg = IntPtr.Zero, hKey = IntPtr.Zero;
            GCHandle hNonce = default(GCHandle), hAad = default(GCHandle), hTag = default(GCHandle);
            try
            {
                Check(BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0), "AES");
                byte[] mode = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
                Check(BCryptSetProperty(hAlg, "ChainingMode", mode, mode.Length, 0), "GCM");
                Check(BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0), "key");

                hNonce = GCHandle.Alloc(nonce, GCHandleType.Pinned);
                hAad = GCHandle.Alloc(aad, GCHandleType.Pinned);
                hTag = GCHandle.Alloc(tag, GCHandleType.Pinned);

                var info = new AuthInfo();
                info.cbSize = Marshal.SizeOf(typeof(AuthInfo));
                info.dwInfoVersion = 1;
                info.pbNonce = hNonce.AddrOfPinnedObject();
                info.cbNonce = nonce.Length;
                info.pbAuthData = hAad.AddrOfPinnedObject();
                info.cbAuthData = aad.Length;
                info.pbTag = hTag.AddrOfPinnedObject();
                info.cbTag = tag.Length;

                int written;
                int status = BCryptDecrypt(hKey, cipher, clen, ref info, null, 0, plain, clen, out written, 0);
                if (status != 0)
                    throw new CryptographicException("Parça çözülemedi (doğrulama hatası, kod 0x" + status.ToString("X8") + ").");
                return plain;
            }
            finally
            {
                if (hNonce.IsAllocated) hNonce.Free();
                if (hAad.IsAllocated) hAad.Free();
                if (hTag.IsAllocated) hTag.Free();
                if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey);
                if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
            }
        }

        static void Check(int status, string what)
        {
            if (status != 0)
                throw new CryptographicException("Şifreleme hatası (" + what + ") 0x" + status.ToString("X8"));
        }
    }

    static class Api
    {
        public static readonly HttpClient Http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        static string access, refresh;

        static string SessionFile
        {
            get
            {
                return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "STRUD", "session.bin");
            }
        }

        public static bool LoggedIn { get { return access != null; } }

        static async Task AuthAsync(string grant, object body, CancellationToken ct)
        {
            using (var req = new HttpRequestMessage(HttpMethod.Post, Config.SupabaseUrl + "/auth/v1/token?grant_type=" + grant))
            {
                req.Headers.TryAddWithoutValidation("apikey", Config.AnonKey);
                req.Content = new StringContent(Json.Write(body), Encoding.UTF8, "application/json");
                using (var resp = await Http.SendAsync(req, ct))
                {
                    string text = await resp.Content.ReadAsStringAsync();
                    if (!resp.IsSuccessStatusCode)
                        throw new ApiException(grant == "password" ? "E-posta veya şifre hatalı." : "Oturum süresi doldu, tekrar giriş yap.", (int)resp.StatusCode);
                    var d = Json.Read(text);
                    access = Json.Str(d, "access_token");
                    refresh = Json.Str(d, "refresh_token");
                    SaveSession();
                }
            }
        }

        public static Task LoginAsync(string email, string password, CancellationToken ct)
        {
            return AuthAsync("password", new Dictionary<string, object> { { "email", email }, { "password", password } }, ct);
        }

        static Task RefreshAsync(CancellationToken ct)
        {
            return AuthAsync("refresh_token", new Dictionary<string, object> { { "refresh_token", refresh } }, ct);
        }

        public static async Task<bool> TryRestoreAsync(CancellationToken ct)
        {
            try
            {
                if (!File.Exists(SessionFile)) return false;
                byte[] raw = ProtectedData.Unprotect(File.ReadAllBytes(SessionFile), null, DataProtectionScope.CurrentUser);
                refresh = Encoding.UTF8.GetString(raw);
                await RefreshAsync(ct);
                return true;
            }
            catch
            {
                access = null;
                refresh = null;
                return false;
            }
        }

        public static void Logout()
        {
            access = null;
            refresh = null;
            try { File.Delete(SessionFile); } catch { }
        }

        static void SaveSession()
        {
            if (refresh == null) return;
            Directory.CreateDirectory(Path.GetDirectoryName(SessionFile));
            File.WriteAllBytes(SessionFile, ProtectedData.Protect(Encoding.UTF8.GetBytes(refresh), null, DataProtectionScope.CurrentUser));
        }

        public static async Task<List<GameInfo>> ListAsync(CancellationToken ct)
        {
            var d = await CallAsync(new Dictionary<string, object> { { "action", "list" } }, ct);
            var result = new List<GameInfo>();
            foreach (var g in Json.Items(d, "games"))
                result.Add(new GameInfo { Id = Json.Str(g, "id"), Title = Json.Str(g, "title"), Size = Json.Num(g, "size") });
            return result;
        }

        public static async Task<Offer> GetOfferAsync(string gameId, CancellationToken ct)
        {
            var d = await CallAsync(new Dictionary<string, object> { { "game", gameId } }, ct);
            var o = new Offer
            {
                Game = Json.Str(d, "game"),
                Version = Json.Str(d, "version"),
                Exe = Json.Str(d, "exe"),
                ZipName = Json.Str(d, "zipName"),
                ZipSha256 = Json.Str(d, "zipSha256"),
                Key = Json.Str(d, "key"),
                TotalPlain = Json.Num(d, "totalPlain")
            };
            foreach (var c in Json.Items(d, "chunks"))
                o.Chunks.Add(new Chunk
                {
                    I = (int)Json.Num(c, "i"),
                    Url = Json.Str(c, "url"),
                    Size = Json.Num(c, "size"),
                    PlainSize = Json.Num(c, "plainSize"),
                    Sha256 = Json.Str(c, "sha256")
                });
            if (o.Chunks.Count == 0 || string.IsNullOrEmpty(o.Key)) throw new ApiException("Sunucudan eksik veri geldi.", 500);
            return o;
        }

        static async Task<Dictionary<string, object>> CallAsync(object payload, CancellationToken ct)
        {
            if (refresh == null) throw new ApiException("Önce giriş yapmalısın.", 401);
            await RefreshAsync(ct); // taze access token

            using (var req = new HttpRequestMessage(HttpMethod.Post, Config.SupabaseUrl + "/functions/v1/" + Config.FunctionName))
            {
                req.Headers.TryAddWithoutValidation("apikey", Config.AnonKey);
                req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + access);
                req.Content = new StringContent(Json.Write(payload), Encoding.UTF8, "application/json");
                using (var resp = await Http.SendAsync(req, ct))
                {
                    string text = await resp.Content.ReadAsStringAsync();
                    if (!resp.IsSuccessStatusCode)
                    {
                        int code = (int)resp.StatusCode;
                        string msg;
                        if (code == 401) msg = "Oturum geçersiz, tekrar giriş yap.";
                        else if (code == 404) msg = "Oyun şu an yayında değil.";
                        else if (code == 429) msg = "Günlük indirme limitine ulaştın, yarın tekrar dene.";
                        else msg = "Sunucu hatası (" + code + ").";
                        throw new ApiException(msg, code);
                    }
                    return Json.Read(text);
                }
            }
        }
    }

    class Installer
    {
        readonly string root;
        readonly string gameId;
        readonly string tmp;
        long done;
        readonly Stopwatch clock = new Stopwatch();

        public Installer(string root, string gameId)
        {
            this.root = root;
            this.gameId = gameId;
            tmp = Path.Combine(root, ".strud");
        }

        public static string InfoPath(string root) { return Path.Combine(root, "install.json"); }

        public static InstallInfo ReadInfo(string root)
        {
            try
            {
                string p = InfoPath(root);
                if (!File.Exists(p)) return null;
                var d = Json.Read(File.ReadAllText(p));
                return new InstallInfo { Version = Json.Str(d, "version"), Exe = Json.Str(d, "exe") };
            }
            catch { return null; }
        }

        static string Hex(byte[] b) { return BitConverter.ToString(b).Replace("-", "").ToLowerInvariant(); }

        string ChunkFile(Chunk c) { return Path.Combine(tmp, c.I.ToString("D4") + ".dat"); }

        public async Task RunAsync(IProgress<ProgressInfo> progress, CancellationToken ct)
        {
            progress.Report(new ProgressInfo { Done = 0, Total = 1, Text = "Sunucuya bağlanılıyor..." });
            Offer offer = await Api.GetOfferAsync(gameId, ct);

            InstallInfo info = ReadInfo(root);
            if (info != null && info.Version == offer.Version && File.Exists(Path.Combine(root, "game", info.Exe)))
            {
                progress.Report(new ProgressInfo { Done = 1, Total = 1, Text = "Oyun zaten güncel." });
                return;
            }

            // Başka sürümden kalan yarım parçalar karışmasın.
            string marker = Path.Combine(tmp, "version.txt");
            if (Directory.Exists(tmp) && (!File.Exists(marker) || File.ReadAllText(marker) != offer.Version))
                Directory.Delete(tmp, true);
            Directory.CreateDirectory(tmp);
            File.WriteAllText(marker, offer.Version);

            byte[] key = Convert.FromBase64String(offer.Key);

            // Daha önce bitmiş parçalar varsa kaldığı yerden devam et.
            done = offer.Chunks.Where(x => File.Exists(ChunkFile(x))).Sum(x => x.PlainSize);
            long startDone = done;
            clock.Restart();

            Action report = () =>
            {
                long now = Interlocked.Read(ref done);
                double secs = Math.Max(clock.Elapsed.TotalSeconds, 0.5);
                double mbps = (now - startDone) / 1048576.0 / secs;
                int pct = offer.TotalPlain == 0 ? 0 : (int)(now * 100 / offer.TotalPlain);
                progress.Report(new ProgressInfo { Done = now, Total = offer.TotalPlain, Text = "İndiriliyor... %" + pct + "  (" + mbps.ToString("F1") + " MB/sn)" });
            };
            report();

            Exception firstError = null;
            using (var linked = CancellationTokenSource.CreateLinkedTokenSource(ct))
            using (var gate = new SemaphoreSlim(3))
            {
                var tasks = new List<Task>();
                foreach (Chunk chunk in offer.Chunks.Where(x => !File.Exists(ChunkFile(x))))
                {
                    Chunk cur = chunk;
                    tasks.Add(Task.Run(async () =>
                    {
                        await gate.WaitAsync(linked.Token);
                        try
                        {
                            await DownloadChunkAsync(cur, key, linked.Token);
                            Interlocked.Add(ref done, cur.PlainSize);
                            report();
                        }
                        catch (Exception ex)
                        {
                            if (!(ex is OperationCanceledException)) Interlocked.CompareExchange(ref firstError, ex, null);
                            linked.Cancel();
                            throw;
                        }
                        finally { gate.Release(); }
                    }));
                }

                try { await Task.WhenAll(tasks); }
                catch
                {
                    if (ct.IsCancellationRequested) throw new OperationCanceledException(ct);
                    if (firstError != null) throw firstError;
                    throw;
                }
            }

            // Birleştir
            progress.Report(new ProgressInfo { Done = offer.TotalPlain, Total = offer.TotalPlain, Text = "Parçalar birleştiriliyor..." });
            string zipPath = Path.Combine(tmp, "game.zip");
            using (var outFs = new FileStream(zipPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920, true))
            {
                foreach (Chunk c in offer.Chunks.OrderBy(x => x.I))
                    using (var inFs = new FileStream(ChunkFile(c), FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true))
                        await inFs.CopyToAsync(outFs, 81920, ct);
            }

            // Tüm dosya özeti varsa kontrol et (her parça zaten SHA-256 + GCM ile doğrulandı).
            if (!string.IsNullOrEmpty(offer.ZipSha256))
            {
                progress.Report(new ProgressInfo { Done = offer.TotalPlain, Total = offer.TotalPlain, Text = "Dosya doğrulanıyor (SHA-256)..." });
                string zipHash = await Task.Run(() =>
                {
                    using (var fs = File.OpenRead(zipPath))
                    using (var sha = SHA256.Create())
                        return Hex(sha.ComputeHash(fs));
                });
                if (!zipHash.Equals(offer.ZipSha256, StringComparison.OrdinalIgnoreCase))
                {
                    Directory.Delete(tmp, true);
                    throw new InvalidDataException("Dosya bozuk çıktı. Tekrar dene.");
                }
            }

            // Aç
            progress.Report(new ProgressInfo { Done = offer.TotalPlain, Total = offer.TotalPlain, Text = "Oyun açılıyor..." });
            string gameDir = Path.Combine(root, "game");
            if (Directory.Exists(gameDir)) Directory.Delete(gameDir, true);
            await Task.Run(() => ExtractSafely(zipPath, gameDir, ct));

            File.WriteAllText(InfoPath(root), Json.Write(new Dictionary<string, object> { { "version", offer.Version }, { "exe", offer.Exe } }));
            Directory.Delete(tmp, true);
            progress.Report(new ProgressInfo { Done = offer.TotalPlain, Total = offer.TotalPlain, Text = "Kurulum tamamlandı." });
        }

        static void ExtractSafely(string zipPath, string gameDir, CancellationToken ct)
        {
            Directory.CreateDirectory(gameDir);
            string full = Path.GetFullPath(gameDir);
            if (!full.EndsWith(Path.DirectorySeparatorChar.ToString())) full += Path.DirectorySeparatorChar;
            using (ZipArchive zip = ZipFile.OpenRead(zipPath))
            {
                foreach (ZipArchiveEntry entry in zip.Entries)
                {
                    ct.ThrowIfCancellationRequested();
                    string dest = Path.GetFullPath(Path.Combine(gameDir, entry.FullName));
                    if (!dest.StartsWith(full, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("Geçersiz dosya yolu: " + entry.FullName);
                    if (entry.FullName.EndsWith("/") || entry.FullName.EndsWith("\\"))
                    {
                        Directory.CreateDirectory(dest);
                        continue;
                    }
                    Directory.CreateDirectory(Path.GetDirectoryName(dest));
                    entry.ExtractToFile(dest, true);
                }
            }
        }

        static byte[] VerifyAndDecrypt(byte[] data, int len, byte[] key, Chunk c)
        {
            string h;
            using (var sha = SHA256.Create()) h = Hex(sha.ComputeHash(data, 0, len));
            if (!h.Equals(c.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Parça " + c.I + " doğrulanamadı.");
            return AesGcmNative.Decrypt(key, data, len, Encoding.ASCII.GetBytes(c.I.ToString()));
        }

        async Task DownloadChunkAsync(Chunk c, byte[] key, CancellationToken ct)
        {
            Exception last = null;
            for (int attempt = 1; attempt <= 3; attempt++)
            {
                try
                {
                    var ms = new MemoryStream((int)c.Size);
                    using (var resp = await Api.Http.GetAsync(c.Url, HttpCompletionOption.ResponseHeadersRead, ct))
                    {
                        resp.EnsureSuccessStatusCode();
                        using (Stream s = await resp.Content.ReadAsStreamAsync())
                            await s.CopyToAsync(ms, 81920, ct);
                    }
                    if (ms.Length != c.Size) throw new InvalidDataException("Parça " + c.I + " eksik indi.");
                    byte[] data = ms.GetBuffer();
                    int len = (int)ms.Length;

                    byte[] plain = await Task.Run(() => VerifyAndDecrypt(data, len, key, c));
                    string target = ChunkFile(c);
                    string part = target + ".part";
                    await Task.Run(() =>
                    {
                        File.WriteAllBytes(part, plain);
                        if (File.Exists(target)) File.Delete(target);
                        File.Move(part, target);
                    });
                    return;
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    last = ex;
                    await Task.Delay(1000 * attempt, ct);
                }
            }
            throw new IOException("Parça " + c.I + " indirilemedi: " + (last == null ? "" : last.Message));
        }
    }

    class MainForm : Form
    {
        readonly Label title = new Label { Text = "STRUD Downloader", Font = new Font("Segoe UI", 13f, FontStyle.Bold), AutoSize = true };
        readonly Label lblEmail = new Label { Text = "E-posta", AutoSize = true };
        readonly Label lblPass = new Label { Text = "Şifre", AutoSize = true };
        readonly TextBox email = new TextBox();
        readonly TextBox pass = new TextBox { UseSystemPasswordChar = true };
        readonly Button login = new Button { Text = "Giriş yap" };
        readonly Button logout = new Button { Text = "Çıkış" };
        readonly ComboBox games = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList };
        readonly Button install = new Button { Text = "İndir ve kur" };
        readonly Button pause = new Button { Text = "Duraklat" };
        readonly Button play = new Button { Text = "Oyna" };
        readonly ProgressBar bar = new ProgressBar { Minimum = 0, Maximum = 1000 };
        readonly Label status = new Label { AutoSize = false };
        List<GameInfo> gameList = new List<GameInfo>();
        CancellationTokenSource cts;

        GameInfo Selected
        {
            get { return games.SelectedIndex >= 0 && games.SelectedIndex < gameList.Count ? gameList[games.SelectedIndex] : null; }
        }

        string Root
        {
            get
            {
                string name = Selected != null ? Selected.Title : "game";
                var bad = Path.GetInvalidFileNameChars();
                name = new string(name.Select(ch => bad.Contains(ch) ? '_' : ch).ToArray()).Trim();
                if (name.Length == 0) name = "game";
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
            lblEmail.Location = new Point(16, 46);
            email.SetBounds(16, 64, 408, 26);
            lblPass.Location = new Point(16, 94);
            pass.SetBounds(16, 112, 408, 26);
            login.SetBounds(16, 146, 408, 28);
            logout.SetBounds(344, 12, 80, 26);
            games.SetBounds(16, 52, 408, 26);
            install.SetBounds(16, 92, 200, 38);
            pause.SetBounds(224, 92, 100, 38);
            play.SetBounds(332, 92, 92, 38);
            bar.SetBounds(16, 148, 408, 18);
            status.SetBounds(16, 178, 408, 80);

            Controls.AddRange(new Control[] { title, lblEmail, email, lblPass, pass, login, logout, games, install, pause, play, bar, status });

            login.Click += async (s, e) => await DoLogin();
            pass.KeyDown += async (s, e) =>
            {
                if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; await DoLogin(); }
            };
            logout.Click += (s, e) => { Api.Logout(); games.Items.Clear(); gameList.Clear(); status.Text = ""; ShowState(); };
            games.SelectedIndexChanged += (s, e) => ShowState();
            install.Click += async (s, e) => await DoInstall();
            pause.Click += (s, e) => { if (cts != null) cts.Cancel(); };
            play.Click += (s, e) => DoPlay();

            Shown += async (s, e) =>
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
            title.Visible = true;
            lblEmail.Visible = email.Visible = lblPass.Visible = pass.Visible = login.Visible = !inn;
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
                foreach (GameInfo g in gameList)
                    games.Items.Add(g.Title + "  (" + (g.Size / 1048576.0).ToString("F0") + " MB)");
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
            if (Selected == null) return;
            cts = new CancellationTokenSource();
            install.Enabled = logout.Enabled = play.Enabled = games.Enabled = false;
            pause.Enabled = true;
            var progress = new Progress<ProgressInfo>(p =>
            {
                bar.Value = p.Total <= 0 ? 0 : (int)Math.Min(1000L, p.Done * 1000L / p.Total);
                status.Text = p.Text;
            });
            try
            {
                string root = Root;
                Directory.CreateDirectory(root);
                await new Installer(root, Selected.Id).RunAsync(progress, cts.Token);
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
            InstallInfo info = Installer.ReadInfo(Root);
            if (info == null) return;
            string gameDir = Path.GetFullPath(Path.Combine(Root, "game"));
            string exe = Path.GetFullPath(Path.Combine(gameDir, info.Exe));
            if (!exe.StartsWith(gameDir, StringComparison.OrdinalIgnoreCase) || !File.Exists(exe))
            {
                status.Text = "Oyun dosyası bulunamadı. Tekrar kur.";
                return;
            }
            Process.Start(new ProcessStartInfo(exe) { WorkingDirectory = Path.GetDirectoryName(exe), UseShellExecute = true });
        }
    }

    static class Program
    {
        [STAThread]
        static void Main()
        {
            ServicePointManager.DefaultConnectionLimit = 16;
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}
