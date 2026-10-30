# STRUD: oyun dağıtımı (siteye uyarlanmış)

## Ne değişti
- **site/index.html**: Oyun yayınlama yine sitede, sadece kurucu. Ama artık seçtiğin ZIP tarayıcında 32 MB'lık parçalara
  bölünüp **AES-256-GCM ile şifreleniyor** ve private `games` bucket'ına yükleniyor. Anahtar + parça yolları
  `game_secrets` tablosuna gidiyor (sadece kurucu ve Edge Function görür). `games` tablosunda artık dosya URL'si yok.
- Sitede oyun kartlarında "indir" butonu yok; sadece **STRUD Downloader'ı İndir** butonu var.
- **Edge Function**: giriş doğrular, günlük limit uygular (10), 1 saatlik imzalı bağlantı + anahtar verir.
- **Downloader**: oyun listesi, indirme (4 paralel), duraklat/devam, SHA-256 + GCM doğrulama, birleştirme, açma, Oyna.

## Kurulum (sırayla)
1. `supabase/setup.sql`'i SQL Editor'de çalıştır. Adım 2'deki sorgu eski policy'leri listeler; çıkanları
   `drop policy "ADI" on storage.objects;` ile sil. (Bunu yapmazsan eski bir policy bucket'ı açık bırakabilir.)
2. Fonksiyonu yayınla: `supabase functions deploy strud-download` (ekstra secret gerekmiyor).
3. **Siteyi güncelle**: `site/index.html`'i yükle.
4. **Eski yayınları sil**: Eski yöntemle yüklenmiş oyunlar "ESKİ YAYIN" etiketiyle görünür, dosya URL'leri `games`
   tablosunda duruyor. Sil (site silerken dosyaları da kaldırır) ve oyunu yeniden yayınla.
5. Oyunu siteden yayınla: ZIP seç + "ZIP içindeki exe yolu" alanına örn. `AroundNature.exe` yaz.
6. **Downloader'ı derle.** Kolay yol (bilgisayarına bir şey kurmadan): bu klasörü bir GitHub deposuna yükle →
   Actions → "Build STRUD Downloader" → Run workflow → bitince Artifacts'tan `STRUD-Downloader.exe`'yi indir.
   Ya da Windows'ta .NET 8 SDK ile `downloader/build.bat`. URL ve anon key zaten içinde.
   Çıkan `publish/STRUD-Downloader.exe` dosyasını Supabase → Storage → **downloader** bucket'ına yükle
   (setup.sql oluşturdu). Sitedeki buton buraya bağlı.

## Sınırlar
- Dosyalar kullanıcının diskine indiğinde okunabilir (Steam'de de). Anahtar indirme sırasında Downloader'ın
  belleğinde durur. Koruma, "dosyaları herkes bulamasın, sadece hesaplı kullanıcı alsın" seviyesindedir.
- Tek ZIP dosyası desteklenir (birden fazla seçersen ilki alınır). Windows SmartScreen imzasız exe için uyarı verebilir.
- Tarayıcıdan yüklerken şifreleme her parça için ~100 MB bellek kullanır, 4 GB'a kadar oyunlarda sorun olmaz.
