# TurboAntivirus

Windows için yerel dosya tarama ve karantina uygulaması.

## Özellikler
- SHA-256 tabanlı bilinen imza kontrolü
- EICAR test dosyası algılama
- PowerShell encoded-command için muhafazakâr şüpheli desen kontrolü
- Dosya ve klasör taraması
- Gerçek zamanlı kullanıcı klasörü izleme
- Karantina
- WinForms GUI
- Tek dosya Windows EXE GitHub Actions ile otomatik üretilir

> Bu proje Microsoft Defender'ın yerine geçmez. İkinci görüş/yerel tarama aracı olarak kullanılmalıdır. Tespit kapsamı sınırlıdır; bilinmeyen tüm malware'leri yakaladığı garanti edilmez.

## EICAR testi
EICAR test dosyasını yalnızca antivirüs test etmek için kullanın. Gerçek zararlı değildir; güvenlik yazılımlarının algılama davranışını test etmek için standart bir test imzasıdır.

## Build
`dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true`
