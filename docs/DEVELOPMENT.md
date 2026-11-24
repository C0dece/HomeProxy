# Разработка

Нужны Node.js 24, Rust MSVC, Visual Studio Build Tools, Windows SDK и WebView2. Для тестов нужны Python 3 и OpenSSL. Go 1.27.4 и sing-box 1.14.4 скрипт Install-DevTools.ps1 загружает в .tools и сверяет SHA-256. Остальные зависимости зафиксированы в Cargo.lock, go.sum и package-lock.json.

```powershell
.\scripts\Install-DevTools.ps1
.\scripts\Build.ps1 -Installer
.\scripts\Test.ps1
npm.cmd install --no-save --package-lock=false playwright@1.65.1
npx.cmd playwright install chromium
.\scripts\Test.ps1 -Browser
```

Укажите параметры Go, SingBox, Python и OpenSsl, если инструменты расположены в другом месте. Browser QA использует порты локального Agent, поэтому его нужно запускать отдельно от обычного Agent. Можно указать путь к Chromium в HOMEPROXY_CHROMIUM. Изолированный профиль удаляется после выхода. Изображения сохраняются в dist/qa.

Для сетевой проверки Windows TUN передайте tests/windows-integration.py флаг --tun-vm из повышенного терминала выделенной VM. Сценарий проверяет прозрачный HTTP, DNS, IPv4, IPv6, правило EXE и резервный маршрут.

Чтобы также проверить постоянные фильтры WFP, добавьте `--strict-vm --strict-dns <IPv4 DNS-сервера гостевой VM>`. Тест проверяет прямой IPv4 и UDP DNS до включения защиты, после принудительной остановки ядра и контроллера и после снятия фильтров. Сценарий снимает фильтры HomeProxy при завершении. Для ручного восстановления выполните `homeproxy-agent.exe firewall-reset` из повышенного терминала VM после завершения контроллера.

Флаг `--strict-named-api` проверяет начальное подключение, синхронизацию и резервный HTTP-прокси по доменному имени. Тесту нужны доступ к Quad9 по HTTPS и публичная запись `127-0-0-1.sslip.io`, которая указывает на loopback. Тест добавляет отдельный CA для локального HTTPS и удаляет его при завершении.

Если переносимый Agent запущен из dist/windows, задайте отдельный WindowsDirectory при сборке, тестировании и запуске Dev.ps1. Например, используйте dist/windows/0.1.1. Сборка в отдельный каталог сохраняет исполняемые файлы запущенного агента.

Для отладки контроллер поддерживает команды serve и ctl. Параметры --data, --port и --proxy-port позволяют разделить тестовое и рабочее состояние. HTTP разрешается только для 127.0.0.1 и при явном флаге --allow-loopback-http.

scripts/Dev.ps1 запускает изолированный сервер, тестовые прокси, Admin и Agent для ручной отладки. Скрипт выводит URL Admin, временный ключ, путь состояния и порт контроллера. Создайте ссылку Agent в Admin и передайте её через homeproxy-agent.exe ctl --data <каталог> --port <порт> --command connect --json <объект с полем link>. Нажатие Enter останавливает процессы и удаляет тестовые данные.

[Требования Tauri](https://v2.tauri.app/start/prerequisites/) | [Выпуск sing-box](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4)

## Android

Сборка использует Android SDK Platform 36, JDK 17, NDK r30 и Rust target x86_64-linux-android или aarch64-linux-android. Укажите SDK и распакованный NDK параметрами Sdk и Ndk, если они находятся вне стандартных каталогов проекта.

```powershell
rustup target add x86_64-linux-android aarch64-linux-android
.\scripts\Build-Android.ps1 -Target x86_64
.\scripts\Build-Android.ps1 -Target aarch64
```

Скрипт собирает libbox из проверенной ревизии sing-box 1.14.4, создаёт проект Android Tauri и копирует APK в dist/android. Сборка отладочная. Проверка в tests/android-integration.py принимает только эмулятор с именем HomeProxy_QA_ и использует тестовые данные через loopback. Из JDK нужен keytool, а из Android SDK Build Tools 36.0.0 нужны aapt2 и apksigner для тестового APK. Для теста используйте сервер этой же ревизии проекта.

```powershell
python tests/android-integration.py --serial emulator-5570 `
  --adb "$env:ANDROID_HOME/platform-tools/adb.exe" --apk dist/android/homeproxy-x86_64-debug.apk `
  --server dist/homeproxy-server.exe --sing-box .tools/sing-box-1.14.4-windows-amd64/sing-box.exe
```

Добавьте --system-vpn для проверки системных переключателей, перезагрузки AVD и блокировки трафика после закрытия туннеля. Этот сценарий ищет названия переключателей в английском интерфейсе Android 14 и удаляет тестовое приложение HomeProxy при выходе, чтобы Android очистил назначение Always-on.

Флаг --network-vpn проверяет DNS, IPv6, блокировку UDP и переход на эмулированную мобильную сеть. Для проверки обновления соберите x86_64 APK 0.1.4 и 0.1.5 в разных OutputDirectory с одним тестовым открытым ключом и адресами http://127.0.0.1:18893/release.json и http://127.0.0.1:18893/release.sig. Передайте путь к APK 0.1.5 через --update-apk и путь к тестовому ключу Ed25519 через --update-key. Сценарий поднимает источник на этом порту и создаёт подписанный манифест.

Android APK включает libbox. При распространении действуют условия GPL ядра. Патч сборки отключает запись открытой конфигурации на диск при отключённых отчётах питания. [Загрузка NDK](https://developer.android.com/ndk/downloads) · [Лицензия sing-box](https://github.com/SagerNet/sing-box/blob/v1.14.4/LICENSE)
