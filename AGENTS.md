# HomeProxy

- Windows x64: scripts/Install-DevTools.ps1 устанавливает проверенные Go и sing-box в .tools, scripts/Build.ps1 создаёт dist, scripts/Test.ps1 выполняет статические и сквозные проверки.
- Изолированный сценарий в tests/windows-integration.py. Параметр Test.ps1 -Browser дополнительно проверяет Chromium и записывает снимки экранов в dist/qa. Обычный Agent и Browser QA используют одни и те же loopback-порты, поэтому запускаются отдельно.
- Windows Agent по умолчанию использует прикладной прокси. Режим serve --tun и тест --tun-vm запускать только в отдельно разрешённой VM. Не добавлять скрытый DIRECT при исчерпании PROXY. LOCAL_DIRECT и SERVER_DIRECT используют разные выходы.
- Правила по EXE проверять двумя разными процессами на одном порту прокси. Для обновления сервера go test запускает реальные сборки на loopback без регистрации службы Windows.
- Встроенный серверный и клиентский транспорт использует sing-box. Изменения конфигурации проверять настоящим HTTP-запросом и сценарием отказа. Настройки Lenovo, системные маршруты и брандмауэр проверять только в отдельно разрешённой среде.
- Android: scripts/Build-Android.ps1 создаёт APK для указанного ABI. tests/android-integration.py выполняет VPN-сценарий на отдельном эмуляторе HomeProxy_QA_*. Команда запуска в docs/DEVELOPMENT.md.
