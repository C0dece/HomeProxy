# HomeProxy

Локально проверенная сборка для Windows x64. Agent принимает трафик приложений на HTTP/SOCKS-прокси. В профиле AUTO он сначала подключается к HomeProxy Server по VLESS + REALITY, затем использует выданные сервером HTTP CONNECT в порядке приоритета. Если все маршруты PROXY недоступны, соединение отклоняется.

```powershell
.\scripts\Install-DevTools.ps1
.\scripts\Build.ps1 -Installer
.\scripts\Test.ps1
```

Тест поднимает временные сервер, HTTP CONNECT и Agent. Для проверки интерфейсов и расширения доступен параметр Test.ps1 -Browser. [Разработка](docs/DEVELOPMENT.md)

Для ручной работы запустите scripts/Dev.ps1 из PowerShell. Он выводит адрес Admin, тестовый ключ и параметры изолированного агента.

В Admin создайте пользователя, добавьте HTTP CONNECT, назначьте его пользователю и выдайте ссылку. Запустите Agent и вставьте эту ссылку. Настройте приложению прокси 127.0.0.1:17770. Расширению выдайте отдельную ссылку Browser за того же пользователя.

[Развёртывание](docs/DEPLOYMENT.md) | [Архитектура](docs/ARCHITECTURE.md) | [Проверки](docs/TESTING.md) | [Безопасность](docs/SECURITY.md) | [Обновления](docs/UPDATES.md)
