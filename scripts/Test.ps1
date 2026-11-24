param(
    [string]$Go = 'go.exe',
    [string]$SingBox = '.tools/sing-box-1.14.4-windows-amd64/sing-box.exe',
    [string]$Python = 'python.exe',
    [string]$OpenSsl = 'C:\Program Files\Git\usr\bin\openssl.exe',
    [string]$WindowsDirectory = 'dist/windows',
    [switch]$Browser
)

$ErrorActionPreference = 'Stop'
function Invoke-TestStep([scriptblock]$Step) {
    & $Step
    if ($LASTEXITCODE -ne 0) { throw "Test step exited with code $LASTEXITCODE" }
}

Push-Location (Join-Path $PSScriptRoot '..')
$previousTestSingBox = [Environment]::GetEnvironmentVariable('HOMEPROXY_TEST_SINGBOX')
try {
    if ($Go -eq 'go.exe' -and (Test-Path -LiteralPath '.tools/go/bin/go.exe')) {
        $Go = (Resolve-Path -LiteralPath '.tools/go/bin/go.exe').Path
    }
    if ($Python -eq 'python.exe' -and (Test-Path -LiteralPath '.tools/python/python.exe')) {
        $Python = (Resolve-Path -LiteralPath '.tools/python/python.exe').Path
    }
    $env:HOMEPROXY_TEST_SINGBOX = (Resolve-Path -LiteralPath $SingBox).Path
    Invoke-TestStep { & $Go test -mod=readonly ./... }
    Invoke-TestStep { & $Go vet -mod=readonly ./... }
    Invoke-TestStep { npm.cmd run check }
    Invoke-TestStep { cargo fmt --all -- --check }
    Invoke-TestStep { cargo clippy --release --locked -p homeproxy-agent -p homeproxy-desktop --all-targets -- -D warnings }
    $arguments = @('tests/windows-integration.py', '--server', 'dist/homeproxy-server.exe', '--agent', (Join-Path $WindowsDirectory 'homeproxy-agent.exe'),
        '--sing-box', $SingBox, '--openssl', $OpenSsl, '--admin-dir', 'dist/admin')
    if ($Browser) { $arguments += @('--browser-qa', 'tests/browser-qa.mjs') }
    Invoke-TestStep { & $Python @arguments }
} finally {
    [Environment]::SetEnvironmentVariable('HOMEPROXY_TEST_SINGBOX', $previousTestSingBox)
    Pop-Location
}
