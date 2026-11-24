param(
    [string]$SingBox = '.tools/sing-box-1.14.4-windows-amd64/sing-box.exe',
    [string]$Python = 'python.exe',
    [string]$OpenSsl = 'C:\Program Files\Git\usr\bin\openssl.exe',
    [string]$WindowsDirectory = 'dist/windows'
)

Push-Location (Join-Path $PSScriptRoot '..')
try {
    if ($Python -eq 'python.exe' -and (Test-Path -LiteralPath '.tools/python/python.exe')) {
        $Python = (Resolve-Path -LiteralPath '.tools/python/python.exe').Path
    }
    & $Python tests/windows-integration.py --server dist/homeproxy-server.exe --agent (Join-Path $WindowsDirectory 'homeproxy-agent.exe') --sing-box $SingBox --openssl $OpenSsl --admin-dir dist/admin --serve
    if ($LASTEXITCODE -ne 0) { throw "Development session exited with code $LASTEXITCODE" }
} finally {
    Pop-Location
}
