param(
    [string]$Go = 'go.exe',
    [string]$WindowsDirectory = 'dist/windows',
    [switch]$Installer,
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [string]$WindowsUpdateEndpoint,
    [string]$WindowsUpdatePublicKey
)

$ErrorActionPreference = 'Stop'
function Invoke-BuildStep([scriptblock]$Step) {
    & $Step
    if ($LASTEXITCODE -ne 0) { throw "Build step exited with code $LASTEXITCODE" }
}

$oldEndpoint = $env:HOMEPROXY_WINDOWS_UPDATE_ENDPOINT
$oldKey = $env:HOMEPROXY_WINDOWS_UPDATE_KEY
$oldTauri = $env:TAURI_CONFIG
$oldReleaseVersion = $env:HOMEPROXY_RELEASE_VERSION
$updatePublicKey = $null
if ($WindowsUpdateEndpoint -or $WindowsUpdatePublicKey) {
    if (!$Installer -or !$WindowsUpdateEndpoint -or !$WindowsUpdatePublicKey -or !$env:TAURI_SIGNING_PRIVATE_KEY) {
        throw 'Signed Windows updates require Installer, both WindowsUpdate parameters and TAURI_SIGNING_PRIVATE_KEY.'
    }
    $releaseUri = [uri]$WindowsUpdateEndpoint.Replace('{channel}', 'stable')
    if (!$releaseUri.IsAbsoluteUri -or $releaseUri.Scheme -ne 'https' -or $releaseUri.UserInfo) {
        throw 'Use an HTTPS Windows release endpoint.'
    }
    $updatePublicKey = (Get-Content -LiteralPath $WindowsUpdatePublicKey -Raw).Trim()
}
Push-Location (Join-Path $PSScriptRoot '..')
try {
    $env:HOMEPROXY_WINDOWS_UPDATE_ENDPOINT = $WindowsUpdateEndpoint
    $env:HOMEPROXY_WINDOWS_UPDATE_KEY = $updatePublicKey
    if ($Version) {
        $env:TAURI_CONFIG = @{ version = $Version } | ConvertTo-Json -Compress
        $env:HOMEPROXY_RELEASE_VERSION = $Version
    }
    if ($Go -eq 'go.exe' -and (Test-Path -LiteralPath '.tools/go/bin/go.exe')) {
        $Go = (Resolve-Path -LiteralPath '.tools/go/bin/go.exe').Path
    }
    Invoke-BuildStep { npm.cmd ci --no-audit --no-fund }
    Invoke-BuildStep { npm.cmd run build }
    $serverArgs = @('build', '-mod=readonly', '-trimpath', '-o', 'dist/homeproxy-server.exe')
    if ($Version) { $serverArgs += "-ldflags=-X main.releaseVersion=$Version" }
    Invoke-BuildStep { & $Go @serverArgs ./apps/server }
    Invoke-BuildStep { & $Go build -mod=readonly -trimpath -o dist/homeproxy-verify-release.exe ./updater/server }
    Invoke-BuildStep { cargo build --release --locked -p homeproxy-agent -p homeproxy-desktop }
    New-Item -ItemType Directory -Path $WindowsDirectory -Force | Out-Null
    Copy-Item -LiteralPath 'target/release/homeproxy-agent.exe','target/release/homeproxy-desktop.exe' -Destination $WindowsDirectory -Force
    if ($Installer) {
        $tauri = (Resolve-Path -LiteralPath 'node_modules/.bin/tauri.cmd').Path
        $binaries = 'apps/client/src-tauri/binaries'
        New-Item -ItemType Directory -Path $binaries -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $WindowsDirectory 'homeproxy-agent.exe') -Destination (Join-Path $binaries 'homeproxy-agent-x86_64-pc-windows-msvc.exe') -Force
        $core = (Resolve-Path '.tools/sing-box-1.14.4-windows-amd64').Path
        Copy-Item -LiteralPath (Join-Path $core 'sing-box.exe') -Destination (Join-Path $binaries 'sing-box-x86_64-pc-windows-msvc.exe') -Force
        Copy-Item -LiteralPath (Join-Path $core 'LICENSE') -Destination (Join-Path $binaries 'sing-box-license.txt') -Force
        Copy-Item -LiteralPath (Join-Path $core 'sing-box.exe') -Destination $WindowsDirectory -Force
        Copy-Item -LiteralPath (Join-Path $core 'LICENSE') -Destination (Join-Path $WindowsDirectory 'sing-box-license.txt') -Force
        $bundleArgs = @('bundle', '--config', 'src-tauri/tauri.bundle.conf.json', '--bundles', 'nsis', '--ci')
        if ($updatePublicKey -or $Version) {
            $release = (New-Item -ItemType Directory -Force .homeproxy/windows).FullName
            $bundleConfig = Join-Path $release 'updater-bundle.json'
            $config = @{}
            if ($Version) { $config.version = $Version }
            if ($updatePublicKey) {
                $config.bundle = @{ createUpdaterArtifacts = $true }
                $config.plugins = @{ updater = @{ pubkey = $updatePublicKey } }
            }
            $config | ConvertTo-Json -Depth 5 -Compress | Set-Content -LiteralPath $bundleConfig -Encoding utf8NoBOM
            $bundleArgs += @('--config', $bundleConfig)
        }
        if (!$updatePublicKey) { $bundleArgs += '--no-sign' }
        Push-Location 'apps/client'
        try { Invoke-BuildStep { & $tauri @bundleArgs } }
        finally { Pop-Location }
        $appVersion = if ($Version) { $Version } else {
            (Get-Content -LiteralPath 'apps/client/src-tauri/tauri.conf.json' -Raw | ConvertFrom-Json).version
        }
        $setup = Get-ChildItem -LiteralPath 'target/release/bundle/nsis' -Filter ('*_{0}_x64-setup.exe' -f $appVersion) | Select-Object -First 1
        if (!$setup) { throw 'Tauri did not produce an NSIS installer' }
        Copy-Item -LiteralPath $setup.FullName -Destination $WindowsDirectory -Force
        if ($updatePublicKey) {
            Copy-Item -LiteralPath "$($setup.FullName).sig" -Destination $WindowsDirectory -Force
        }
    }
} finally {
    Pop-Location
    $env:HOMEPROXY_WINDOWS_UPDATE_ENDPOINT = $oldEndpoint
    $env:HOMEPROXY_WINDOWS_UPDATE_KEY = $oldKey
    $env:TAURI_CONFIG = $oldTauri
    $env:HOMEPROXY_RELEASE_VERSION = $oldReleaseVersion
}
