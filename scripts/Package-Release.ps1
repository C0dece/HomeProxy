param(
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [Parameter(Mandatory)][ValidatePattern('^[\w.-]+/[\w.-]+$')][string]$Repository,
    [Parameter(Mandatory)][string]$WindowsPayload,
    [Parameter(Mandatory)][string]$AndroidPayload,
    [Parameter(Mandatory)][string]$ReleasePrivateKey,
    [Parameter(Mandatory)][string]$ReleasePublicKey,
    [Parameter(Mandatory)][string]$BrowserPrivateKey,
    [Parameter(Mandatory)][string]$Aapt,
    [string]$OpenSsl = 'openssl.exe',
    [string]$OutputDirectory = 'dist/publish'
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Use a new output directory.' }
$out = (New-Item -ItemType Directory -Path $OutputDirectory).FullName
$windows = (Resolve-Path -LiteralPath $WindowsPayload).Path
$android = (Resolve-Path -LiteralPath $AndroidPayload).Path
$assets = "https://github.com/$Repository/releases/download/v$Version"
$notes = "HomeProxy $Version"
$installer = 'homeproxy-windows-x64-setup.exe'
$original = Join-Path $windows "HomeProxy Agent_${Version}_x64-setup.exe"
Copy-Item -LiteralPath $original -Destination (Join-Path $out $installer)
Copy-Item -LiteralPath "$original.sig" -Destination (Join-Path $out "$installer.sig")
Copy-Item -LiteralPath (Join-Path $windows 'homeproxy-server.exe') -Destination (Join-Path $out 'homeproxy-server-windows-amd64.exe')
Copy-Item -LiteralPath (Join-Path $windows 'homeproxy-verify-release.exe') -Destination $out
Copy-Item -LiteralPath $ReleasePublicKey -Destination (Join-Path $out 'release-public.pem')

@{
    version = $Version; apiMin = 1; apiMax = 1; notes = $notes
    platforms = @{'windows-x86_64' = @{ url = "$assets/$installer"; signature = (Get-Content -LiteralPath "$original.sig" -Raw).Trim() }}
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $out 'windows-stable.json') -Encoding utf8NoBOM

function Get-Artifact([string]$File, [string]$Component, [string]$Platform, [string]$Arch) {
    $item = Get-Item -LiteralPath (Join-Path $out $File)
    return @{
        component = $Component; channel = 'stable'; version = $Version; platform = $Platform; arch = $Arch
        url = "$assets/$File"; size = $item.Length; sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        apiMin = 1; apiMax = 1; dbSchema = 3; notes = $notes
    }
}

$artifacts = @(Get-Artifact 'homeproxy-server-windows-amd64.exe' 'server' 'windows' 'amd64')
foreach ($arch in @('aarch64', 'x86_64')) {
    $file = "homeproxy-android-$arch.apk"
    Copy-Item -LiteralPath (Join-Path $android $file) -Destination $out
    $metadata = & $Aapt dump badging (Join-Path $out $file) | Select-Object -First 1
    if ($metadata -notmatch "versionCode='([0-9]+)' versionName='([^']+)'" -or $Matches[2] -ne $Version) {
        throw "Android APK version mismatch for $arch."
    }
    $artifact = Get-Artifact $file 'agent' 'android' $arch
    $artifact.versionCode = [long]$Matches[1]
    $artifacts += $artifact
}

$manifest = Join-Path $out 'release.json'
@{format=1; artifacts=$artifacts} | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $manifest -Encoding utf8NoBOM
$signature = Join-Path $out 'release.signature.bin'
try {
    & $OpenSsl pkeyutl -sign -rawin -inkey $ReleasePrivateKey -in $manifest -out $signature
    [Convert]::ToBase64String([IO.File]::ReadAllBytes($signature)) | Set-Content -LiteralPath (Join-Path $out 'release.sig') -Encoding Ascii
    foreach ($entry in $artifacts) {
        $file = (Split-Path $entry.url -Leaf)
        $verified = Join-Path $out ".$file.verified"
        & (Join-Path $out 'homeproxy-verify-release.exe') -manifest $manifest -signature (Join-Path $out 'release.sig') `
            -public-key $ReleasePublicKey -package (Join-Path $out $file) -out $verified `
            -component $entry.component -platform $entry.platform -arch $entry.arch -current 0.0.0
        Remove-Item -LiteralPath $verified
    }
} finally { Remove-Item -LiteralPath $signature -ErrorAction SilentlyContinue }

$oldVersion = $env:HOMEPROXY_RELEASE_VERSION
$oldBrowserUrl = $env:HOMEPROXY_BROWSER_UPDATE_URL
try {
    $env:HOMEPROXY_RELEASE_VERSION = $Version
    $env:HOMEPROXY_BROWSER_UPDATE_URL = "https://github.com/$Repository/releases/latest/download/browser-update.xml"
    npm.cmd run build:browser
} finally {
    $env:HOMEPROXY_RELEASE_VERSION = $oldVersion
    $env:HOMEPROXY_BROWSER_UPDATE_URL = $oldBrowserUrl
}
$browserZip = Join-Path $out 'homeproxy-browser.zip'
Compress-Archive -Path 'dist/browser/*' -DestinationPath $browserZip
node scripts/pack-browser.mjs $browserZip $BrowserPrivateKey (Join-Path $out 'homeproxy-browser.crx') `
    (Join-Path $out 'browser-update.xml') $Version "$assets/homeproxy-browser.crx"

$serverZip = Join-Path $out 'homeproxy-server-windows-amd64.zip'
Compress-Archive -LiteralPath @((Join-Path $windows 'homeproxy-server.exe'), (Join-Path $windows 'sing-box.exe'), `
    (Join-Path $windows 'sing-box-license.txt'), (Join-Path $windows 'admin'), (Join-Path $out 'homeproxy-verify-release.exe'), `
    (Join-Path $out 'release-public.pem'), 'docs/server.example.json', 'scripts/Update-ServerFromGitHub.ps1', 'scripts/Install-ServerService.ps1') -DestinationPath $serverZip
