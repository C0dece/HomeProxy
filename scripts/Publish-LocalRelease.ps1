param(
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [ValidatePattern('^[\w.-]+/[\w.-]+$')][string]$Repository = 'C0dece/HomeProxy',
    [string]$KeysDir = 'keys',
    [string]$Sdk = $env:ANDROID_HOME,
    [string]$Ndk = $env:NDK_HOME,
    [switch]$Draft,
    [switch]$SkipUpload
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$project = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

Push-Location $project
$prevTauriKey = [Environment]::GetEnvironmentVariable('TAURI_SIGNING_PRIVATE_KEY', 'Process')
$prevAndroidPwd = [Environment]::GetEnvironmentVariable('HOMEPROXY_ANDROID_KEY_PASSWORD', 'Process')
try {
    if (!$Version) {
        $versionFile = Join-Path $project 'VERSION'
        if (!(Test-Path -LiteralPath $versionFile -PathType Leaf)) {
            throw 'Supply -Version or create VERSION file in the repository root.'
        }
        $Version = (Get-Content -LiteralPath $versionFile -Raw).Trim()
        if ($Version -notmatch '^\d+\.\d+\.\d+$') {
            throw "Invalid version in VERSION file: $Version"
        }
    }

    $keysRoot = if ([IO.Path]::IsPathRooted($KeysDir)) { $KeysDir } else { Join-Path $project $KeysDir }
    $winKey = Join-Path $keysRoot 'windows-signing.key'
    $winPub = Join-Path $keysRoot 'windows-signing.pub'
    $relPriv = Join-Path $keysRoot 'release-private.pem'
    $relPub = Join-Path $keysRoot 'release-public.pem'
    $browserPriv = Join-Path $keysRoot 'browser-private.pem'
    $androidStore = Join-Path $keysRoot 'android.p12'
    $androidPwdFile = Join-Path $keysRoot 'android-password.txt'

    $missing = @()
    foreach ($file in @($winKey, $winPub, $relPriv, $relPub, $browserPriv, $androidStore)) {
        if (!(Test-Path -LiteralPath $file -PathType Leaf)) {
            $missing += $file
        }
    }
    $androidPassword = $env:HOMEPROXY_ANDROID_KEY_PASSWORD
    if ([string]::IsNullOrWhiteSpace($androidPassword) -and (Test-Path -LiteralPath $androidPwdFile -PathType Leaf)) {
        $androidPassword = (Get-Content -LiteralPath $androidPwdFile -Raw).Trim()
    }
    if ([string]::IsNullOrWhiteSpace($androidPassword)) {
        $missing += "$androidPwdFile (or env HOMEPROXY_ANDROID_KEY_PASSWORD)"
    }
    if ($missing.Count -gt 0) {
        throw ("Missing signing keys in '$keysRoot':`n - " + ($missing -join "`n - "))
    }

    if (!$Sdk -and (Test-Path -LiteralPath 'D:\Dev\SDKs\Android')) { $Sdk = 'D:\Dev\SDKs\Android' }
    if (!$Ndk) { $Ndk = Join-Path $project '.tools/android/android-ndk-r30' }
    $aapt = Get-ChildItem (Join-Path $Sdk 'build-tools') -Filter aapt2.exe -File -Recurse -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
    if (!$aapt) { throw "Could not find aapt2.exe under '$Sdk\build-tools'." }

    $ssl = 'C:\Program Files\Git\usr\bin\openssl.exe'
    if (!(Test-Path -LiteralPath $ssl -PathType Leaf)) {
        $ssl = (Get-Command openssl.exe -ErrorAction Stop).Source
    }

    if (!$SkipUpload) {
        $latestTag = gh release list --limit 1 --exclude-drafts --exclude-pre-releases --json tagName --jq '.[0].tagName'
        if ($latestTag -and [version]$Version -le [version]$latestTag.TrimStart('v')) {
            throw "Release version $Version must be greater than latest published $latestTag."
        }
    }

    $stageRoot = Join-Path $project "dist/local-release-$Version"
    if (Test-Path -LiteralPath $stageRoot) {
        Remove-Item -LiteralPath $stageRoot -Recurse -Force
    }
    $winDir = Join-Path $stageRoot 'windows'
    $androidDir = Join-Path $stageRoot 'android'
    $publishDir = Join-Path $stageRoot 'publish'

    $feed = "https://github.com/$Repository/releases/latest/download"
    $env:TAURI_SIGNING_PRIVATE_KEY = (Get-Content -LiteralPath $winKey -Raw).Trim()
    $env:HOMEPROXY_ANDROID_KEY_PASSWORD = $androidPassword.Trim()

    Write-Host "[1/4] Building signed Windows artifacts ($Version)..."
    & (Join-Path $PSScriptRoot 'Build.ps1') -Installer -Version $Version -WindowsDirectory $winDir `
        -WindowsUpdateEndpoint "$feed/windows-{channel}.json" -WindowsUpdatePublicKey $winPub
    Copy-Item dist/homeproxy-server.exe, dist/homeproxy-verify-release.exe -Destination $winDir
    Copy-Item dist/admin -Destination $winDir -Recurse

    foreach ($arch in @('aarch64', 'x86_64')) {
        Write-Host "[2/4] Building signed Android APK ($arch)..."
        & (Join-Path $PSScriptRoot 'Build-Android.ps1') -Target $arch -Sdk $Sdk -Ndk $Ndk -Version $Version `
            -SigningKeystore $androidStore -OutputDirectory $androidDir -ReleasePublicKey $relPub `
            -UpdateManifest "$feed/release.json" -UpdateSignature "$feed/release.sig"
    }

    Write-Host "[3/4] Packaging signed release bundle..."
    & (Join-Path $PSScriptRoot 'Package-Release.ps1') -Version $Version -Repository $Repository `
        -WindowsPayload $winDir -AndroidPayload $androidDir -ReleasePrivateKey $relPriv `
        -ReleasePublicKey $relPub -BrowserPrivateKey $browserPriv -Aapt $aapt -OpenSsl $ssl `
        -OutputDirectory $publishDir

    if ($SkipUpload) {
        Write-Host "Release bundle ready (upload skipped): $publishDir"
        return
    }

    Write-Host "[4/4] Uploading release v$Version to GitHub..."
    $tag = "v$Version"
    $headSha = (git rev-parse HEAD).Trim()
    $files = @(Get-ChildItem -LiteralPath $publishDir -File | ForEach-Object FullName)
    gh release create $tag @files --draft --target $headSha --title "HomeProxy $Version" --generate-notes
    if (!$Draft) {
        gh release edit $tag --draft=false --latest
    }
    Write-Host "Published release $tag from local build."
} finally {
    [Environment]::SetEnvironmentVariable('TAURI_SIGNING_PRIVATE_KEY', $prevTauriKey, 'Process')
    [Environment]::SetEnvironmentVariable('HOMEPROXY_ANDROID_KEY_PASSWORD', $prevAndroidPwd, 'Process')
    Pop-Location
}
