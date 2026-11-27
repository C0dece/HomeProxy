param(
    [ValidateSet('x86_64', 'aarch64')][string]$Target = 'x86_64',
    [string]$Sdk = $env:ANDROID_HOME,
    [string]$Ndk = $env:NDK_HOME,
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [string]$OutputDirectory = 'dist/android',
    [string]$ReleasePublicKey,
    [uri]$UpdateManifest,
    [uri]$UpdateSignature,
    [string]$SigningKeystore
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$project = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (!$Version -and (Test-Path -LiteralPath (Join-Path $project 'VERSION'))) {
    $Version = (Get-Content -LiteralPath (Join-Path $project 'VERSION') -Raw).Trim()
    if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Invalid version in VERSION file: $Version" }
}
$keystore = if ($SigningKeystore) { (Resolve-Path -LiteralPath $SigningKeystore).Path }
if ($keystore -and (!$env:HOMEPROXY_ANDROID_KEY_PASSWORD -or !$Version)) {
    throw 'Set HOMEPROXY_ANDROID_KEY_PASSWORD and Version to sign an Android release.'
}
$releaseKeyPem = $null
if ($ReleasePublicKey -or $UpdateManifest -or $UpdateSignature) {
    if (!$ReleasePublicKey -or !$UpdateManifest -or !$UpdateSignature) {
        throw 'Supply ReleasePublicKey, UpdateManifest and UpdateSignature together.'
    }
    foreach ($url in @($UpdateManifest, $UpdateSignature)) {
        if (!$url.IsAbsoluteUri -or $url.UserInfo -or
            !($url.Scheme -eq 'https' -or ($url.Scheme -eq 'http' -and $url.Host -eq '127.0.0.1'))) {
            throw 'Use HTTPS for signed release sources.'
        }
    }
    $releaseKeyPem = (Get-Content -LiteralPath $ReleasePublicKey -Raw).Trim()
    if ($releaseKeyPem -notmatch '(?s)\A-----BEGIN PUBLIC KEY-----\s+[A-Za-z0-9+/=\s]+\s+-----END PUBLIC KEY-----\z' -or $releaseKeyPem.Length -gt 256) {
        throw 'Supply an Ed25519 public key in PEM format.'
    }
}
$previous = @{}
foreach ($name in @('ANDROID_HOME', 'ANDROID_NDK_HOME', 'NDK_HOME', 'JAVA_HOME', 'GOBIN', 'Path', 'CARGO_BUILD_JOBS', 'CARGO_PROFILE_DEV_DEBUG')) {
    $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
Push-Location $project
try {
    if (!$Sdk -and (Test-Path -LiteralPath 'D:\Dev\SDKs\Android')) { $Sdk = 'D:\Dev\SDKs\Android' }
    if (!$Ndk) { $Ndk = Join-Path $project '.tools/android/android-ndk-r30' }
    if (!$Sdk -or !(Test-Path -LiteralPath (Join-Path $Sdk 'platform-tools/adb.exe'))) { throw 'Set ANDROID_HOME to the Android SDK directory.' }
    if (!(Test-Path -LiteralPath (Join-Path $Sdk 'platforms/android-36/android.jar'))) { throw 'Install Android SDK Platform 36.' }
    if (!(Test-Path -LiteralPath (Join-Path $Ndk 'source.properties'))) { throw 'Set NDK_HOME to the extracted Android NDK.' }
    $env:ANDROID_HOME = (Resolve-Path -LiteralPath $Sdk).Path
    $env:NDK_HOME = (Resolve-Path -LiteralPath $Ndk).Path
    $env:ANDROID_NDK_HOME = $env:NDK_HOME
    if (!$env:CARGO_BUILD_JOBS) { $env:CARGO_BUILD_JOBS = '2' }
    if (!$env:CARGO_PROFILE_DEV_DEBUG) { $env:CARGO_PROFILE_DEV_DEBUG = '0' }
    if (!$env:JAVA_HOME) { $env:JAVA_HOME = Split-Path (Split-Path (Get-Command java.exe).Source) }
    $tools = (New-Item -ItemType Directory -Path '.tools/android' -Force).FullName
    $env:GOBIN = (New-Item -ItemType Directory -Path (Join-Path $tools 'bin') -Force).FullName
    $go = if (Test-Path -LiteralPath '.tools/go/bin/go.exe') { (Resolve-Path '.tools/go/bin/go.exe').Path } else { (Get-Command go.exe).Source }
    $env:Path = (Split-Path $go) + ';' + $env:GOBIN + ';' + $env:Path
    $mobile = Join-Path $env:GOBIN 'gomobile.exe'
    $bind = Join-Path $env:GOBIN 'gobind.exe'
    if (!(Test-Path -LiteralPath $mobile) -or !(Test-Path -LiteralPath $bind)) {
        & $go install github.com/sagernet/gomobile/cmd/gomobile@v0.1.12 github.com/sagernet/gomobile/cmd/gobind@v0.1.12
    }
    $source = Join-Path $tools 'sing-box'
    if (!(Test-Path -LiteralPath (Join-Path $source '.git'))) {
        git clone --quiet --depth 1 --branch v1.14.4 https://github.com/SagerNet/sing-box.git $source
    }
    if ((git -C $source rev-parse HEAD) -ne 'c005f35300ce76427dc285481ec5695f5b179cd2') { throw 'Unexpected sing-box source revision.' }
    $patch = (Resolve-Path 'native/android/libbox-private-config.patch').Path
    $PSNativeCommandUseErrorActionPreference = $false
    git -C $source apply --unidiff-zero --reverse --check $patch 2>$null
    $alreadyPatched = $LASTEXITCODE -eq 0
    $PSNativeCommandUseErrorActionPreference = $true
    if (!$alreadyPatched) { git -C $source apply --unidiff-zero $patch }
    $binding = if ($Target -eq 'x86_64') { 'android/amd64' } else { 'android/arm64' }
    $aar = Join-Path $tools ("libbox-private-$Target.aar")
    if (!(Test-Path -LiteralPath $aar)) {
        $bindArgs = @('bind', '-target', $binding, '-androidapi', '29', '-javapkg', 'io.nekohasekai',
            '-tags', 'with_gvisor,with_utls,with_clash_api,badlinkname,tfogo_checklinkname0',
            '-ldflags=-s -w -checklinkname=0', '-o', $aar, './experimental/libbox')
        Push-Location $source
        try { & $mobile @bindArgs } finally { Pop-Location }
    }
    if (!(Test-Path -LiteralPath 'node_modules/.bin/tauri.cmd')) { npm.cmd ci --no-audit --no-fund }
    npm.cmd run build:agent
    $tauri = (Resolve-Path 'node_modules/.bin/tauri.cmd').Path
    $gradleRoot = Join-Path $project 'apps/client/src-tauri/gen/android'
    if (!(Test-Path -LiteralPath (Join-Path $gradleRoot 'gradlew.bat'))) {
        Push-Location 'apps/client'
        try { & $tauri android init --ci --skip-targets-install } finally { Pop-Location }
    }
    $buildTask = Join-Path $gradleRoot 'buildSrc/src/main/java/app/homeproxy/agent/kotlin/BuildTask.kt'
    $buildTaskText = Get-Content -LiteralPath $buildTask -Raw
    # Gradle runs from src-tauri and needs the JavaScript entry point in the root workspace.
    $buildTaskText = $buildTaskText.Replace('listOf("tauri", "android", "android-studio-script")',
        'listOf("../../../node_modules/@tauri-apps/cli/tauri.js", "android", "android-studio-script")')
    Set-Content -LiteralPath $buildTask -Value $buildTaskText -Encoding utf8NoBOM -NoNewline
    $module = Join-Path $gradleRoot 'app'
    $gradle = Join-Path $module 'build.gradle.kts'
    $wrapper = Join-Path $gradleRoot 'gradle/wrapper/gradle-wrapper.properties'
    $wrapperText = Get-Content -LiteralPath $wrapper -Raw
    $wrapperText -replace 'gradle-9\.6\.1-bin\.zip', 'gradle-9.6.0-bin.zip' | Set-Content -LiteralPath $wrapper -Encoding utf8NoBOM -NoNewline
    $properties = Join-Path $gradleRoot 'gradle.properties'
    if (!(Select-String -LiteralPath $properties -Pattern '^kotlin\.incremental=' -Quiet)) {
        # The Tauri dependency and the project can reside on different Windows drives.
        Add-Content -LiteralPath $properties -Value "`nkotlin.incremental=false" -Encoding utf8
    }
    $gradleText = Get-Content -LiteralPath $gradle -Raw
    $gradleText -replace '(?m)(compileSdk|targetSdk) = 37\b', '$1 = 36' | Set-Content -LiteralPath $gradle -Encoding utf8NoBOM -NoNewline
    $main = Join-Path $module 'src/main'
    $libs = (New-Item -ItemType Directory -Path (Join-Path $module 'libs') -Force).FullName
    Copy-Item -LiteralPath $aar -Destination (Join-Path $libs 'libbox.aar') -Force
    if (!(Select-String -LiteralPath $gradle -SimpleMatch 'libs/libbox.aar' -Quiet)) {
        Add-Content -Encoding utf8 -LiteralPath $gradle -Value @'

dependencies {
    implementation(files("libs/libbox.aar"))
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
}
'@
    }
    $kotlin = (New-Item -ItemType Directory -Force -Path (Join-Path $main 'java/app/homeproxy/agent')).FullName
    Get-ChildItem -LiteralPath 'native/android/kotlin' -Filter '*.kt' | Copy-Item -Destination $kotlin -Force
    $resources = (New-Item -ItemType Directory -Force -Path (Join-Path $main 'res/xml')).FullName
    Copy-Item -LiteralPath 'native/android/network_security_config.xml' -Destination $resources -Force
    $assets = (New-Item -ItemType Directory -Path (Join-Path $main 'assets') -Force).FullName
    $updateSource = @{ arch = $Target }
    if ($releaseKeyPem) {
        $updateSource.key = $releaseKeyPem
        $updateSource.manifest = $UpdateManifest.AbsoluteUri
        $updateSource.signature = $UpdateSignature.AbsoluteUri
    }
    $updateSource | ConvertTo-Json -Compress |
        Set-Content -LiteralPath (Join-Path $assets 'update-source.json') -Encoding utf8NoBOM

    $file = Join-Path $main 'AndroidManifest.xml'
    $manifest = [xml](Get-Content -LiteralPath $file -Raw)
    $ns = 'http://schemas.android.com/apk/res/android'
    $queries = $manifest.manifest.queries
    if (!$queries) {
        $queries = $manifest.CreateElement('queries')
        [void]$manifest.manifest.InsertBefore($queries, $manifest.manifest.application)
    }
    if (!($queries.intent | Where-Object { $_ -and $_.category.GetAttribute('name', $ns) -eq 'android.intent.category.LAUNCHER' })) {
        $launcherQuery = $manifest.CreateElement('intent')
        $mainAction = $manifest.CreateElement('action')
        [void]$mainAction.SetAttribute('name', $ns, 'android.intent.action.MAIN')
        [void]$launcherQuery.AppendChild($mainAction)
        $category = $manifest.CreateElement('category')
        [void]$category.SetAttribute('name', $ns, 'android.intent.category.LAUNCHER')
        [void]$launcherQuery.AppendChild($category)
        [void]$queries.AppendChild($launcherQuery)
    }
    $names = @($manifest.manifest.'uses-permission' | ForEach-Object { $_.GetAttribute('name', $ns) })
    foreach ($permission in @('ACCESS_NETWORK_STATE', 'FOREGROUND_SERVICE', 'FOREGROUND_SERVICE_SPECIAL_USE', 'POST_NOTIFICATIONS', 'REQUEST_INSTALL_PACKAGES', 'RECEIVE_BOOT_COMPLETED')) {
        $name = "android.permission.$permission"
        if ($name -notin $names) {
            $item = $manifest.CreateElement('uses-permission')
            [void]$item.SetAttribute('name', $ns, $name)
            [void]$manifest.manifest.InsertBefore($item, $manifest.manifest.application)
        }
    }
    $app = $manifest.manifest.application
    [void]$app.SetAttribute('networkSecurityConfig', $ns, '@xml/network_security_config')
    [void]$app.SetAttribute('allowBackup', $ns, 'false')
    $service = $app.service | Where-Object { $_ -and $_.GetAttribute('name', $ns) -eq '.HomeProxyVpnService' }
    if (!$service) {
        $service = $manifest.CreateElement('service')
        [void]$service.SetAttribute('name', $ns, '.HomeProxyVpnService')
        [void]$service.SetAttribute('exported', $ns, 'true')
        [void]$service.SetAttribute('permission', $ns, 'android.permission.BIND_VPN_SERVICE')
        [void]$service.SetAttribute('foregroundServiceType', $ns, 'specialUse')
        $property = $manifest.CreateElement('property')
        [void]$property.SetAttribute('name', $ns, 'android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE')
        [void]$property.SetAttribute('value', $ns, 'User-configured HomeProxy VPN')
        [void]$service.AppendChild($property)
        $filter = $manifest.CreateElement('intent-filter')
        $action = $manifest.CreateElement('action')
        [void]$action.SetAttribute('name', $ns, 'android.net.VpnService')
        [void]$filter.AppendChild($action)
        [void]$service.AppendChild($filter)
        [void]$app.AppendChild($service)
    }
    $alwaysOn = $service.'meta-data' | Where-Object {
        $_ -and $_.GetAttribute('name', $ns) -eq 'android.net.VpnService.SUPPORTS_ALWAYS_ON'
    }
    if (!$alwaysOn) {
        $alwaysOn = $manifest.CreateElement('meta-data')
        [void]$alwaysOn.SetAttribute('name', $ns, 'android.net.VpnService.SUPPORTS_ALWAYS_ON')
        [void]$service.AppendChild($alwaysOn)
    }
    [void]$alwaysOn.SetAttribute('value', $ns, 'true')
    if (!($app.receiver | Where-Object { $_ -and $_.GetAttribute('name', $ns) -eq '.AndroidUpdateResult' })) {
        $receiver = $manifest.CreateElement('receiver')
        [void]$receiver.SetAttribute('name', $ns, '.AndroidUpdateResult')
        [void]$receiver.SetAttribute('exported', $ns, 'false')
        [void]$app.AppendChild($receiver)
    }
    if (!($app.service | Where-Object { $_ -and $_.GetAttribute('name', $ns) -eq '.HomeProxyTileService' })) {
        $tile = $manifest.CreateElement('service')
        [void]$tile.SetAttribute('name', $ns, '.HomeProxyTileService')
        [void]$tile.SetAttribute('exported', $ns, 'true')
        [void]$tile.SetAttribute('label', $ns, 'HomeProxy')
        [void]$tile.SetAttribute('icon', $ns, '@mipmap/ic_launcher')
        [void]$tile.SetAttribute('permission', $ns, 'android.permission.BIND_QUICK_SETTINGS_TILE')
        $tileFilter = $manifest.CreateElement('intent-filter')
        $tileAction = $manifest.CreateElement('action')
        [void]$tileAction.SetAttribute('name', $ns, 'android.service.quicksettings.action.QS_TILE')
        [void]$tileFilter.AppendChild($tileAction)
        [void]$tile.AppendChild($tileFilter)
        [void]$app.AppendChild($tile)
    }
    if (!($app.receiver | Where-Object { $_ -and $_.GetAttribute('name', $ns) -eq '.BootReceiver' })) {
        $boot = $manifest.CreateElement('receiver')
        [void]$boot.SetAttribute('name', $ns, '.BootReceiver')
        [void]$boot.SetAttribute('exported', $ns, 'true')
        $bootFilter = $manifest.CreateElement('intent-filter')
        $bootAction = $manifest.CreateElement('action')
        [void]$bootAction.SetAttribute('name', $ns, 'android.intent.action.BOOT_COMPLETED')
        [void]$bootFilter.AppendChild($bootAction)
        [void]$boot.AppendChild($bootFilter)
        [void]$app.AppendChild($boot)
    }
    $manifest.Save($file)
    $buildArguments = @('android', 'build', '--apk', '--target', $Target, '--split-per-abi', '--ci')
    if (!$keystore) { $buildArguments += '--debug' }
    if ($Version) {
        $override = Join-Path $tools 'android-version.json'
        @{version = $Version} | ConvertTo-Json -Compress |
            Set-Content -LiteralPath $override -Encoding utf8NoBOM
        $buildArguments += @('--config', $override)
    }
    Push-Location 'apps/client'
    try { & $tauri @buildArguments } finally { Pop-Location }
    $flavor = if ($Target -eq 'aarch64') { 'arm64' } else { 'x86_64' }
    $out = (New-Item -ItemType Directory -Path $OutputDirectory -Force).FullName
    if ($keystore) {
        $apk = Join-Path $module "build/outputs/apk/$flavor/release/app-$flavor-release-unsigned.apk"
        if (!(Test-Path -LiteralPath $apk)) { throw 'Unsigned release APK output is missing.' }
        $buildTools = Join-Path $env:ANDROID_HOME 'build-tools/36.0.0'
        $aligned = Join-Path $tools "homeproxy-$Target-aligned.apk"
        $artifact = Join-Path $out "homeproxy-android-$Target.apk"
        try {
            & (Join-Path $buildTools 'zipalign.exe') -f -P 16 4 $apk $aligned
            & (Join-Path $buildTools 'apksigner.bat') sign --ks $keystore --ks-key-alias homeproxy `
                --ks-pass env:HOMEPROXY_ANDROID_KEY_PASSWORD --key-pass env:HOMEPROXY_ANDROID_KEY_PASSWORD --out $artifact $aligned
            & (Join-Path $buildTools 'apksigner.bat') verify $artifact
        } finally {
            Remove-Item -LiteralPath $aligned,"$aligned.idsig" -ErrorAction SilentlyContinue
        }
    } else {
        $apk = Join-Path $module "build/outputs/apk/$flavor/debug/app-$flavor-debug.apk"
        if (!(Test-Path -LiteralPath $apk)) { throw 'APK output is missing.' }
        Copy-Item -LiteralPath $apk -Destination (Join-Path $out "homeproxy-$Target-debug.apk") -Force
    }
} finally {
    Pop-Location
    foreach ($name in $previous.Keys) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
}
