param(
    [ValidatePattern('^[\w.-]+/[\w.-]+$')][string]$Repository = 'C0dece/HomeProxy'
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$verifier = Join-Path $root 'homeproxy-verify-release.exe'
$key = Join-Path $root 'release-public.pem'
$log = Join-Path $root 'last-release-check.log'
$feed = "https://github.com/$Repository/releases/latest/download"
$history = Join-Path $root '.homeproxy-update-history'
$started = [DateTimeOffset]::UtcNow
$record = [ordered]@{
    startedAt = $started.ToUnixTimeSeconds()
    finishedAt = 0
    outcome = 'failed'
    phase = 'prerequisites'
}

function Write-UpdateHistory {
    [IO.Directory]::CreateDirectory($history) | Out-Null
    $stamp = $started.ToString('yyyyMMddHHmmssfffffff', [Globalization.CultureInfo]::InvariantCulture)
    $name = $stamp + '-' + [guid]::NewGuid().ToString('N')
    $temp = Join-Path $history "$name.tmp"
    try {
        [IO.File]::WriteAllText($temp, ($record | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
        [IO.File]::Move($temp, (Join-Path $history "$name.json"))
    } finally {
        if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
    }
    Get-ChildItem -LiteralPath $history -File -Filter '*.json' |
        Where-Object Name -Match '^\d{21}-[a-f0-9]{32}\.json$' |
        Sort-Object Name -Descending | Select-Object -Skip 30 | ForEach-Object {
            Remove-Item -LiteralPath $_.FullName -ErrorAction Continue
        }
}

function Run-Verifier([string[]]$Arguments, [switch]$AllowNoUpdate) {
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $PSNativeCommandUseErrorActionPreference = $false
    try {
        $result = & $verifier @Arguments 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousPreference }
    $result | Add-Content -LiteralPath $log -Encoding UTF8
    if ($AllowNoUpdate -and $code -ne 0 -and ($result -join "`n").Trim() -eq 'no newer compatible release') {
        return 'no-update'
    }
    if ($code -ne 0) {
        $record['exitCode'] = $code
        throw "HomeProxy release operation failed ($code). See $log."
    }
    if ($AllowNoUpdate) {
        $installed = $result | Select-String '^Installed (v?\d+\.\d+\.\d+)\. Recovery copy in ' | Select-Object -First 1
        if ($installed) {
            $record['version'] = $installed.Matches[0].Groups[1].Value
            return 'installed'
        }
        return 'completed'
    }
}

try {
    if (!(Test-Path -LiteralPath $verifier -PathType Leaf) -or !(Test-Path -LiteralPath $key -PathType Leaf)) {
        throw 'The release verifier and pinned public key must be installed beside this script.'
    }
    $started.ToString('o') | Set-Content -LiteralPath $log -Encoding UTF8
    $record.phase = 'recovery'
    Run-Verifier @('-recover-service')
    $record.phase = 'apply'
    $record.outcome = Run-Verifier @('-apply-service','-manifest',"$feed/release.json",'-signature',"$feed/release.sig",'-public-key',$key,'-channel','stable') -AllowNoUpdate
} finally {
    $record.finishedAt = [Math]::Max($record.startedAt, [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    try { Write-UpdateHistory } catch { Write-Warning "Could not save update history: $($_.Exception.Message)" }
}
