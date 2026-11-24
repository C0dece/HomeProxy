param(
    [ValidatePattern('^[\w.-]+/[\w.-]+$')][string]$Repository = 'C0dece/HomeProxy'
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$verifier = Join-Path $root 'homeproxy-verify-release.exe'
$key = Join-Path $root 'release-public.pem'
$log = Join-Path $root 'last-release-check.log'
$feed = "https://github.com/$Repository/releases/latest/download"
if (!(Test-Path -LiteralPath $verifier -PathType Leaf) -or !(Test-Path -LiteralPath $key -PathType Leaf)) {
    throw 'The release verifier and pinned public key must be installed beside this script.'
}

function Run-Verifier([string[]]$Arguments) {
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $result = & $verifier @Arguments 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousPreference }
    $result | Add-Content -LiteralPath $log -Encoding UTF8
    if ($code -ne 0 -and ($result -join "`n").Trim() -ne 'no newer compatible release') {
        throw "HomeProxy release operation failed ($code). See $log."
    }
}

[DateTime]::UtcNow.ToString('o') | Set-Content -LiteralPath $log -Encoding UTF8
Run-Verifier @('-recover-service')
Run-Verifier @('-apply-service','-manifest',"$feed/release.json",'-signature',"$feed/release.sig",'-public-key',$key,'-channel','stable')
