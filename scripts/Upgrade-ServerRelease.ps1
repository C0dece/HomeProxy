param(
    [ValidatePattern('^(latest|\d+\.\d+\.\d+)$')][string]$Version = '0.3.1',
    [ValidatePattern('^[\w.-]+/[\w.-]+$')][string]$Repository = 'C0dece/HomeProxy',
    [ValidatePattern('^[\w.-]+$')][string]$ServiceName = 'HomeProxyServer',
    [string]$InstallDir = '',
    [string]$ConfigFile = ''
)

$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell window (Run as Administrator).'
    }
}

function Parse-ServicePaths {
    param([string]$PathName)
    if ([string]::IsNullOrWhiteSpace($PathName)) {
        throw "Service '$ServiceName' has an empty ImagePath."
    }
    $exePath = $null
    $trimmed = $PathName.Trim()
    if ($trimmed.StartsWith('"')) {
        $endQuote = $trimmed.IndexOf('"', 1)
        if ($endQuote -gt 1) {
            $exePath = $trimmed.Substring(1, $endQuote - 1)
        }
    } else {
        $spaceIdx = $trimmed.IndexOf(' ')
        if ($spaceIdx -gt 0) {
            $exePath = $trimmed.Substring(0, $spaceIdx)
        } else {
            $exePath = $trimmed
        }
    }
    if ([string]::IsNullOrWhiteSpace($exePath)) {
        throw "Could not determine executable path from service ImagePath: $PathName"
    }

    $cfgPath = $null
    $cfgMatch = [regex]::Match($trimmed, '(?i)(?:^|\s)-{1,2}config(?:\s+|=)(?:"([^"]+)"|(\S+))')
    if ($cfgMatch.Success) {
        if ($cfgMatch.Groups[1].Success) {
            $cfgPath = $cfgMatch.Groups[1].Value
        } else {
            $cfgPath = $cfgMatch.Groups[2].Value
        }
    }
    return @{
        InstallDir = (Split-Path -Parent $exePath)
        ConfigFile = $cfgPath
    }
}

function Get-HealthUri {
    param($Config)
    $endpoint = $null
    $scheme = 'http'
    if ($Config.PSObject.Properties['localAdminListen'] -and -not [string]::IsNullOrWhiteSpace($Config.localAdminListen)) {
        $endpoint = $Config.localAdminListen.Trim()
        $scheme = 'http'
    } elseif ($Config.PSObject.Properties['listen'] -and -not [string]::IsNullOrWhiteSpace($Config.listen)) {
        $endpoint = $Config.listen.Trim()
        if ($Config.PSObject.Properties['certFile'] -and -not [string]::IsNullOrWhiteSpace($Config.certFile) -and
            $Config.PSObject.Properties['tlsKeyFile'] -and -not [string]::IsNullOrWhiteSpace($Config.tlsKeyFile)) {
            $scheme = 'https'
        }
    }
    if ([string]::IsNullOrWhiteSpace($endpoint)) {
        return $null
    }
    $lastColon = $endpoint.LastIndexOf(':')
    if ($lastColon -le 0) {
        return $null
    }
    $hostPart = $endpoint.Substring(0, $lastColon).Trim('[', ']')
    $portPart = $endpoint.Substring($lastColon + 1)
    if ($hostPart -eq '0.0.0.0' -or $hostPart -eq '::' -or $hostPart -eq '') {
        $hostPart = '127.0.0.1'
    }
    return "${scheme}://${hostPart}:${portPart}/healthz"
}

function Invoke-HealthCheck {
    param([string]$Uri)
    if ($Uri.StartsWith('https://')) {
        $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
        if ($curl) {
            $raw = & $curl.Source -fsSk --max-time 3 $Uri 2>$null
            if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($raw)) {
                return $null
            }
            return ($raw | ConvertFrom-Json)
        }
        $prevCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        try {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            return Invoke-RestMethod -Uri $Uri -Method Get -TimeoutSec 3
        } finally {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $prevCallback
        }
    }
    return Invoke-RestMethod -Uri $Uri -Method Get -TimeoutSec 3
}

function Copy-FileIfExists {
    param([string]$Source, [string]$DestinationDir)
    if (Test-Path -LiteralPath $Source -PathType Leaf) {
        Copy-Item -LiteralPath $Source -Destination $DestinationDir -Force
        return $true
    }
    return $false
}

Assert-Administrator
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$svcCim = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
if (-not $svcCim) {
    throw "Windows service '$ServiceName' was not found on this machine. Pass an existing -ServiceName."
}
$parsedPaths = Parse-ServicePaths -PathName $svcCim.PathName
if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir = $parsedPaths.InstallDir
}
$resolvedInstallDir = (Resolve-Path -LiteralPath $InstallDir).Path

if ([string]::IsNullOrWhiteSpace($ConfigFile)) {
    if (-not [string]::IsNullOrWhiteSpace($parsedPaths.ConfigFile)) {
        $ConfigFile = $parsedPaths.ConfigFile
    } else {
        $ConfigFile = Join-Path $resolvedInstallDir 'server.json'
    }
}
if (-not [IO.Path]::IsPathRooted($ConfigFile)) {
    $ConfigFile = Join-Path $resolvedInstallDir $ConfigFile
}
$resolvedConfig = (Resolve-Path -LiteralPath $ConfigFile).Path
$cfg = Get-Content -LiteralPath $resolvedConfig -Raw -Encoding UTF8 | ConvertFrom-Json

if (-not $cfg.PSObject.Properties['database'] -or [string]::IsNullOrWhiteSpace($cfg.database)) {
    throw "Missing 'database' setting in $resolvedConfig"
}
$dbPath = $cfg.database
if (-not [IO.Path]::IsPathRooted($dbPath)) {
    $dbPath = Join-Path (Split-Path -Parent $resolvedConfig) $dbPath
}

$adminDirPath = $null
if ($cfg.PSObject.Properties['adminDir'] -and -not [string]::IsNullOrWhiteSpace($cfg.adminDir)) {
    $adminDirPath = $cfg.adminDir
    if (-not [IO.Path]::IsPathRooted($adminDirPath)) {
        $adminDirPath = Join-Path (Split-Path -Parent $resolvedConfig) $adminDirPath
    }
} elseif (Test-Path -LiteralPath (Join-Path $resolvedInstallDir 'admin') -PathType Container) {
    $adminDirPath = Join-Path $resolvedInstallDir 'admin'
}

$healthUri = Get-HealthUri -Config $cfg

if ($Version -eq 'latest') {
    $zipUrl = "https://github.com/$Repository/releases/latest/download/homeproxy-server-windows-amd64.zip"
} else {
    $zipUrl = "https://github.com/$Repository/releases/download/v$Version/homeproxy-server-windows-amd64.zip"
}

$tempDir = Join-Path ([IO.Path]::GetTempPath()) ("homeproxy-upgrade-" + [Guid]::NewGuid().ToString('N'))
$zipPath = Join-Path $tempDir 'homeproxy-server-windows-amd64.zip'
$extractDir = Join-Path $tempDir 'extracted'
New-Item -ItemType Directory -Path $extractDir -Force | Out-Null

$backupRoot = Join-Path $resolvedInstallDir '.homeproxy-manual-backup'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupDir = Join-Path $backupRoot $stamp
$backupDbDir = Join-Path $backupDir 'db'
$backupAdminDir = Join-Path $backupDir 'admin'

$managedFiles = @(
    'homeproxy-server.exe',
    'homeproxy-verify-release.exe',
    'sing-box.exe',
    'sing-box-license.txt',
    'release-public.pem',
    'Update-ServerFromGitHub.ps1',
    'Install-ServerService.ps1'
)

$applied = $false
$hadAdminDir = $false

try {
    Write-Host "Downloading $zipUrl ..."
    $prevProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
    } finally {
        $ProgressPreference = $prevProgress
    }

    Expand-Archive -LiteralPath $zipPath -DestinationPath $extractDir -Force
    if (-not (Test-Path -LiteralPath (Join-Path $extractDir 'homeproxy-server.exe') -PathType Leaf)) {
        throw 'Downloaded archive does not contain homeproxy-server.exe.'
    }

    $svc = Get-Service -Name $ServiceName
    if ($svc.Status -ne 'Stopped') {
        Write-Host "Stopping service $ServiceName ..."
        Stop-Service -Name $ServiceName -Force
        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }

    New-Item -ItemType Directory -Path $backupDbDir -Force | Out-Null
    Copy-Item -LiteralPath $resolvedConfig -Destination (Join-Path $backupDir 'server.json') -Force
    foreach ($name in $managedFiles) {
        Copy-FileIfExists -Source (Join-Path $resolvedInstallDir $name) -DestinationDir $backupDir | Out-Null
    }
    foreach ($suffix in @('', '-wal', '-shm')) {
        $candidateDb = $dbPath + $suffix
        Copy-FileIfExists -Source $candidateDb -DestinationDir $backupDbDir | Out-Null
    }
    if ($adminDirPath -and (Test-Path -LiteralPath $adminDirPath -PathType Container)) {
        $hadAdminDir = $true
        New-Item -ItemType Directory -Path $backupAdminDir -Force | Out-Null
        Copy-Item -Path (Join-Path $adminDirPath '*') -Destination $backupAdminDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Backup saved to $backupDir"

    $applied = $true
    foreach ($name in $managedFiles) {
        Copy-FileIfExists -Source (Join-Path $extractDir $name) -DestinationDir $resolvedInstallDir | Out-Null
    }
    $stagedAdmin = Join-Path $extractDir 'admin'
    if ($adminDirPath -and (Test-Path -LiteralPath $stagedAdmin -PathType Container)) {
        if (-not (Test-Path -LiteralPath $adminDirPath -PathType Container)) {
            New-Item -ItemType Directory -Path $adminDirPath -Force | Out-Null
        } else {
            Get-ChildItem -LiteralPath $adminDirPath -Force | Remove-Item -Recurse -Force
        }
        Copy-Item -Path (Join-Path $stagedAdmin '*') -Destination $adminDirPath -Recurse -Force
    }

    Write-Host "Starting service $ServiceName ..."
    Start-Service -Name $ServiceName
    $svc.Refresh()
    $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))

    if ($healthUri) {
        Write-Host "Waiting for health check at $healthUri ..."
        $deadline = (Get-Date).AddSeconds(30)
        $health = $null
        while ((Get-Date) -lt $deadline) {
            try {
                $resp = Invoke-HealthCheck -Uri $healthUri
                if ($resp -and $resp.ready -eq $true) {
                    $health = $resp
                    break
                }
            } catch {
                # Retry until deadline
            }
            Start-Sleep -Milliseconds 500
        }
        if (-not $health) {
            throw "Service started, but health check did not become ready at $healthUri within 30 seconds."
        }
        if ($Version -ne 'latest' -and $health.version -and $health.version -ne $Version) {
            throw "Expected version $Version from health check, got $($health.version)."
        }
        Write-Host "Upgrade succeeded: version=$($health.version), api=$($health.api), dbSchema=$($health.dbSchema)"
    } else {
        Write-Host 'Upgrade succeeded: service is running.'
    }
    Write-Host "Backup location: $backupDir"
} catch {
    $err = $_
    if ($applied) {
        Write-Warning "Upgrade failed ($($err.Exception.Message)). Restoring previous server binaries and database from $backupDir ..."
        try {
            $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -ne 'Stopped') {
                Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
            }
            foreach ($name in $managedFiles) {
                Copy-FileIfExists -Source (Join-Path $backupDir $name) -DestinationDir $resolvedInstallDir | Out-Null
            }
            $dbLeaf = Split-Path -Leaf $dbPath
            $dbDir = Split-Path -Parent $dbPath
            foreach ($suffix in @('', '-wal', '-shm')) {
                $targetDb = $dbPath + $suffix
                if (Test-Path -LiteralPath $targetDb -PathType Leaf) {
                    Remove-Item -LiteralPath $targetDb -Force
                }
                $savedDb = Join-Path $backupDbDir ($dbLeaf + $suffix)
                if (Test-Path -LiteralPath $savedDb -PathType Leaf) {
                    Copy-Item -LiteralPath $savedDb -Destination $dbDir -Force
                }
            }
            if ($hadAdminDir -and $adminDirPath) {
                if (Test-Path -LiteralPath $adminDirPath -PathType Container) {
                    Get-ChildItem -LiteralPath $adminDirPath -Force | Remove-Item -Recurse -Force
                } else {
                    New-Item -ItemType Directory -Path $adminDirPath -Force | Out-Null
                }
                Copy-Item -Path (Join-Path $backupAdminDir '*') -Destination $adminDirPath -Recurse -Force -ErrorAction SilentlyContinue
            }
            Start-Service -Name $ServiceName
            Write-Warning 'Rollback completed and service restarted.'
        } catch {
            Write-Error "Rollback encountered an error: $($_.Exception.Message). Manual backup is preserved at $backupDir"
        }
    }
    throw $err
} finally {
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
