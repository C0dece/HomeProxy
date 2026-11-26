[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$InstallDir = '',
    [string]$ConfigFile = 'server.json',
    [string]$ServiceName = 'HomeProxyServer',
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$SkipFirewall,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

$apiRuleName = 'HomeProxy Server - API (TCP)'
$tunnelRuleName = 'HomeProxy Server - Tunnel (TCP)'

function Remove-HomeProxyFirewallRules {
    foreach ($name in @($apiRuleName, $tunnelRuleName)) {
        $existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
        if ($existing -and $PSCmdlet.ShouldProcess($name, 'Remove Windows Firewall rule')) {
            $existing | Remove-NetFirewallRule
        }
    }
}

function Set-HomeProxyFirewallRule {
    param(
        [string]$DisplayName,
        [int]$Port,
        [string]$Program
    )
    $existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if ($existing) {
        if ($PSCmdlet.ShouldProcess($DisplayName, 'Remove previous rule before recreating')) {
            $existing | Remove-NetFirewallRule
        }
    }
    if ($PSCmdlet.ShouldProcess("$DisplayName (TCP $Port)", 'Create Windows Firewall allow rule')) {
        New-NetFirewallRule -DisplayName $DisplayName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -Program $Program -Profile Any | Out-Null
    }
}

function Get-ListenPortIfNonLoopback {
    param([string]$Endpoint)
    if ([string]::IsNullOrWhiteSpace($Endpoint)) { return $null }
    $lastColon = $Endpoint.LastIndexOf(':')
    if ($lastColon -le 0) { return $null }
    $hostPart = $Endpoint.Substring(0, $lastColon).Trim('[', ']')
    $portPart = $Endpoint.Substring($lastColon + 1)
    [int]$port = 0
    if (![int]::TryParse($portPart, [ref]$port) -or $port -lt 1 -or $port -gt 65535) { return $null }
    if ($hostPart -eq '127.0.0.1' -or $hostPart -eq '::1' -or $hostPart -ieq 'localhost') {
        return $null
    }
    return $port
}

if ($Uninstall) {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -ne 'Stopped' -and $PSCmdlet.ShouldProcess($ServiceName, 'Stop Windows service')) {
            Stop-Service -Name $ServiceName -Force
            $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
        }
        if ($PSCmdlet.ShouldProcess($ServiceName, 'Delete Windows service')) {
            & sc.exe delete $ServiceName | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed ($LASTEXITCODE)" }
        }
    }
    if (!$SkipFirewall) {
        Remove-HomeProxyFirewallRules
    }
    return
}

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
}

$resolvedDir = (Resolve-Path -LiteralPath $InstallDir).Path
$serverExe = Join-Path $resolvedDir 'homeproxy-server.exe'
$singBoxExe = Join-Path $resolvedDir 'sing-box.exe'
$configPath = if ([IO.Path]::IsPathRooted($ConfigFile)) { $ConfigFile } else { Join-Path $resolvedDir $ConfigFile }

if (!(Test-Path -LiteralPath $serverExe -PathType Leaf)) { throw "Missing homeproxy-server.exe in $resolvedDir" }
if (!(Test-Path -LiteralPath $singBoxExe -PathType Leaf)) { throw "Missing sing-box.exe in $resolvedDir" }
if (!(Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "Missing server config file: $configPath" }

$resolvedConfig = (Resolve-Path -LiteralPath $configPath).Path
$binaryPath = "`"$serverExe`" -config `"$resolvedConfig`""

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped' -and $PSCmdlet.ShouldProcess($ServiceName, 'Stop existing service before reconfiguring')) {
        Stop-Service -Name $ServiceName -Force
        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
    }
    if ($PSCmdlet.ShouldProcess($ServiceName, 'Update Windows service binary path')) {
        $scArgs = @('config', $ServiceName, 'binPath=', $binaryPath, 'start=', 'auto')
        if ($Credential) {
            $scArgs += @('obj=', $Credential.UserName, 'password=', $Credential.GetNetworkCredential().Password)
        }
        & sc.exe @scArgs | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe config failed ($LASTEXITCODE)" }
    }
} else {
    if ($PSCmdlet.ShouldProcess($ServiceName, 'Create Windows service')) {
        $params = @{
            Name           = $ServiceName
            BinaryPathName = $binaryPath
            DisplayName    = 'HomeProxy Server'
            Description    = 'HomeProxy Control Plane and VLESS+REALITY relay service'
            StartupType    = 'Automatic'
        }
        if ($Credential) { $params.Credential = $Credential }
        New-Service @params | Out-Null
    }
}

if ($PSCmdlet.ShouldProcess($ServiceName, 'Configure service failure recovery')) {
    & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/15000/restart/30000 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe failure failed ($LASTEXITCODE)" }
}

if (!$SkipFirewall) {
    $cfg = Get-Content -LiteralPath $resolvedConfig -Raw -Encoding UTF8 | ConvertFrom-Json
    $apiPort = Get-ListenPortIfNonLoopback -Endpoint $cfg.publicListen
    if ($null -eq $apiPort) {
        $apiPort = Get-ListenPortIfNonLoopback -Endpoint $cfg.listen
    }
    if ($null -ne $apiPort) {
        Set-HomeProxyFirewallRule -DisplayName $apiRuleName -Port $apiPort -Program $serverExe
    } else {
        $existingApi = Get-NetFirewallRule -DisplayName $apiRuleName -ErrorAction SilentlyContinue
        if ($existingApi -and $PSCmdlet.ShouldProcess($apiRuleName, 'Remove unused loopback API firewall rule')) {
            $existingApi | Remove-NetFirewallRule
        }
    }

    $tunnelPort = Get-ListenPortIfNonLoopback -Endpoint $cfg.tunnelListen
    if ($null -ne $tunnelPort) {
        Set-HomeProxyFirewallRule -DisplayName $tunnelRuleName -Port $tunnelPort -Program $singBoxExe
    } else {
        $existingTunnel = Get-NetFirewallRule -DisplayName $tunnelRuleName -ErrorAction SilentlyContinue
        if ($existingTunnel -and $PSCmdlet.ShouldProcess($tunnelRuleName, 'Remove unused loopback tunnel firewall rule')) {
            $existingTunnel | Remove-NetFirewallRule
        }
    }
}
