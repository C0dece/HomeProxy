[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$AgentExe = (Join-Path $PSScriptRoot 'homeproxy-agent.exe'),
    [string]$DataDir = $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'HomeProxy' } else { '' }),
    [string]$TaskName = 'HomeProxyAgentTun',
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

if ($Uninstall) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing -and $PSCmdlet.ShouldProcess($TaskName, 'Unregister scheduled TUN task')) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    return
}

if (!(Test-Path -LiteralPath $AgentExe -PathType Leaf)) {
    throw "Missing homeproxy-agent.exe at $AgentExe"
}
if ([string]::IsNullOrWhiteSpace($DataDir)) {
    throw 'LocalAppData directory is unavailable; specify -DataDir explicitly.'
}

$resolvedExe = (Resolve-Path -LiteralPath $AgentExe).Path
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$argument = "serve --tun --data `"$DataDir`""
$action = New-ScheduledTaskAction -Execute $resolvedExe -Argument $argument
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew

if ($PSCmdlet.ShouldProcess($TaskName, 'Register scheduled TUN task with highest privileges')) {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
}
