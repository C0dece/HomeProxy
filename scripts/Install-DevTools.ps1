param([string]$Destination = (Join-Path $PSScriptRoot '../.tools'))

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { throw 'The pinned tools are for Windows x64.' }
$Destination = [IO.Path]::GetFullPath($Destination)
New-Item -ItemType Directory -Path $Destination -Force | Out-Null
$downloads = @(
    @{
        File = 'go1.27.4.windows-amd64.zip'
        Url = 'https://go.dev/dl/go1.27.4.windows-amd64.zip'
        Sha256 = '178ab98950ac69ab25069307dc6ade79f3816e414cce95b4da166a115cde1e7e'
        Bin = 'go/bin/go.exe'
    },
    @{
        File = 'sing-box-1.14.4-windows-amd64.zip'
        Url = 'https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-windows-amd64.zip'
        Sha256 = '99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df'
        Bin = 'sing-box-1.14.4-windows-amd64/sing-box.exe'
    }
)
foreach ($download in $downloads) {
    $archive = Join-Path $Destination $download.File
    if (!(Test-Path -LiteralPath $archive)) {
        $temporary = "$archive.partial"
        Invoke-WebRequest -UseBasicParsing $download.Url -OutFile $temporary
        if ((Get-FileHash -LiteralPath $temporary).Hash -ne $download.Sha256) { throw "Checksum mismatch for $($download.File)" }
        Move-Item -LiteralPath $temporary -Destination $archive -Force
    }
    if ((Get-FileHash -LiteralPath $archive).Hash -ne $download.Sha256) { throw "Checksum mismatch for $($download.File)" }
    $binary = Join-Path $Destination $download.Bin
    if (!(Test-Path -LiteralPath $binary)) { Expand-Archive -LiteralPath $archive -DestinationPath $Destination -Force }
    Get-Item -LiteralPath $binary | Select-Object -ExpandProperty FullName
}
