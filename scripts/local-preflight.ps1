[CmdletBinding()]
param(
    [string]$ServerIp,
    [string]$PrivateKey = "$env:USERPROFILE\.ssh\greyfield_oracle"
)

$ErrorActionPreference = 'Stop'

$clientIp = (Invoke-RestMethod -Uri 'https://api.ipify.org').Trim()
Write-Output "Current administrator IPv4: $clientIp"
Write-Output "OCI administrator CIDR:       $clientIp/32"

$ssh = Get-Command ssh.exe -ErrorAction SilentlyContinue
if (-not $ssh) {
    throw 'Windows OpenSSH client is not installed or not on PATH.'
}
Write-Output "OpenSSH client:                $($ssh.Source)"

if (-not (Test-Path -LiteralPath $PrivateKey -PathType Leaf)) {
    throw "Private key not found: $PrivateKey"
}
Write-Output "Private key:                   $PrivateKey"

if ($ServerIp) {
    foreach ($port in 22, 23, 2223) {
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $pending = $client.BeginConnect($ServerIp, $port, $null, $null)
            $reachable = $pending.AsyncWaitHandle.WaitOne(5000)
            if ($reachable) {
                try { $client.EndConnect($pending); $state = 'reachable' }
                catch { $state = 'refused' }
            } else {
                $state = 'timeout'
            }
            Write-Output ("TCP {0,-4} {1}" -f $port, $state)
        } finally {
            $client.Dispose()
        }
    }
}
