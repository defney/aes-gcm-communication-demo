param([string]$ClientExe = 'app2.exe')
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$cryptoFiles = @('key.bin','secret.bin','password.verifier')
$before = @{}
foreach ($name in $cryptoFiles) {
    $before[$name] = if (Test-Path -LiteralPath $name) { (Get-FileHash -LiteralPath $name).Hash } else { 'absent' }
}
function Start-Demo([string]$Name, [string]$Arguments) {
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = Join-Path $PSScriptRoot $Name
    $info.Arguments = $Arguments
    $info.WorkingDirectory = $PSScriptRoot
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    [void]$process.Start()
    return $process
}
foreach ($mode in @('--auto', '--negative-tests')) {
    $channel = [guid]::NewGuid().ToString('N')
    $client = Start-Demo $ClientExe "$mode --channel=$channel"
    $menu = $null
    try {
        # Wait for actual readiness, not a fixed startup assumption.
        $ready = $client.StandardOutput.ReadLineAsync()
        if (-not $ready.Wait(5000)) { throw 'Client startup timed out' }
        $menu = Start-Demo 'app1.exe' "$mode --channel=$channel"
        if (-not $menu.WaitForExit(20000)) { throw 'Menu timed out' }
        if (-not $client.WaitForExit(5000)) { throw 'Client close timed out' }
        $menuLog = $menu.StandardOutput.ReadToEnd() + $menu.StandardError.ReadToEnd()
        $clientLog = $ready.Result + "`n" + $client.StandardOutput.ReadToEnd() + $client.StandardError.ReadToEnd()
        Write-Output "MODE: $mode"
        Write-Output $menuLog
        Write-Output $clientLog
        if ($menu.ExitCode -ne 0 -or $client.ExitCode -ne 0) { throw 'Round-trip failed' }
        if ($menuLog -notmatch 'Client -> Menu' -or $clientLog -notmatch 'Menu -> Client') { throw 'Direction information is missing' }
        if ($clientLog -notmatch 'Authenticated close') { throw 'Authenticated close message is missing' }
        if ($mode -eq '--negative-tests' -and ($menuLog -notmatch 'PASS:' -or $clientLog -notmatch 'PASS:')) { throw 'Negative tests failed' }
    } finally {
        if ($menu -and -not $menu.HasExited) { $menu.Kill(); $menu.WaitForExit() }
        if (-not $client.HasExited) { $client.Kill(); $client.WaitForExit() }
    }
}
$missing = Start-Demo 'app1.exe' ('--channel=missing-' + [guid]::NewGuid().ToString('N'))
try {
    if (-not $missing.WaitForExit(5000)) { throw 'Missing-peer test timed out' }
    $log = $missing.StandardOutput.ReadToEnd() + $missing.StandardError.ReadToEnd()
    if ($missing.ExitCode -ne 1 -or $log -notmatch 'App2 was not found') { throw 'Missing-peer test failed' }
    Write-Output 'PASS: App2-closed test.'
} finally { if (-not $missing.HasExited) { $missing.Kill() } }
foreach ($name in $cryptoFiles) {
    $after = if (Test-Path -LiteralPath $name) { (Get-FileHash -LiteralPath $name).Hash } else { 'absent' }
    if ($after -ne $before[$name]) { throw "Crypto file was created or modified: $name" }
}
Write-Output 'ALL TESTS PASSED; key.bin/secret.bin/password.verifier were not created or modified.'
