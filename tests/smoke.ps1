# End-to-end smoke test for an installed wsrv. Run from an elevated PowerShell after `wsrv install`.
# Read-only: it makes requests and inspects machine state, but changes nothing.
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$failures = 0

function Check($name, [scriptblock]$test) {
    try {
        if (& $test) { Write-Host "  ok    $name" -ForegroundColor Green }
        else { Write-Host "  FAIL  $name" -ForegroundColor Red; $script:failures++ }
    } catch {
        Write-Host "  FAIL  $name : $($_.Exception.Message)" -ForegroundColor Red; $script:failures++
    }
}

function Request($url, $method = 'GET') {
    try { Invoke-WebRequest -UseBasicParsing -Uri $url -Method $method -TimeoutSec 10 }
    catch [System.Net.WebException] { $_.Exception.Response }
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "wsrv smoke test"
Check "service is running" { (Get-Service wsrv).Status -eq 'Running' }
Check "HTTP/3 switched on in http.sys (active after reboot)" {
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters').EnableHttp3 -eq 1
}
Check "hosts file has local.admin" { (Get-Content "$env:windir\System32\drivers\etc\hosts" -Raw) -match '127\.0\.0\.1 local\.admin' }
Check "SNI binding for local.admin:8192" { (netsh http show sslcert hostnameport=local.admin:8192) -match 'Certificate Hash' }
Check "local.admin certificate trusted by Windows (TLS succeeds)" { (Request 'https://local.admin:8192/').StatusCode -eq 200 }
Check "admin page served" { (Request 'https://local.admin:8192/').Content -match 'wsrv admin' }
Check "admin API requires sign-in" { [int](Request 'https://local.admin:8192/api/sites').StatusCode -eq 401 }
Check "Alt-Svc advertises h3" { (Request 'https://local.admin:8192/').Headers['Alt-Svc'] -match 'h3=":8192"' }

$hello = Request 'https://localhost/'
if ($hello -and [int]$hello.StatusCode -eq 200) {
    Check "hello page on https://localhost/" { $hello.Content -match 'Hello, world!' }
    Check "POST to content site is 405" { [int](Request 'https://localhost/' 'POST').StatusCode -eq 405 }
    Check "HEAD to content site is 200" { [int](Request 'https://localhost/' 'HEAD').StatusCode -eq 200 }
} else {
    Write-Host "  skip  https://localhost/ (a folder is mapped, so the hello fallback is off)"
}

Write-Host ""
if ($failures) { Write-Host "$failures check(s) failed. See C:\ProgramData\wsrv\logs\wsrv.log" -ForegroundColor Red; exit 1 }
Write-Host "All checks passed." -ForegroundColor Green
