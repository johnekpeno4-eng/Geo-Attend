$RootPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$Port = 5502
$HealthUrl = "http://localhost:$Port/login.html"

Set-Location $RootPath

while ($true) {
  $healthy = $false
  try {
    $response = Invoke-WebRequest -UseBasicParsing $HealthUrl -TimeoutSec 3
    $healthy = $response.StatusCode -ge 200 -and $response.StatusCode -lt 500
  } catch {
    $healthy = $false
  }

  if (-not $healthy) {
    $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $listener) {
      Start-Process -FilePath node -ArgumentList "server.js" -WorkingDirectory $RootPath -RedirectStandardOutput "server-live.out.log" -RedirectStandardError "server-live.err.log" -WindowStyle Hidden
      Start-Sleep -Seconds 2
    }
  }

  Start-Sleep -Seconds 5
}
