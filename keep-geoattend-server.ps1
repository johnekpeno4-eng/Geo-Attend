$RootPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$Port = 5501
$HealthUrl = "http://localhost:$Port/login.html"
$SyncIntervalSeconds = 60
$lastSyncAttempt = [datetime]::MinValue

Set-Location $RootPath

while ($true) {
  if (((Get-Date) - $lastSyncAttempt).TotalSeconds -ge $SyncIntervalSeconds) {
    $lastSyncAttempt = Get-Date
    $changes = git status --porcelain 2>$null
    if (-not $changes) {
      git fetch origin --prune 2>$null
      if ($LASTEXITCODE -eq 0) {
        # Rebase keeps local commits while applying new partner commits from GitHub.
        git pull --rebase 2>$null
      }
    }
  }

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
      # WebAuthn relies on Web Crypto; --no-warnings only hides Node's experimental notices.
      Start-Process -FilePath node -ArgumentList "--no-warnings", "server.js" -WorkingDirectory $RootPath -RedirectStandardOutput "server-live.out.log" -RedirectStandardError "server-live.err.log" -WindowStyle Hidden
      Start-Sleep -Seconds 2
    }
  }

  Start-Sleep -Seconds 5
}
