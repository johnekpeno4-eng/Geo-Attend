# Auto-commit and push safe project changes to GitHub.
# .gitignore protects .env, data/, database files, reports, logs, and node_modules/.
param(
  [int]$IntervalSeconds = 60
)

$ErrorActionPreference = "Continue"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $ProjectRoot

Write-Host "GeoAttend auto-push is running. Press Ctrl+C to stop." -ForegroundColor Cyan
Write-Host "Project: $ProjectRoot" -ForegroundColor DarkCyan

while ($true) {
  try {
    git rev-parse --is-inside-work-tree *> $null
    if ($LASTEXITCODE -ne 0) {
      Write-Host "This folder is not a Git repository." -ForegroundColor Red
      break
    }

    $branch = (git branch --show-current).Trim()
    if (-not $branch) { $branch = "main" }

    $changes = git status --porcelain
    if ($changes) {
      git add -A
      $staged = git diff --cached --name-only
      if ($staged) {
        $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        git commit -m "Auto update GeoAttend $stamp"
        if ($LASTEXITCODE -eq 0) {
          git push origin $branch
          if ($LASTEXITCODE -eq 0) {
            Write-Host "Pushed changes to origin/$branch at $stamp" -ForegroundColor Green
          } else {
            Write-Host "Commit was created, but push failed. Check GitHub login/network." -ForegroundColor Yellow
          }
        }
      }
    } else {
      Write-Host "No changes to push: $(Get-Date -Format "HH:mm:ss")" -ForegroundColor DarkGray
    }
  } catch {
    Write-Host "Auto-push error: $($_.Exception.Message)" -ForegroundColor Red
  }

  Start-Sleep -Seconds $IntervalSeconds
}
