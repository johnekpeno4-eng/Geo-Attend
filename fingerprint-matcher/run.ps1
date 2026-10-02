$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $projectRoot '.env'
$envMap = @{}
Get-Content $envFile | ForEach-Object {
    if ($_ -match '^\s*([^#=]+)=(.*)$') { $envMap[$Matches[1].Trim()] = $Matches[2].Trim() }
}
if (-not $envMap.FINGERPRINT_MATCHER_TOKEN -or $envMap.FINGERPRINT_MATCHER_TOKEN -like 'replace-*') {
    throw 'FINGERPRINT_MATCHER_TOKEN is missing in the project .env file.'
}
$env:FINGERPRINT_MATCHER_TOKEN = $envMap.FINGERPRINT_MATCHER_TOKEN
if ($envMap.FINGERPRINT_MATCHER_PORT) { $env:FINGERPRINT_MATCHER_PORT = $envMap.FINGERPRINT_MATCHER_PORT }
$jar = Join-Path $PSScriptRoot 'target\fingerprint-matcher-1.0.0.jar'
if (-not (Test-Path $jar)) { throw 'Matcher JAR is missing. Run build.ps1 first.' }
$env:FINGERPRINT_MATCHER_PORT = $envMap.FINGERPRINT_MATCHER_PORT
$env:FINGERPRINT_MATCHER_URL = $envMap.FINGERPRINT_MATCHER_URL
Write-Host "Starting GeoAttend fingerprint matcher at $env:FINGERPRINT_MATCHER_URL. Keep this window open."
& java -jar $jar



