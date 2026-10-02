$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$maven = Join-Path $projectRoot '.tools\apache-maven-3.9.16\bin\mvn.cmd'
$javaHome = $env:JAVA_HOME
if (-not $javaHome -or -not (Test-Path (Join-Path $javaHome 'bin\javac.exe'))) {
    $javaHome = $null
    $toolsPath = Join-Path $projectRoot '.tools'
    if (Test-Path $toolsPath) {
        $jdk = Get-ChildItem -LiteralPath $toolsPath -Directory -Recurse -ErrorAction SilentlyContinue |
            Where-Object { Test-Path (Join-Path $_.FullName 'bin\javac.exe') } |
            Select-Object -First 1
        if ($jdk) { $javaHome = $jdk.FullName }
    }
}
if (-not $javaHome) {
    $systemJdk = Join-Path $env:ProgramFiles 'Eclipse Adoptium\jdk-17.0.20.101-hotspot'
    if (Test-Path (Join-Path $systemJdk 'bin\javac.exe')) { $javaHome = $systemJdk }
}
if (-not $javaHome) { throw 'Java 17 JDK not found. Set JAVA_HOME or place a JDK 17 under the project .tools directory.' }
if (-not (Test-Path $maven)) { throw 'Local Apache Maven not found in .tools.' }
$env:JAVA_HOME = $javaHome
$env:Path = "$javaHome\bin;$env:Path"
Push-Location $PSScriptRoot
try { & $maven -DskipTests package; if ($LASTEXITCODE -ne 0) { throw "Maven build failed with exit code $LASTEXITCODE" } }
finally { Pop-Location }
