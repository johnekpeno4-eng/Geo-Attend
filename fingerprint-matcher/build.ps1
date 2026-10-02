$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$javaHome = Join-Path $env:ProgramFiles 'Eclipse Adoptium\jdk-17.0.20.101-hotspot'
$maven = Join-Path $projectRoot '.tools\apache-maven-3.9.16\bin\mvn.cmd'
if (-not (Test-Path (Join-Path $javaHome 'bin\java.exe'))) { throw 'Java 17 not found. Install Eclipse Temurin JDK 17.' }
if (-not (Test-Path $maven)) { throw 'Local Apache Maven not found in .tools.' }
$env:JAVA_HOME = $javaHome
$env:Path = "$javaHome\bin;$env:Path"
Push-Location $PSScriptRoot
try { & $maven -DskipTests package; if ($LASTEXITCODE -ne 0) { throw "Maven build failed with exit code $LASTEXITCODE" } }
finally { Pop-Location }
