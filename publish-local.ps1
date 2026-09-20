#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Feed = $(if ($env:MM_FEED) { $env:MM_FEED } else { "E:\MM-Feed" }),
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

$nugetDir = Join-Path $Feed "nuget"
$npmDir = Join-Path $Feed "npm"
New-Item -ItemType Directory -Force -Path $nugetDir | Out-Null
New-Item -ItemType Directory -Force -Path $npmDir | Out-Null

$projects = @(
    "src\MM.Auth\MM.Auth.csproj",
    "src\MM.Auth.Totp\MM.Auth.Totp.csproj",
    "src\MM.Auth.Sqlite\MM.Auth.Sqlite.csproj",
    "src\MM.Auth.Crypto.Aes\MM.Auth.Crypto.Aes.csproj"
)

foreach ($project in $projects) {
    Write-Host "Packing $project -> $nugetDir"
    dotnet pack (Join-Path $root $project) -c $Configuration -o $nugetDir
    if ($LASTEXITCODE -ne 0) { throw "dotnet pack failed for $project with exit code $LASTEXITCODE" }
}

$reactDir = Join-Path $root "web\packages\auth-react"
if (Test-Path (Join-Path $reactDir "package.json")) {
    Write-Host "Packing @mm/auth-react -> $npmDir"
    pnpm --dir $reactDir pack --pack-destination $npmDir
    if ($LASTEXITCODE -ne 0) { throw "pnpm pack failed with exit code $LASTEXITCODE" }
}
else {
    Write-Host "Skipping @mm/auth-react: $reactDir not present"
}

Write-Host ""
Write-Host "Feed contents:"
Get-ChildItem -Path $nugetDir, $npmDir -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 10 |
    ForEach-Object { Write-Host ("  " + $_.FullName) }
