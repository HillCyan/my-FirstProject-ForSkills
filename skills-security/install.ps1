[CmdletBinding()]
param(
    [string]$RepoUrl = "https://github.com/Damond-Fung/skills-security.git",
    [string]$Branch = "main",
    [string]$InstallRoot = "$HOME\.trae\skills",
    [string]$SkillName = "skills-security"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "Git is required. Please install Git first."
}

if (-not (Get-Command py -ErrorAction SilentlyContinue) -and -not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python 3 is required. Please install Python first."
}

if (-not (Test-Path $InstallRoot)) {
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
}

$targetPath = Join-Path $InstallRoot $SkillName
$gitPath = Join-Path $targetPath ".git"

if (Test-Path $targetPath) {
    Remove-Item -Path $targetPath -Recurse -Force
}

git clone --depth 1 --branch $Branch $RepoUrl $targetPath | Out-Null

if (Test-Path $gitPath) {
    Remove-Item -Path $gitPath -Recurse -Force
}

Write-Host "Installed to: $targetPath"
Write-Host "Run: py -3 `"$targetPath\main.py`" <skills_dir>"
