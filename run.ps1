<#
.SYNOPSIS
    Run the CrowdStrike -> Zafran integration via the starlark-runner.
    Reads API credentials from credentials.json in the same directory.

.EXAMPLE
    .\run.ps1
    .\run.ps1 -Runner "C:\tools\starlark-runner.exe"
    .\run.ps1 -Output out.json
#>
param(
    [string]$Runner = "starlark-runner",
    [string]$Config = "$PSScriptRoot\credentials.json",
    [string]$Output = "$PSScriptRoot\out.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path $Config)) {
    Write-Error "Credentials file not found: $Config"
    exit 1
}

$creds = Get-Content $Config -Raw | ConvertFrom-Json

$apiUrl    = $creds.api_url
$apiKey    = $creds.api_key
$apiSecret = $creds.api_secret

if (-not $apiUrl -or -not $apiKey -or -not $apiSecret) {
    Write-Error "$Config is missing required fields (api_url, api_key, api_secret). Populate them before running."
    exit 1
}

$script = "$PSScriptRoot\crowdstrike.star"

Write-Host "Running integration: $script"
Write-Host "Target:              $apiUrl"
Write-Host "Output:              $Output"
Write-Host ""

& $Runner run $script `
    --params "api_url=$apiUrl" `
    --params "api_key=$apiKey" `
    --params "api_secret=$apiSecret" `
    --output $Output
