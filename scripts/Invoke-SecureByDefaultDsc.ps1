<#
.SYNOPSIS
  Native Microsoft365DSC engine for ALSO Secure by Default.

.DESCRIPTION
  Compiles dsc/SecureByDefault.dsc.ps1 into a MOF using config/reference-state.json.
  Discover : Test-DscConfiguration against the MOF (read-only drift check, nothing applied).
  Enforce  : Start-DscConfiguration (applies the desired state).

  Requires Windows PowerShell 5.1 (DSC Local Configuration Manager), the Microsoft365DSC module
  and an Entra app registration with a certificate (app-only auth), see
  https://microsoft365dsc.com/user-guide/get-started/authentication-and-permissions/
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Discover', 'Enforce')][string]$Mode = 'Discover',
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ApplicationId,
    [Parameter(Mandatory)][string]$CertificateThumbprint,
    [ValidateSet('AuditLog', 'UserSettings', 'Consent', 'Fido2', 'SharePoint', 'Laps')]
    [string[]]$Steps = @('AuditLog', 'UserSettings', 'Consent', 'Fido2', 'SharePoint', 'Laps'),
    [string]$OutputPath = (Join-Path (Get-Location) 'sbd-dsc')
)
$ErrorActionPreference = 'Stop'
if (-not (Get-Module -ListAvailable Microsoft365DSC)) { Install-Module Microsoft365DSC -Scope CurrentUser -Force }
Import-Module Microsoft365DSC

$ref = Get-Content (Join-Path $PSScriptRoot '..\config\reference-state.json') -Raw | ConvertFrom-Json
. (Join-Path $PSScriptRoot '..\dsc\SecureByDefault.dsc.ps1')

SecureByDefault -ApplicationId $ApplicationId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint `
    -Reference $ref -Steps $Steps -OutputPath $OutputPath | Out-Null
Write-Host "MOF compiled to $OutputPath" -ForegroundColor DarkGray

if ($Mode -eq 'Discover') {
    $r = Test-DscConfiguration -ReferenceConfiguration (Join-Path $OutputPath 'localhost.mof') -Detailed
    Write-Host "In desired state: $($r.InDesiredState)" -ForegroundColor $(if ($r.InDesiredState) { 'Green' } else { 'Yellow' })
    $r.ResourcesInDesiredState | ForEach-Object { Write-Host "  [Compliant] $($_.ResourceId)" -ForegroundColor Green }
    $r.ResourcesNotInDesiredState | ForEach-Object { Write-Host "  [Drift    ] $($_.ResourceId)" -ForegroundColor Yellow }
    if (-not $r.InDesiredState) { Write-Host 'Review drift, then re-run with -Mode Enforce.' -ForegroundColor Yellow }
}
else {
    Start-DscConfiguration -Path $OutputPath -Wait -Verbose -Force
}

