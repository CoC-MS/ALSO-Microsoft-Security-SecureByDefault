<#
.SYNOPSIS
  ALSO Secure by Default - tenant-wide Microsoft 365 baseline automation.

.DESCRIPTION
  Automates tenant settings not covered by ALSO JSON configuration files.
  Default mode is Discover (read-only). Use -Mode Enforce to apply changes;
  each change is confirmed step by step (-Force skips prompts, -WhatIf dry-runs).


.PARAMETER Mode     Discover (read-only, default) or Enforce.
.PARAMETER Steps    Subset of step ids. Default: all.
.PARAMETER SharePointAdminUrl  e.g. https://contoso-admin.sharepoint.com (derived if omitted).
.PARAMETER OutputPath  Folder for JSON/HTML report.
.PARAMETER PilotGroupId  Optional group id for Intune MDM auto-enrollment (otherwise 'All').
.PARAMETER AdminConsentReviewerIds  User object ids for the admin consent workflow.
.PARAMETER Force    Do not prompt per change in Enforce mode.

.EXAMPLE
  ./Invoke-SecureByDefault.ps1                      # discovery only
  ./Invoke-SecureByDefault.ps1 -Mode Enforce        # guided enforcement
  ./Invoke-SecureByDefault.ps1 -Mode Enforce -Steps AuditLog,Fido2 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Discover', 'Enforce')][string]$Mode = 'Discover',
    [ValidateSet('Licensing', 'AuditLog', 'SecurityDefaults', 'UserSettings', 'Consent', 'BreakGlass', 'Fido2', 'AuthMethods', 'SharePoint',
        'IntuneEnrollment', 'Laps', 'MdoPresets', 'DefenderEndpoint', 'DefenderGuidance')]
    [string[]]$Steps = @('Licensing', 'AuditLog', 'SecurityDefaults', 'UserSettings', 'Consent', 'BreakGlass', 'Fido2', 'AuthMethods', 'SharePoint',
        'IntuneEnrollment', 'Laps', 'MdoPresets', 'DefenderEndpoint', 'DefenderGuidance'),
    [string]$SharePointAdminUrl,
    [string]$OutputPath = (Join-Path (Get-Location) 'sbd-reports'),
    [string]$PilotGroupId,
    [string]$BreakGlassGroupName = 'SRV-EA-ACCOUNTS',
    [string]$BreakGlassAuName = 'Identity-Governance-AU',
    [string[]]$AdminConsentReviewerIds,
    [switch]$Force
)

$banner = @'
    _    _     ____   ___
   / \  | |   / ___| / _ \
  / _ \ | |   \___ \| | | |
 / ___ \| |___ ___) | |_| |   SECURE BY DEFAULT
/_/   \_\_____|____/ \___/    secure from day 1
'@
$banner -split "`n" | ForEach-Object { Write-Host $_ -ForegroundColor Cyan }

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'
$script:Results = [System.Collections.Generic.List[object]]::new()
$script:Reference = Get-Content (Join-Path $PSScriptRoot '..\config\reference-state.json') -Raw | ConvertFrom-Json

#region helpers
$GuideBase = 'https://coc-ms.github.io/ALSO-Microsoft-Security-Fundamentals-and-Copilot-Readiness/'
$BreakGlassPdf = $GuideBase + 'downloads/break-glass-account-best-practices.pdf'

function Add-Result {
    param($Step, $Setting, $Current, $Expected, [ValidateSet('Compliant', 'Drift', 'Fixed', 'Manual', 'Info', 'Error', 'Skipped')]$Status, $Link, $Detail, $Doc, $DocText)
    $script:Results.Add([pscustomobject]@{ Step = $Step; Setting = $Setting; Current = "$Current"; Expected = "$Expected"; Status = $Status; Link = $Link; Detail = "$Detail"; Doc = $Doc; DocText = $(if ($DocText) { $DocText } else { 'Read the ALSO guide' }) })
    $color = @{ Compliant = 'Green'; Fixed = 'Green'; Drift = 'Yellow'; Manual = 'Cyan'; Info = 'Gray'; Error = 'Red'; Skipped = 'DarkGray' }[$Status]
    $msg = switch ($Status) {
        'Compliant' { "${Setting}: $Current" }
        'Fixed'     { "${Setting}: changed from '$Current' to '$Expected'" }
        'Drift'     { "${Setting}: currently '$Current', should be '$Expected'" }
        'Error'     { "${Setting}: could not change from '$Current' to '$Expected'" }
        'Skipped'   { "${Setting}: skipped - $Current" }
        'Info'      { if ($Step -eq 'Licensing') { "${Setting}: $Current" } else { "${Setting}: $Current (reference: $Expected)" } }
        default     { "${Setting}: $Current (reference: $Expected)" }
    }
    Write-Host ("  [{0,-9}] {1}" -f $Status, $msg) -ForegroundColor $color
    if ($Link -and $Status -in 'Manual', 'Drift') { Write-Host "              -> $Link" -ForegroundColor DarkCyan }
    if ($Doc -and $Status -in 'Manual', 'Drift', 'Skipped') { Write-Host "              Guide: $Doc" -ForegroundColor DarkCyan }
}

function Write-Step([string]$Title, [string]$Why) {
    Write-Host "`n== $Title ==" -ForegroundColor Magenta
    Write-Host "   $Why" -ForegroundColor DarkGray
}

function Confirm-Change([string]$Action) {
    if ($Mode -ne 'Enforce') { return $false }
    if (-not $PSCmdlet.ShouldProcess($Action)) { return $false }
    if ($Force) { return $true }
    return ((Read-Host "   Apply: $Action ? [y/N]") -match '^(y|yes)$')
}

function Compare-Setting {
    param($Step, $Setting, $Current, $Expected, [scriptblock]$Fix, $Link, $Detail, $Doc, $DocText)
    if ("$Current" -eq "$Expected") { Add-Result $Step $Setting $Current $Expected Compliant $Link $Detail $Doc $DocText; return }
    if ($Fix -and (Confirm-Change "$Setting - change from '$Current' to '$Expected'")) {
        try { & $Fix; Add-Result $Step $Setting $Current $Expected Fixed $Link $Detail $Doc $DocText }
        catch { Add-Result $Step $Setting $Current $Expected Error $Link $Detail $Doc $DocText; Write-Warning $_.Exception.Message }
    }
    else { Add-Result $Step $Setting $Current $Expected Drift $Link $Detail $Doc $DocText }
}

function Invoke-Safe([string]$Step, [scriptblock]$Body) {
    try { & $Body } catch { Add-Result $Step 'step execution' $_.Exception.Message 'success' Error $null }
}

function Graph($Method, $Uri, $Body) {
    $p = @{ Method = $Method; Uri = $Uri }
    if ($Body) { $p.Body = ($Body | ConvertTo-Json -Depth 10); $p.ContentType = 'application/json' }
    Invoke-MgGraphRequest @p
}

function New-StrongPassword {
    $chars = [char[]](33..126) | Where-Object { $_ -notin [char[]]'"''`\' }
    $bytes = [byte[]]::new(40)
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    -join ($bytes | ForEach-Object { $chars[$_ % $chars.Count] })
}

function Initialize-Module([string]$Name) {
    if (-not (Get-Module -ListAvailable $Name)) {
        Write-Host "   Installing module $Name (CurrentUser)..." -ForegroundColor DarkGray
        Install-Module $Name -Scope CurrentUser -Force -AllowClobber
    }
    if ($Name -like 'Microsoft.Online.SharePoint*' -and $PSVersionTable.PSEdition -eq 'Core') { Import-Module $Name -UseWindowsPowerShell -WarningAction SilentlyContinue -ErrorAction Stop }
    else { Import-Module $Name -ErrorAction Stop }
}
#endregion

#region connections
$graphScopes = if ($Mode -eq 'Enforce') {
    'Policy.ReadWrite.Authorization', 'Policy.ReadWrite.AuthenticationMethod', 'Policy.ReadWrite.ConsentRequest',
    'Policy.ReadWrite.PermissionGrant', 'Policy.ReadWrite.DeviceConfiguration', 'User.ReadWrite.All', 'Group.ReadWrite.All',
    'AdministrativeUnit.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'DeviceManagementServiceConfig.ReadWrite.All',
    'DeviceManagementConfiguration.ReadWrite.All', 'Directory.ReadWrite.All', 'Organization.Read.All',
    'SharePointTenantSettings.ReadWrite.All', 'Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess'
}
else {
    'Policy.Read.All', 'User.Read.All', 'Group.Read.All', 'AdministrativeUnit.Read.All', 'RoleManagement.Read.Directory',
    'DeviceManagementServiceConfig.Read.All',     'DeviceManagementConfiguration.Read.All', 'Directory.Read.All', 'Organization.Read.All',
        'SharePointTenantSettings.Read.All'
    }
    Write-Host "ALSO Secure by Default - mode: $Mode" -ForegroundColor Cyan
if ($Mode -eq 'Discover') { Write-Host "Read-only discovery. Nothing will be changed." -ForegroundColor Green }

Initialize-Module Microsoft.Graph.Authentication
$needsExo = [bool]($Steps | Where-Object { $_ -in 'AuditLog', 'MdoPresets' })
$signInCount = 1 + [int]$needsExo
$script:signInNo = 0
function Show-SignIn([string]$Service, [string]$Why, [string]$Access) {
    $script:signInNo++
    Write-Host ''
    Write-Host "SIGN-IN $($script:signInNo) of ${signInCount}: $Service" -ForegroundColor Yellow
    Write-Host "  Why    : $Why"
    Write-Host "  Access : $Access"
    Write-Host '  A browser window opens. Sign in with your Global Administrator account.'
}

$graphWhy = if ($Mode -eq 'Enforce') {
    'ENFORCE mode: the script will change tenant-wide settings (Entra user settings, consent, authentication methods, break-glass accounts, SharePoint sharing, Intune/Defender connection). You approve every change before it is applied. This sign-in grants the read AND write permissions listed below.'
} else {
    'DISCOVER mode: the script only READS your tenant settings (Entra, Intune, SharePoint, licensing) and compares them with the secure reference. Nothing is changed. This sign-in grants read-only permissions.'
}
Show-SignIn 'Microsoft Graph (Entra ID, Intune, SharePoint settings)' $graphWhy ($graphScopes -join ', ')
Write-Host '  First run only: approve the request for the "Microsoft Graph Command Line Tools" enterprise application ("Consent on behalf of your organization").' -ForegroundColor DarkGray
function Get-BrowserToken([string[]]$Scopes) {
    $clientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'   # Microsoft Graph Command Line Tools
    $port = Get-Random -Minimum 49200 -Maximum 65000
    $redirect = "http://localhost:$port"
    $b64 = { param([byte[]]$b) [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $rand = { param($n) $x = [byte[]]::new($n); $rng.GetBytes($x); & $b64 $x }
    $verifier = & $rand 48
    $challenge = & $b64 ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier)))
    $state = & $rand 16
    $scope = ($Scopes | ForEach-Object { "https://graph.microsoft.com/$_" }) -join ' '
    $auth = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?client_id=$clientId&response_type=code&response_mode=query" +
        "&redirect_uri=$([uri]::EscapeDataString($redirect))&scope=$([uri]::EscapeDataString($scope))&state=$state&code_challenge=$challenge&code_challenge_method=S256&prompt=select_account"
    $listeners = @()
    foreach ($ip in [Net.IPAddress]::Loopback, [Net.IPAddress]::IPv6Loopback) {
        try { $l = [Net.Sockets.TcpListener]::new($ip, $port); $l.Start(); $listeners += $l } catch { }
    }
    if (-not $listeners) { throw "Could not listen on localhost port $port for the sign-in response." }
    try {
        Start-Process $auth
        $deadline = (Get-Date).AddMinutes(5); $client = $null
        while (-not $client -and (Get-Date) -lt $deadline) {
            foreach ($l in $listeners) { if ($l.Pending()) { $client = $l.AcceptTcpClient(); break } }
            if (-not $client) { Start-Sleep -Milliseconds 200 }
        }
        if (-not $client) { throw 'Timed out waiting for browser sign-in (5 minutes).' }
        $stream = $client.GetStream(); $buf = [byte[]]::new(8192); $n = $stream.Read($buf, 0, $buf.Length)
        $line = ([Text.Encoding]::ASCII.GetString($buf, 0, $n) -split "`r?`n")[0]
        $q = [Web.HttpUtility]::ParseQueryString(($line -split ' ')[1].Split('?', 2)[1])
        $ok = [bool]$q['code']
        $msg = if ($ok) { 'Signed in. You can close this tab and return to PowerShell.' } else { 'Sign-in failed. Return to PowerShell for details.' }
        $body = [Text.Encoding]::UTF8.GetBytes("<html><body style='font-family:Segoe UI;margin:3em'><h2>ALSO Secure by Default</h2><p>$msg</p></body></html>")
        $hdr = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/html; charset=utf-8`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n")
        $stream.Write($hdr, 0, $hdr.Length); $stream.Write($body, 0, $body.Length); $stream.Flush(); $client.Close()
        if ($q['error']) { throw "$($q['error']): $($q['error_description'])" }
        if ($q['state'] -ne $state) { throw 'Sign-in response state mismatch.' }
    }
    finally { foreach ($l in $listeners) { $l.Stop() } }
    $tok = Invoke-RestMethod -Method Post -Uri 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token' -Body @{
        client_id = $clientId; grant_type = 'authorization_code'; code = $q['code']; redirect_uri = $redirect; code_verifier = $verifier; scope = $scope }
    $tok.access_token
}

Write-Host '  Opening your default browser for sign-in...' -ForegroundColor DarkGray
try {
    $token = Get-BrowserToken $graphScopes
    Connect-MgGraph -AccessToken (ConvertTo-SecureString $token -AsPlainText -Force) -NoWelcome -ErrorAction Stop
}
catch { throw "Microsoft Graph sign-in failed: $($_.Exception.Message)" }
Write-Host '  Signed in to Microsoft Graph.' -ForegroundColor Green
$gaRole = '62e90394-69f5-4237-9190-012177145e10'
$myRoles = (Graph GET 'https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole?$select=roleTemplateId').value.roleTemplateId
if ($gaRole -notin $myRoles) {
    $msg = 'The signed-in account is not an active Global Administrator. All steps require Global Administrator.'
    if ($Mode -eq 'Enforce') { throw $msg }
    Write-Warning "$msg Discovery results may be incomplete."
}
$org = (Graph GET 'https://graph.microsoft.com/v1.0/organization').value[0]
$initialDomain = ($org.verifiedDomains | Where-Object { $_.isInitial }).name
Write-Host "Tenant: $($org.displayName) ($($org.id)), initial domain: $initialDomain"
if (-not $SharePointAdminUrl) { $SharePointAdminUrl = "https://$($initialDomain.Split('.')[0])-admin.sharepoint.com" }

if ($needsExo) {
    Show-SignIn 'Exchange Online / Security & Compliance' $(if ($Mode -eq 'Enforce') { 'ENFORCE mode: turns on the unified audit log and enables Defender for Office 365 preset protection rules, after you approve each change.' } else { 'DISCOVER mode: only READS whether the unified audit log is on and whether Defender for Office 365 preset protection rules are enabled. Nothing is changed.' }) 'Exchange Online administration (Global Administrator role)'
    Initialize-Module ExchangeOnlineManagement
    try { Connect-ExchangeOnline -ShowBanner:$false -DisableWAM -ErrorAction Stop }
    catch { throw "Exchange Online sign-in failed: $($_.Exception.Message)" }
    Write-Host '  Signed in to Exchange Online.' -ForegroundColor Green
}
#endregion

#region steps
function Get-LicenseTier {
    if ($script:LicenseInfo) { return $script:LicenseInfo }
    $skus = @((Graph GET 'https://graph.microsoft.com/v1.0/subscribedSkus').value | Where-Object { $_.capabilityStatus -eq 'Enabled' })
    $parts = @($skus | ForEach-Object { $_.skuPartNumber } | Sort-Object -Unique)
    $plans = @($skus | ForEach-Object { $_.servicePlans } | Where-Object { $_.provisioningStatus -ne 'Disabled' } | ForEach-Object { $_.servicePlanName })
    $fullRx = 'SPE_E5|SPE_E7|M365_E5|ENTERPRISEPREMIUM|M365_E7|DEFENDER.*SUITE|PURVIEW.*SUITE|IDENTITY_THREAT_PROTECTION|EMSPREMIUM|M365_SECURITY_COMPLIANCE|ATA_STANDALONE|DEFENDER_FOR_IDENTITY|MCAS'
    $stdRx = '^SPB$|SPE_E3|ENTERPRISEPACK|SPE_F1|M365_F1|SPE_F3|M365_F3|DESKLESSPACK|O365_BUSINESS_PREMIUM|SMB_BUSINESS_PREMIUM|M365EDU|^EMS$|WIN10_VDA_E3|INTUNE_A'
    $basicRx = 'O365_BUSINESS_ESSENTIALS|O365_BUSINESS$|SMB_BUSINESS_ESSENTIALS|SMB_BUSINESS$|STANDARDPACK|O365_BUSINESS'
    $hasFull = [bool](($parts | Where-Object { $_ -match $fullRx }) -or ($plans | Where-Object { $_ -match '^ATA$|ADALLOM_S_(STANDALONE|DISCOVERY)' }))
    $tier = if ($hasFull) { 'Full' }
    elseif ($parts | Where-Object { $_ -match $stdRx }) { 'Standard' }
    elseif ($parts | Where-Object { $_ -match $basicRx }) { 'Basic' }
    elseif ($plans | Where-Object { $_ -match 'INTUNE_A|WINDEFATP|MDE_SMB|AAD_PREMIUM' }) { 'Standard' }
    else { 'Standard' }
    $script:LicenseInfo = [pscustomobject]@{ Tier = $tier; Skus = ($parts -join ', ') }
    $script:LicenseInfo
}

function Step-Licensing {
    Write-Step 'License check' 'Finds your Microsoft 365 license level so only the recommendations that apply to you today are shown.'
    $lic = Get-LicenseTier
    $desc = @{
        Full     = 'Microsoft 365 E5/E7, Defender or Purview suite - all recommendations apply.'
        Standard = 'Business Premium, E3, F3 or F1 - all recommendations apply except Defender for Identity, Defender for Cloud Apps and app governance.'
        Basic    = 'Business Basic or Standard - Intune and the Defender products (Endpoint, Office 365, Identity, Cloud Apps) are not included, so those recommendations are skipped.'
    }
    Add-Result 'Licensing' 'Detected license level' "$($lic.Tier) ($($lic.Skus))" $desc[$lic.Tier] Info $null $desc[$lic.Tier]
    Write-Host "   $($desc[$lic.Tier])" -ForegroundColor Cyan
}

function Step-AuditLog {
    Write-Step 'Unified audit log' 'Required for investigations, Defender and Purview.'
    $cfg = Get-AdminAuditLogConfig
    Compare-Setting 'AuditLog' 'UnifiedAuditLogIngestionEnabled' $cfg.UnifiedAuditLogIngestionEnabled 'True' {
        Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
    } 'https://purview.microsoft.com/audit/auditsearch'
}

function YN($v) { if ($v -eq $true) { 'Yes' } elseif ($v -eq $false) { 'No' } else { 'Unknown' } }
function Cap($s) { if ($s) { "$s".Substring(0, 1).ToUpper() + "$s".Substring(1) } else { 'Unknown' } }
$script:GuestRoles = @{
    'a0b1b346-4d3e-4e8b-98f8-753987be4970' = 'Same access as members (most inclusive)'
    '10dae51f-b6af-4016-8d66-8c2a99b929b3' = 'Limited access to properties and memberships of directory objects (default)'
    '2af84b1e-32c8-42b7-82bc-daa82404023b' = 'Restricted access to properties and memberships of directory objects (most restrictive)'
}
function Get-GuestRoleName($id) { if ($script:GuestRoles.ContainsKey("$id")) { $script:GuestRoles["$id"] } else { "Unknown role ($id)" } }

function Step-SecurityDefaults {
    Write-Step 'Security defaults' 'Microsoft free baseline MFA. Should be replaced by ALSO Conditional Access baseline for full control.'
    $link = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/EntraProperties.ReactView'
    $doc = $GuideBase + '#identity-policies'
    $uri = 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
    $sd = Graph GET $uri
    $ca = @((Graph GET 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$select=id').value)
    $why = 'Security defaults gives every user baseline MFA but cannot be customised (no break-glass exclusions, no authentication strengths, no device or location rules). Conditional Access and security defaults cannot be used together. Recommended: deploy ALSO''s Conditional Access baseline (step 10, Identity and access, in the ALSO guide), then turn security defaults OFF. If no Conditional Access policies exist, keep security defaults ON so the tenant is never left without MFA.'
    if ($sd.isEnabled -eq $true) {
        Add-Result 'SecurityDefaults' 'Security defaults' 'On' 'On until ALSO Conditional Access baseline is deployed, then Off' Manual $link $why $doc 'ALSO guide: Conditional Access baseline (step 10)'
    }
    elseif ($ca.Count -gt 0) {
        Add-Result 'SecurityDefaults' 'Security defaults' "Off - $($ca.Count) Conditional Access policies in use" 'Off with Conditional Access in use' Compliant $link $why $doc 'ALSO guide: Conditional Access baseline (step 10)'
    }
    else {
        Compare-Setting 'SecurityDefaults' 'Security defaults' 'Off (and no Conditional Access policies exist)' 'On until ALSO Conditional Access baseline is deployed' {
            Graph PATCH $uri @{ isEnabled = $true } | Out-Null
            Write-Host '   Security defaults is now ON. When you deploy the ALSO Conditional Access baseline (step 10 in the ALSO guide), turn security defaults OFF again.' -ForegroundColor Yellow
            Write-Host "   Guide: $doc" -ForegroundColor DarkCyan
        } $link $why $doc 'ALSO guide: Conditional Access baseline (step 10)'
    }
}

function Step-UserSettings {
    Write-Step 'Entra user settings & external collaboration' 'Default user permissions and guest restrictions.'
    $ref = $script:Reference.userSettings
    $uri = 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
    $p = Graph GET $uri
    $d = $p.defaultUserRolePermissions
    $link = 'https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/UserSettings'
    Compare-Setting 'UserSettings' 'Users can register applications' (YN $d.allowedToCreateApps) (YN $ref.usersCanRegisterApps) { Graph PATCH $uri @{ defaultUserRolePermissions = @{ allowedToCreateApps = $ref.usersCanRegisterApps } } } $link
    Compare-Setting 'UserSettings' 'Restrict non-admin users from creating tenants' (YN (-not $d.allowedToCreateTenants)) (YN $ref.restrictTenantCreation) { Graph PATCH $uri @{ defaultUserRolePermissions = @{ allowedToCreateTenants = (-not $ref.restrictTenantCreation) } } } $link
    Compare-Setting 'UserSettings' 'Users can create security groups' (YN $d.allowedToCreateSecurityGroups) (YN $ref.usersCanCreateSecurityGroups) { Graph PATCH $uri @{ defaultUserRolePermissions = @{ allowedToCreateSecurityGroups = $ref.usersCanCreateSecurityGroups } } } $link
    Compare-Setting 'UserSettings' 'Guest user access restrictions' (Get-GuestRoleName $p.guestUserRoleId) (Get-GuestRoleName $ref.guestUserRoleId) { Graph PATCH $uri @{ guestUserRoleId = $ref.guestUserRoleId } } 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AllowlistPolicyBlade'
    try {
        $buri = 'https://graph.microsoft.com/beta/policies/authorizationPolicy'
        $beta = Graph GET $buri
        $patchUri = $buri
        if ($beta.value) { $beta = @($beta.value)[0]; $patchUri = "$buri/$($beta.id)" }
        $prop = @($beta.defaultUserRolePermissions.Keys) | Where-Object { $_ -match 'agentIdentityBlueprint' } | Select-Object -First 1
        if ($prop) {
            Compare-Setting 'UserSettings' 'Users can register agent identity blueprints' (YN $beta.defaultUserRolePermissions[$prop]) (YN $ref.usersCanRegisterAgentBlueprints) {
                Graph PATCH $patchUri @{ defaultUserRolePermissions = @{ $prop = $ref.usersCanRegisterAgentBlueprints } } } $link
        }
        else { Add-Result 'UserSettings' 'Users can register agent identity blueprints' 'Not exposed by this tenant API' (YN $ref.usersCanRegisterAgentBlueprints) Manual $link }
    }
    catch { Add-Result 'UserSettings' 'Users can register agent identity blueprints' "Not readable: $($_.Exception.Message)" (YN $ref.usersCanRegisterAgentBlueprints) Manual $link }
    try {
        $ux = 'https://graph.microsoft.com/beta/admin/entra/uxSetting'
        $u = Graph GET $ux
        Compare-Setting 'UserSettings' 'Restrict access to Microsoft Entra admin center' (YN $u.restrictNonAdminAccess) $ref.restrictAdminCenter {
            Graph PATCH $ux @{ restrictNonAdminAccess = ($ref.restrictAdminCenter -eq 'Yes') } | Out-Null } $link
    }
    catch { Add-Result 'UserSettings' 'Restrict access to Microsoft Entra admin center' "Not readable: $($_.Exception.Message)" $ref.restrictAdminCenter Manual $link }
    Add-Result 'UserSettings' 'Allow users to connect work or school account with LinkedIn' 'Cannot be read automatically (no Microsoft API)' "$($ref.linkedIn) - business/privacy decision" Manual $link
    Add-Result 'UserSettings' 'Show keep user signed in' 'Cannot be read automatically (no Microsoft API)' $ref.showKeepSignedIn Manual 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/CompanyBrandingMenuBlade/~/CompanyBranding'
}

function Step-Consent {
    Write-Step 'User consent & admin consent workflow' 'Limit OAuth consent phishing.'
    $ref = $script:Reference.consent
    $uri = 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
    $p = Graph GET $uri
    $assigned = @($p.defaultUserRolePermissions.permissionGrantPoliciesAssigned)
    $low = $ref.userConsentPolicy
    $ok = ($low -in $assigned) -and -not ($assigned | Where-Object { $_ -match 'microsoft-user-default-legacy' })
    Compare-Setting 'Consent' 'User consent limited to low-risk (verified publishers)' $ok 'True' {
        $keep = @($assigned | Where-Object { $_ -notmatch '^ManagePermissionGrantsForSelf\.' })
        Graph PATCH $uri @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @($low) + $keep } }
    } 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/UserSettings'
    $w = Graph GET 'https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy'
    Compare-Setting 'Consent' 'Admin consent request workflow enabled' $w.isEnabled 'True' {
        if (-not $AdminConsentReviewerIds) { throw 'Provide -AdminConsentReviewerIds (user object ids) to enable the workflow.' }
        Graph PUT 'https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy' @{
            isEnabled = $true; notifyReviewers = $true; remindersEnabled = $true; requestDurationInDays = $ref.requestDurationInDays
            reviewers = @($AdminConsentReviewerIds | ForEach-Object { @{ query = "/users/$_"; queryType = 'MicrosoftGraph' } })
        }
    } 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/AdminConsentSettings'
}

function Step-BreakGlass {
    Write-Step 'Emergency access (break-glass) accounts' '2 cloud-only Global Admins on onmicrosoft.com, group, restricted-management AU.'
    $link = 'https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers'
    $users = @(foreach ($n in $script:Reference.breakGlass.accountNames) {
        $upn = "$n@$initialDomain"
        $u = (Graph GET "https://graph.microsoft.com/v1.0/users?`$filter=userPrincipalName eq '$upn'").value | Select-Object -First 1
        if ($u) { Add-Result 'BreakGlass' "Account $upn" 'exists' 'exists' Compliant $link; $u; continue }
        if (Confirm-Change "Create break-glass account $upn") {
            $pw = New-StrongPassword
            $u = Graph POST 'https://graph.microsoft.com/v1.0/users' @{
                accountEnabled = $true; displayName = "Emergency Access $n"; mailNickname = $n; userPrincipalName = $upn
                passwordPolicies = 'DisablePasswordExpiration'; passwordProfile = @{ password = $pw; forceChangePasswordNextSignIn = $false }
            }
            # Shown once on the console only; never written to reports or logs.
            Write-Host "   >>> ONE-TIME PASSWORD for ${upn}: $pw  (store offline now; not shown again)" -ForegroundColor Black -BackgroundColor Yellow
            Remove-Variable pw
            Add-Result 'BreakGlass' "Account $upn" 'Does not exist' 'Created' Fixed $link; $u
        }
        else { Add-Result 'BreakGlass' "Account $upn" 'Does not exist' 'Should exist' Drift $link }
    })

    $g = (Graph GET "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$BreakGlassGroupName'").value | Select-Object -First 1
    if (-not $g -and (Confirm-Change "Create security group $BreakGlassGroupName")) {
        $g = Graph POST 'https://graph.microsoft.com/v1.0/groups' @{ displayName = $BreakGlassGroupName; mailNickname = ($BreakGlassGroupName -replace '\W', ''); mailEnabled = $false; securityEnabled = $true; description = 'Emergency access accounts' }
        Add-Result 'BreakGlass' 'Security group' 'Does not exist' 'Created' Fixed $null
    }
    elseif ($g) { Add-Result 'BreakGlass' 'Security group' 'exists' 'exists' Compliant $null }
    else { Add-Result 'BreakGlass' 'Security group' 'Does not exist' 'Should exist' Drift $null }

    if ($g) {
        $members = @((Graph GET "https://graph.microsoft.com/v1.0/groups/$($g.id)/members?`$select=id").value.id)
        foreach ($u in $users) {
            if ($u.id -in $members) { continue }
            if (Confirm-Change "Add $($u.userPrincipalName) to $BreakGlassGroupName") {
                Graph POST "https://graph.microsoft.com/v1.0/groups/$($g.id)/members/`$ref" @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($u.id)" } | Out-Null
                Add-Result 'BreakGlass' "Membership $($u.userPrincipalName)" 'Not a member' 'Member of the group' Fixed $null
            }
            else { Add-Result 'BreakGlass' "Membership $($u.userPrincipalName)" 'Not a member' 'Member of the group' Drift $null }
        }
    }

    $gaTemplate = '62e90394-69f5-4237-9190-012177145e10'
    foreach ($u in $users) {
        $has = (Graph GET "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($u.id)' and roleDefinitionId eq '$gaTemplate'").value
        if ($has) { Add-Result 'BreakGlass' "Global Admin $($u.userPrincipalName)" 'assigned' 'assigned' Compliant $null; continue }
        if (Confirm-Change "Assign Global Administrator (permanent) to $($u.userPrincipalName)") {
            Graph POST 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments' @{ principalId = $u.id; roleDefinitionId = $gaTemplate; directoryScopeId = '/' } | Out-Null
            Add-Result 'BreakGlass' "Global Admin $($u.userPrincipalName)" 'Role not assigned' 'Global Administrator assigned' Fixed $null
        }
        else { Add-Result 'BreakGlass' "Global Admin $($u.userPrincipalName)" 'Role not assigned' 'Global Administrator assigned' Drift $null }
    }

    $auLink = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AdministrativeUnitsMenuBlade/~/AdminUnits'
    $au = (Graph GET "https://graph.microsoft.com/v1.0/directory/administrativeUnits?`$filter=displayName eq '$BreakGlassAuName'").value | Select-Object -First 1
    if (-not $au -and (Confirm-Change "Create restricted-management AU $BreakGlassAuName")) {
        $au = Graph POST 'https://graph.microsoft.com/v1.0/directory/administrativeUnits' @{ displayName = $BreakGlassAuName; description = 'Protects emergency access objects'; isMemberManagementRestricted = $true }
        Add-Result 'BreakGlass' 'Restricted management AU' 'Does not exist' 'Created' Fixed $auLink
    }
    elseif ($au) { Compare-Setting 'BreakGlass' 'AU restricted management' $au.isMemberManagementRestricted 'True' $null $auLink }
    else { Add-Result 'BreakGlass' 'Restricted management AU' 'Does not exist' 'Should exist' Drift $auLink }
    if ($au -and $g) {
        $auMembers = @((Graph GET "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$($au.id)/members?`$select=id").value.id)
        if ($g.id -in $auMembers) { Add-Result 'BreakGlass' 'Group in AU' 'yes' 'yes' Compliant $null }
        elseif (Confirm-Change "Add group to AU $BreakGlassAuName") {
            Graph POST "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$($au.id)/members/`$ref" @{ '@odata.id' = "https://graph.microsoft.com/v1.0/groups/$($g.id)" } | Out-Null
            Add-Result 'BreakGlass' 'Group in AU' 'Not in the AU' 'In the AU' Fixed $null
        }
        else { Add-Result 'BreakGlass' 'Group in AU' 'Not in the AU' 'In the AU' Drift $null }
    }
    $bgDoc = 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access'
    $adminLink = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AdministrativeUnitsMenuBlade/~/AdminUnits'
    $caLink = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'
    Add-Result 'BreakGlass' "Add 1-2 trusted admins as administrators of the '$BreakGlassAuName' administrative unit" 'Cannot be checked automatically' "Only these trusted admins can manage the group '$BreakGlassGroupName' and the two break-glass accounts" Manual $adminLink 'The restricted management administrative unit protects the group and both accounts from being changed by regular admins. Only the trusted admins you add as administrators of the unit (Entra ID > Roles and administrators > Administrative units) can reset passwords, change membership or delete them. Add 1-2 trusted admins only.' $BreakGlassPdf 'Break-glass best practices (PDF)'
    Add-Result 'BreakGlass' 'Set up monitoring and an alert on every sign-in of the break-glass accounts' 'Cannot be checked automatically' 'Alert goes to the security team on any sign-in' Manual $bgDoc 'Any sign-in with a break-glass account means something went wrong or an attack is under way. Send sign-in logs to Log Analytics / Sentinel and create an alert rule (or a Defender XDR custom detection) that notifies the security team immediately on every sign-in of either account. Test the alert regularly.' $BreakGlassPdf 'Break-glass best practices (PDF)'
    Add-Result 'BreakGlass' 'Exclude both break-glass accounts (or the group) from ALL Conditional Access policies' 'Cannot be checked automatically' 'Excluded from every Conditional Access policy' Manual $caLink "If a Conditional Access policy breaks sign-in (or MFA is unavailable) the break-glass accounts must still be able to get in. Exclude the group '$BreakGlassGroupName' from every Conditional Access policy, including new ones. Their own protection comes from long random passwords, security keys and monitoring." $BreakGlassPdf 'Break-glass best practices (PDF)'
    Add-Result 'BreakGlass' 'Register at least one FIDO2 security key on EACH break-glass account' 'Cannot be checked automatically' 'Each account has its own registered security key' Manual 'https://mysignins.microsoft.com/security-info' 'The accounts are excluded from Conditional Access, so they need their own phishing-resistant sign-in. Sign in once to each account and register at least one FIDO2 security key per account at My Security Info. Store the keys in separate secure physical locations (for example two safes) and document who may access them.' $BreakGlassPdf 'Break-glass best practices (PDF)'
    if ($Mode -eq 'Enforce') {
        Write-Host ''
        Write-Host '   NEXT STEPS for the break-glass accounts (do these now):' -ForegroundColor Yellow
        Write-Host "   1. Add 1-2 trusted admins to the administrative unit '$BreakGlassAuName' in Entra ID, so only they can manage the group '$BreakGlassGroupName' and the two accounts." -ForegroundColor Yellow
        Write-Host '   2. Set up monitoring and a sign-in alert on both accounts.' -ForegroundColor Yellow
        Write-Host '   3. Exclude both accounts from ALL Conditional Access policies.' -ForegroundColor Yellow
        Write-Host '   4. Register a security key (FIDO2) on each account.' -ForegroundColor Yellow
        Write-Host "   More info (PDF): $BreakGlassPdf" -ForegroundColor DarkCyan
    }
}

function Step-Fido2 {
    Write-Step 'Passkey (FIDO2) authentication method' 'Allow phishing-resistant sign-in for all users.'
    $uri = 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2'
    $f = Graph GET $uri
    Compare-Setting 'Fido2' 'Passkey (FIDO2)' (Cap $f.state) 'Enabled' {
        Graph PATCH $uri @{ '@odata.type' = '#microsoft.graph.fido2AuthenticationMethodConfiguration'; state = 'enabled'; includeTargets = @(@{ targetType = 'group'; id = 'all_users'; isRegistrationRequired = $false }) }
    } 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods' 'Passkeys (FIDO2 security keys) are phishing-resistant and the strongest sign-in method Entra offers. Allow them for all users so people and break-glass accounts can register a key.' ($GuideBase + '#authentication') 'ALSO guide: Allow strong authentication methods (Identity and access, step 6)'
}

function Step-AuthMethods {
    Write-Step 'Authentication methods' 'Passwordless first, then phishing-resistant MFA; weak methods off.'
    $link = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods'
    $base = 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'
    $pol = Graph GET $base
    $names = @{ Fido2 = 'Passkey (FIDO2)'; MicrosoftAuthenticator = 'Microsoft Authenticator'; Sms = 'SMS'; TemporaryAccessPass = 'Temporary Access Pass'
        SoftwareOath = 'Third-party software OATH tokens'; Voice = 'Voice call'; Email = 'Email OTP'; X509Certificate = 'Certificate-based authentication'
        HardwareOath = 'Hardware OATH tokens'; VerifiableCredentials = 'Verified ID'; QRCodePin = 'QR code' }
    $authDoc = $GuideBase + '#authentication'
    $authText = 'ALSO guide: Allow strong authentication methods (Identity and access, step 6)'
    $authWhy = 'Authentication methods decide how users prove who they are. Passwordless and phishing-resistant methods (passkeys, Authenticator, Temporary Access Pass) should be on; weak methods that can be intercepted (SMS, voice, email OTP) should be off. Methods marked Review depend on your organization. Read ALSO''s recommendations for the full reasoning.'
    $wanted = @{ Fido2 = 'enabled'; MicrosoftAuthenticator = 'enabled'; TemporaryAccessPass = 'enabled'; Sms = 'disabled'; Voice = 'disabled'; Email = 'disabled' }
    foreach ($m in $pol.authenticationMethodConfigurations) {
        $mid = $m.id
        if ($mid -eq 'Fido2' -and $Steps -contains 'Fido2') { continue }
        $label = if ($names.ContainsKey($mid)) { $names[$mid] } else { $mid }
        if ($wanted.ContainsKey($mid)) {
            $otype = $m.'@odata.type'
            $newState = $wanted[$mid]
            Compare-Setting 'AuthMethods' $label (Cap $m.state) (Cap $newState) { Graph PATCH "$base/authenticationMethodConfigurations/$mid" @{ '@odata.type' = $otype; state = $newState } | Out-Null } $link $authWhy $authDoc $authText
        }
        else { Add-Result 'AuthMethods' $label (Cap $m.state) 'Review for your organization' Info $link $authWhy $authDoc $authText }
    }
    Add-Result 'AuthMethods' 'Authenticator push is not phishing-resistant' 'Enforce phishing-resistant MFA with Conditional Access authentication strengths' 'Authentication strength policy assigned' Manual 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/AuthStrengths' 'Authenticator push can still be phished by prompt bombing or real-time proxies. For admins and sensitive access, create a Conditional Access policy that requires a phishing-resistant authentication strength (passkeys / FIDO2, Windows Hello, certificates).' $authDoc $authText
}

function Step-SharePoint {
    Write-Step 'SharePoint & OneDrive external sharing' 'Tighten tenant-level sharing (read and set through Microsoft Graph, no extra sign-in).'
    $uri = 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings'
    $t = Graph GET $uri
    $ref = $script:Reference.sharePoint
    $link = "$SharePointAdminUrl/_layouts/15/online/AdminHome.aspx#/sharing"
    $levels = @{ disabled = 'Only people in your organization (no external sharing)'; existingExternalUserSharingOnly = 'Existing guests only'
        externalUserSharingOnly = 'New and existing guests (sign-in required)'; externalUserAndGuestSharing = 'Anyone (anonymous links allowed)' }
    $wantKey = $ref.sharingCapability.Substring(0, 1).ToLower() + $ref.sharingCapability.Substring(1)
    $curLevel = if ($levels.ContainsKey("$($t.sharingCapability)")) { $levels["$($t.sharingCapability)"] } else { "$($t.sharingCapability)" }
    Compare-Setting 'SharePoint' 'External sharing level (SharePoint and OneDrive)' $curLevel $levels[$wantKey] { Graph PATCH $uri @{ sharingCapability = $wantKey } | Out-Null } $link
    if ($null -ne $t.isResharingByExternalUsersEnabled) {
        Compare-Setting 'SharePoint' 'Guests can share items they do not own' (YN $t.isResharingByExternalUsersEnabled) 'No' { Graph PATCH $uri @{ isResharingByExternalUsersEnabled = $false } | Out-Null } $link
    }
    if ($null -ne $t.isRequireAcceptingUserToMatchInvitedUserEnabled) {
        Compare-Setting 'SharePoint' 'Guests must sign in with the account that was invited' (YN $t.isRequireAcceptingUserToMatchInvitedUserEnabled) 'Yes' { Graph PATCH $uri @{ isRequireAcceptingUserToMatchInvitedUserEnabled = $true } | Out-Null } $link
    }
    if ($null -ne $t.isLegacyAuthProtocolsEnabled) {
        Compare-Setting 'SharePoint' 'Legacy authentication protocols' $(if ($t.isLegacyAuthProtocolsEnabled) { 'Allowed' } else { 'Blocked' }) 'Blocked' { Graph PATCH $uri @{ isLegacyAuthProtocolsEnabled = $false } | Out-Null } $link
    }
    Add-Result 'SharePoint' 'Default sharing link type, anonymous link expiry, guest expiry, OneDrive-specific sharing level' 'Cannot be read automatically (not exposed by Microsoft Graph)' 'Specific people link, links expire in 30 days' Manual $link
}

function Step-IntuneEnrollment {
    Write-Step 'Intune automatic enrollment (MDM user scope)' 'Devices joining Entra are enrolled in Intune automatically.'
    $link = 'https://intune.microsoft.com/#view/Microsoft_AAD_IAM/MdmConfiguration.ReactView'
    $base = 'https://graph.microsoft.com/beta/policies/mobileDeviceManagementPolicies'
    $pol = (Graph GET $base).value | Where-Object { $_.displayName -match 'Intune' } | Select-Object -First 1
    if (-not $pol) { Add-Result 'IntuneEnrollment' 'MDM user scope' 'Intune MDM policy not found' 'Intune' Manual $link; return }
    $scope = @{ all = 'All users'; selected = 'Selected group'; none = 'None' }
    $want = if ($PilotGroupId) { 'selected' } else { 'all' }
    $cur = if ($scope.ContainsKey("$($pol.appliesTo)")) { $scope["$($pol.appliesTo)"] } else { "$($pol.appliesTo)" }
    Compare-Setting 'IntuneEnrollment' 'Automatic MDM enrollment: user scope' $cur $scope[$want] {
        Graph PATCH "$base/$($pol.id)" @{ appliesTo = $want }
        if ($PilotGroupId) { Graph POST "$base/$($pol.id)/includedGroups/`$ref" @{ '@odata.id' = "https://graph.microsoft.com/beta/groups/$PilotGroupId" } | Out-Null }
    } $link
}

function Step-Laps {
    Write-Step 'Local admin & LAPS (Entra device settings)' 'Remove standing local admin; enable Entra LAPS.'
    $link = 'https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings'
    $uri = 'https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy'
    $dr = Graph GET $uri
    $lapsDoc = $GuideBase + '#local-admin'
    $lapsText = 'ALSO guide: LAPS via policy templates (Endpoints, step 4)'
    $lapsWhy = 'Entra LAPS lets devices store a unique, rotating local administrator password in Entra ID, so one stolen local password cannot be reused on other devices. This switch only allows the feature. To actually deploy it, create the Windows LAPS policy in Intune (Endpoint security > Account protection) using ALSO''s policy templates and test password recovery - see step 4 under Endpoint management and protection in the ALSO guide.'
    Compare-Setting 'Laps' 'Enable Microsoft Entra Local Administrator Password Solution (LAPS)' (YN $dr.localAdminPassword.isEnabled) 'Yes' { Graph PATCH $uri @{ localAdminPassword = @{ isEnabled = $true } } } $link $lapsWhy $lapsDoc $lapsText
    $regDoc = $GuideBase + '#device-registration'
    $mfaCur = if ("$($dr.multiFactorAuthConfiguration)" -eq 'required') { 'Yes' } else { 'No' }
    Compare-Setting 'Laps' 'Require multifactor authentication to register or join devices (legacy device setting)' $mfaCur 'No' { Graph PATCH $uri @{ multiFactorAuthConfiguration = 'notRequired' } } $link 'This old per-tenant switch is replaced by a Conditional Access policy (user action: Register or join devices) that requires MFA. The legacy switch and the Conditional Access policy conflict, so the reference state is No here and MFA is enforced through Conditional Access instead. Deploy that policy from ALSO''s templates - see step 1 under Endpoint management and protection in the ALSO guide.' $regDoc 'ALSO guide: MFA when registering devices (Endpoints, step 1)'
    Compare-Setting 'Laps' 'Global administrators become local admin on Entra-joined devices' (YN $dr.azureADJoin.localAdmins.enableGlobalAdmins) 'No' {
        Graph PATCH $uri @{ azureADJoin = @{ localAdmins = @{ enableGlobalAdmins = $false } } } } $link 'Global administrators should not automatically be local admins on every Entra-joined device. This limits the damage if a global admin account is compromised. Use LAPS for controlled local admin access instead.' $lapsDoc $lapsText
    $ru = @{ '#microsoft.graph.noDeviceRegistrationMembership' = 'None (registering user is not local admin)'
        '#microsoft.graph.allDeviceRegistrationMembership' = 'All registering users'
        '#microsoft.graph.enumeratedDeviceRegistrationMembership' = 'Selected users and groups' }
    $curType = "$($dr.azureADJoin.localAdmins.registeringUsers.'@odata.type')"
    $curRu = if ($ru.ContainsKey($curType)) { $ru[$curType] } else { "Unknown ($curType)" }
    Compare-Setting 'Laps' 'Registering user is added as local administrator on join' $curRu $ru['#microsoft.graph.noDeviceRegistrationMembership'] {
        Graph PATCH $uri @{ azureADJoin = @{ localAdmins = @{ registeringUsers = @{ '@odata.type' = '#microsoft.graph.noDeviceRegistrationMembership' } } } } } $link 'The user who joins a device should not become its local administrator. Set to None so users run as standard users.' $lapsDoc $lapsText
}

function Step-MdoPresets {
    Write-Step 'Defender for Office 365 preset security policies' 'Standard/Strict presets for EOP and Safe Links/Attachments.'
    $link = 'https://security.microsoft.com/presetSecurityPolicies'
    $found = $false
    foreach ($kind in 'EOP', 'ATP') {
        $kindName = if ($kind -eq 'EOP') { 'Exchange Online Protection' } else { 'Defender for Office 365' }
        try { $rules = @(& "Get-${kind}ProtectionPolicyRule" -ErrorAction Stop) }
        catch { Add-Result 'MdoPresets' "$kindName preset rules" "Not readable: $($_.Exception.Message)" 'Readable' Manual $link; continue }
        foreach ($r in $rules) {
            $found = $true
            if ($r.Identity -match 'Standard') {
                Compare-Setting 'MdoPresets' "$kindName - $($r.Identity)" (Cap "$($r.State)".ToLower()) 'Enabled' { & "Enable-${kind}ProtectionPolicyRule" -Identity $r.Identity } $link
            }
            else { Add-Result 'MdoPresets' "$kindName - $($r.Identity)" (Cap "$($r.State)".ToLower()) 'Review recipients' Info $link }
        }
    }
    if (-not $found) {
        Add-Result 'MdoPresets' 'Standard preset security policy' 'Not configured' 'Standard preset turned on for all recipients' Manual $link 'Standard preset protection applies Microsoft''s recommended anti-spam, anti-phishing, Safe Links and Safe Attachments settings to all recipients in one step. Microsoft provides no API to create it, so turn it on once in the Defender portal. Then read ALSO''s recommendations for Defender for Office 365 and for SPF, DKIM and DMARC.' ($GuideBase + '#office-protection') 'ALSO guide: Defender for Office 365 protection (Email, apps and collaboration, step 1)'
        Add-Result 'MdoPresets' 'SPF, DKIM and DMARC email authentication' 'Cannot be checked automatically' 'Configured for every sending domain' Manual 'https://security.microsoft.com/authentication' 'SPF, DKIM and DMARC stop others from spoofing your domains and improve delivery of your own mail. Verify each domain in the Defender portal and in your DNS.' ($GuideBase + '#email-authentication') 'ALSO guide: SPF, DKIM and DMARC (Email, apps and collaboration, step 2)'
        Write-Host '   Microsoft does not allow creating the preset policies through any API or PowerShell cmdlet. Turn Standard protection on once in the Defender portal (Preset security policies > Standard protection > Manage). After that, this script can verify and enable/disable it.' -ForegroundColor DarkGray
    }
}

function Step-DefenderEndpoint {
    Write-Step 'Defender for Endpoint & Intune connection' 'Verify provisioning and connector status.'
    $atp = 'https://intune.microsoft.com/#view/Microsoft_Intune_Workflows/SecurityManagementMenu/~/atp'
    try {
        $skus = (Graph GET 'https://graph.microsoft.com/v1.0/subscribedSkus').value
        $plans = @($skus | Where-Object { $_.capabilityStatus -eq 'Enabled' } | ForEach-Object { $_.servicePlans } | Where-Object { $_.servicePlanName -match 'WINDEFATP|MDE_SMB|MDE_LITE|DEFENDER_ENDPOINT' -and $_.provisioningStatus -eq 'Success' })
        Compare-Setting 'DefenderEndpoint' 'Defender for Business / Endpoint licensed and provisioned' $(if ($plans) { 'Licensed and provisioned' } else { 'No Defender for Endpoint licence found' }) 'Licensed and provisioned' $null 'https://security.microsoft.com/machines?category=all-devices'
    }
    catch { Add-Result 'DefenderEndpoint' 'Defender for Business / Endpoint licensed and provisioned' "Not readable: $($_.Exception.Message)" 'Licensed and provisioned' Manual 'https://security.microsoft.com/machines?category=all-devices' }
    try {
        $c = @((Graph GET 'https://graph.microsoft.com/beta/deviceManagement/mobileThreatDefenseConnectors').value)
        if (-not $c) { Add-Result 'DefenderEndpoint' 'Intune connection to Defender for Endpoint' 'No connector exists yet' 'Connected' Manual 'https://security.microsoft.com/securitysettings/endpoints/integration'; Write-Host '   Turn on "Microsoft Intune connection" once in the Defender portal (Settings > Endpoints > Advanced features); this creates the connector, after which this script can verify and enable it.' -ForegroundColor DarkGray }
        foreach ($x in $c) {
            $cid = $x.id
            $cur = if ($x.partnerState -eq 'enabled') { 'Connected' } else { "Not connected (status: $($x.partnerState))" }
            Compare-Setting 'DefenderEndpoint' 'Intune connection to Defender for Endpoint' $cur 'Connected' {
                Graph PATCH "https://graph.microsoft.com/beta/deviceManagement/mobileThreatDefenseConnectors/$cid" @{ partnerState = 'enabled'; windowsEnabled = $true; androidEnabled = $true; iosEnabled = $true; macEnabled = $true; microsoftDefenderForEndpointAttachEnabled = $true } | Out-Null
            } $atp
        }
    }
    catch { Add-Result 'DefenderEndpoint' 'Intune connection to Defender for Endpoint' "Not readable: $($_.Exception.Message)" 'Connected' Manual $atp }
}

function Step-DefenderGuidance {
    Write-Step 'Defender XDR guidance' 'Settings Microsoft offers only in the portal (no public API to read or set them).'
    $na = 'Cannot be read automatically (no Microsoft API)'
    Add-Result 'DefenderGuidance' 'Incident email notifications to the right people' $na 'Configured' Manual 'https://security.microsoft.com/securitysettings/defender/email_notifications' 'Make sure the right people (security team or your partner) receive Defender incident emails so high-severity incidents are not missed. Also make sure alert policies notify a monitored mailbox.' ($GuideBase + '#alerts') 'ALSO guide: Make sure Defender alerts reach the right people (Email, apps and collaboration, step 3)'

    $need = 'requires Microsoft 365 E5/E7, the Defender or Purview suite, or a standalone license'
    $hasMdi = ((Get-LicenseTier).Tier -eq 'Full')
    $hasMda = $hasMdi
    $mdiLink = 'https://security.microsoft.com/securitysettings/identities'
    $mdiText = 'ALSO guide: Defender for Identity (Extend identity, step 1)'
    $mcaText = 'ALSO guide: Integrate Defender for Cloud Apps with Defender for Endpoint (Email, apps and collaboration, step 1 of the E5 section)'
    $agText = 'ALSO guide: Configure app governance (Email, apps and collaboration, step 3 of the E5 section)'
    if ($hasMdi) {
        Add-Result 'DefenderGuidance' 'Defender for Identity readiness / sensor deployment' $na 'Ready' Manual $mdiLink 'Defender for Identity watches domain controllers and Entra for identity attacks. Deploy sensors on domain controllers and check the health status in the Defender portal.' ($GuideBase + '#defender-identity') $mdiText
    }
    else { Add-Result 'DefenderGuidance' 'Defender for Identity readiness / sensor deployment' "No license found - Defender for Identity $need" 'Skipped (not licensed)' Skipped $mdiLink 'Defender for Identity is not licensed in this tenant, so this step is skipped.' ($GuideBase + '#defender-identity') $mdiText }
    if ($hasMda) {
        Add-Result 'DefenderGuidance' 'Defender for Cloud Apps and Defender for Endpoint integration' $na 'Enabled' Manual 'https://security.microsoft.com/cloudapps/settings?tabid=mdatp' 'Integrating Defender for Cloud Apps with Defender for Endpoint lets you discover and block unsanctioned cloud apps from managed devices.' ($GuideBase + '#cloud-apps') $mcaText
        Add-Result 'DefenderGuidance' 'App governance / OAuth app policies' $na 'Turned on' Manual 'https://security.microsoft.com/cloudapps/app-governance' 'App governance detects risky or over-privileged OAuth apps and lets you create policies to alert on or disable them.' ($GuideBase + '#app-governance') $agText
    }
    else {
        Add-Result 'DefenderGuidance' 'Defender for Cloud Apps and Defender for Endpoint integration' "No license found - Defender for Cloud Apps $need" 'Skipped (not licensed)' Skipped 'https://security.microsoft.com/cloudapps/settings?tabid=mdatp' 'Defender for Cloud Apps is not licensed in this tenant, so this step is skipped.' ($GuideBase + '#cloud-apps') $mcaText
        Add-Result 'DefenderGuidance' 'App governance / OAuth app policies' "No license found - app governance $need (Defender for Cloud Apps)" 'Skipped (not licensed)' Skipped 'https://security.microsoft.com/cloudapps/app-governance' 'App governance is an add-on to Defender for Cloud Apps and is not available without it, so this step is skipped.' ($GuideBase + '#app-governance') $agText
    }
}
#endregion

$basicSkip = 'IntuneEnrollment', 'MdoPresets', 'DefenderEndpoint', 'DefenderGuidance'
foreach ($s in $Steps) {
    if ($s -in $basicSkip) {
        $tier = $null
        try { $tier = (Get-LicenseTier).Tier } catch { }
        if ($tier -eq 'Basic') {
            Write-Step "$s (skipped)" 'Not part of Business Basic / Standard licenses.'
            Add-Result $s 'Intune / Defender recommendations' 'Not included in Business Basic or Standard licenses' 'Requires Business Premium, E3/E5 or a Defender suite' Skipped $null 'Intune and the Defender products are not part of this license level, so these recommendations are skipped. Upgrade the license (for example Microsoft 365 Business Premium) to use them.'
            continue
        }
    }
    Invoke-Safe $s { & "Step-$s" }
}

#region report
New-Item -ItemType Directory -Force $OutputPath | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$json = Join-Path $OutputPath "sbd-$Mode-$stamp.json"
$html = Join-Path $OutputPath "sbd-$Mode-$stamp.html"
$script:Results | ConvertTo-Json -Depth 4 | Set-Content $json -Encoding UTF8
$enc = { param($s) [Net.WebUtility]::HtmlEncode("$s") }
$cats = [ordered]@{
    AuditLog = 'Auditing & compliance'; SecurityDefaults = 'Identity: users & external collaboration'; UserSettings = 'Identity: users & external collaboration'; Consent = 'Identity: app consent'
    BreakGlass = 'Identity: emergency access'; Fido2 = 'Authentication'; AuthMethods = 'Authentication'
    SharePoint = 'Collaboration: SharePoint & OneDrive'; IntuneEnrollment = 'Devices: Intune & LAPS'; Laps = 'Devices: Intune & LAPS'
    MdoPresets = 'Defender'; DefenderEndpoint = 'Defender'; DefenderGuidance = 'Defender'
}
$label = @{ Compliant = 'Compliant'; Fixed = 'Fixed'; Drift = 'Needs change'; Manual = 'Manual action'; Info = 'Info'; Error = 'Error'; Skipped = 'Skipped' }
$reportResults = @($script:Results | Where-Object Step -ne 'Licensing')
$total = $reportResults.Count
$cards = foreach ($st in 'Compliant', 'Fixed', 'Drift', 'Manual', 'Info', 'Skipped', 'Error') {
    $n = @($reportResults | Where-Object Status -eq $st).Count
    "<div class='card $st'><b>$n</b><span>$($label[$st])</span></div>"
}
$buildSections = {
    param([bool]$ManualOnly)
    foreach ($cat in ($cats.Values | Select-Object -Unique)) {
    $items = @($script:Results | Where-Object { $cats[$_.Step] -eq $cat -and (($_.Status -eq 'Manual') -eq $ManualOnly) })
    if (-not $items) { continue }
    $bad = @($items | Where-Object { $_.Status -in 'Drift', 'Error' }).Count
    $badge = if ($ManualOnly) { "<span class='pill Manual'>$($items.Count) to do</span>" } elseif ($bad) { "<span class='pill Drift'>$bad to fix</span>" } else { "<span class='pill Compliant'>all good</span>" }
    $rows = foreach ($r in $items) {
        $l = if ($r.Link) { "<a href='$(& $enc $r.Link)' target='_blank'>Open in portal &rarr;</a>" } else { '' }
        $d = if ($r.Detail) { "<div class='why'>$(& $enc $r.Detail)$(if ($r.Doc) { " <a href='$(& $enc $r.Doc)' target='_blank'>$(& $enc $r.DocText) &rarr;</a>" })</div>" } else { '' }
        "<tr><td class='st'><span class='pill $($r.Status)'>$($label[$r.Status])</span></td><td><b>$(& $enc $r.Setting)</b>$d</td><td>$(& $enc $r.Current)</td><td>$(& $enc $r.Expected)</td><td>$l</td></tr>"
    }
    "<section><h2>$(& $enc $cat) $badge</h2><table><tr><th>State</th><th>Setting</th><th>Current value</th><th>Expected</th><th></th></tr>$($rows -join '')</table></section>"
    }
}
$autoSections = & $buildSections $false
$manualSections = & $buildSections $true
$manualCount = @($reportResults | Where-Object Status -eq 'Manual').Count
$autoCount = $total - $manualCount
$tabs = "<div class='tabs'><button class='tab on' data-t='auto' onclick=""sw('auto')"">Automated checks and actions ($autoCount)</button><button class='tab' data-t='manual' onclick=""sw('manual')"">Manual checks and actions ($manualCount)</button></div>"
$manualIntro = "<p class='intro'>These items cannot be read or changed automatically because Microsoft offers no API for them, or they need a person to decide. Work through them in the portal using the links and guides.</p>"
$js = "function sw(t){document.querySelectorAll('.pane').forEach(function(e){e.style.display=e.id===t?'block':'none'});document.querySelectorAll('.tab').forEach(function(b){b.classList.toggle('on',b.dataset.t===t)})}"
$css = @'
body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f5f7fa;color:#1d2b3a}
header{background:#fff;border-bottom:1px solid #dde3ea;padding:20px 40px}
header h1{margin:0;font-size:1.5rem}header p{margin:4px 0 0;color:#5b6b7c}
main{max-width:1200px;margin:24px auto;padding:0 24px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-bottom:24px}
.tabs{display:flex;gap:8px;margin-bottom:18px;border-bottom:2px solid #dde3ea}.tab{background:none;border:0;padding:10px 18px;font-size:1rem;font-weight:600;color:#5b6b7c;cursor:pointer;border-bottom:3px solid transparent;margin-bottom:-2px}.tab.on{color:#00757d;border-bottom-color:#00757d}.intro{color:#5b6b7c;max-width:820px}
.card{min-width:0;background:#fff;border:1px solid #dde3ea;border-radius:10px;padding:14px 18px;border-top:4px solid #9aa7b4}
.card b{display:block;font-size:1.8rem}.card span{color:#5b6b7c;font-size:.85rem}
.card.Compliant,.card.Fixed{border-top-color:#2e8b57}.card.Drift{border-top-color:#d98e04}.card.Manual{border-top-color:#00757d}.card.Error{border-top-color:#c0392b}
section{background:#fff;border:1px solid #dde3ea;border-radius:10px;margin-bottom:20px;padding:6px 18px 14px}
h2{font-size:1.15rem;display:flex;align-items:center;gap:10px}
table{border-collapse:collapse;width:100%}th{text-align:left;font-size:.78rem;text-transform:uppercase;color:#5b6b7c;padding:6px 8px;border-bottom:2px solid #e6ebf0}
td{padding:9px 8px;border-bottom:1px solid #eef2f6;vertical-align:top;font-size:.9rem;word-break:break-word}td.st{white-space:nowrap}
.why{margin-top:6px;font-size:.82rem;font-weight:400;color:#4a5a6a;line-height:1.45}a{color:#0b5cab;text-decoration:none}a:hover{text-decoration:underline}
.next{background:#fff;border:1px solid #dde3ea;border-left:5px solid #00757d;border-radius:10px;padding:8px 24px 22px;margin:28px 0}.next p{color:#5b6b7c;max-width:760px}.btn{display:inline-block;background:#0b5cab;color:#fff!important;padding:10px 20px;border-radius:8px;font-weight:600}.btn:hover{text-decoration:none;background:#094a8c}
.pill{display:inline-block;padding:2px 10px;border-radius:12px;font-size:.78rem;font-weight:600;color:#fff;background:#9aa7b4}
.pill.Compliant,.pill.Fixed{background:#2e8b57}.pill.Drift{background:#d98e04}.pill.Manual{background:#00757d}.pill.Error{background:#c0392b}
'@
$nextBox = if ($Mode -eq 'Enforce') { "<div class='next'><h2>Done reviewing these settings? Continue with deeper configuration.</h2><p>Secure by Default sets the tenant-wide prerequisites. Next, use the ALSO Microsoft Security Policy Templates Navigator to choose the policy templates and configuration that fit your licenses and platforms.</p><a class='btn' href='https://coc-ms.github.io/ALSO-security-policy-templates-navigator/' target='_blank'>Open the Navigator &rarr;</a></div>" } else { '' }
$page = "<!DOCTYPE html><html><head><meta charset='utf-8'><title>ALSO Secure by Default report</title><style>$css</style></head><body><header><h1>ALSO Secure by Default &ndash; $Mode report</h1><p>$(& $enc $org.displayName) &middot; $(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; $total settings checked</p></header><main><div class='cards'>$($cards -join '')</div>$tabs<div class='pane' id='auto'>$($autoSections -join '')</div><div class='pane' id='manual' style='display:none'>$manualIntro$($manualSections -join '')</div>$nextBox</main><script>$js</script></body></html>"
[IO.File]::WriteAllText($html, $page, (New-Object Text.UTF8Encoding($false)))

Write-Host "`nSummary:" -ForegroundColor Cyan
$script:Results | Group-Object Status | ForEach-Object { Write-Host ("  {0,-10} {1}" -f $_.Name, $_.Count) }
Write-Host "Reports: $json`n         $html"
if ($Mode -eq 'Enforce') {
    Write-Host "`nDone? Continue with deeper configuration in the ALSO Policy Templates Navigator:" -ForegroundColor Cyan
    Write-Host '  https://coc-ms.github.io/ALSO-security-policy-templates-navigator/' -ForegroundColor Cyan
}
try { Invoke-Item $html } catch { Write-Host "Open the HTML report manually: $html" -ForegroundColor Yellow }
if ($Mode -eq 'Discover') {
    $driftSteps = @($script:Results | Where-Object Status -eq 'Drift' | Select-Object -ExpandProperty Step -Unique)
    if ($driftSteps) {
        Write-Host "`nDrift found in: $($driftSteps -join ', ')" -ForegroundColor Yellow
        Write-Host 'Enforce mode changes settings one at a time and asks you to confirm each change. It needs a new Global Administrator sign-in with write permissions.'
        if ((Read-Host 'Do you want to proceed with step-by-step enforce mode? [y/N]') -match '^(y|yes)$') {
            # A fresh process gives a clean sign-in; re-using this one breaks the interactive sign-in.
            $q = { param($v) "'" + ("$v" -replace "'", "''") + "'" }
            $argText = "-Mode Enforce -Steps $(($driftSteps | ForEach-Object { & $q $_ }) -join ',') -OutputPath $(& $q $OutputPath) -BreakGlassGroupName $(& $q $BreakGlassGroupName) -BreakGlassAuName $(& $q $BreakGlassAuName)"
            if ($PSBoundParameters.ContainsKey('SharePointAdminUrl')) { $argText += " -SharePointAdminUrl $(& $q $SharePointAdminUrl)" }
            if ($PSBoundParameters.ContainsKey('PilotGroupId')) { $argText += " -PilotGroupId $(& $q $PilotGroupId)" }
            if ($PSBoundParameters.ContainsKey('AdminConsentReviewerIds')) { $argText += " -AdminConsentReviewerIds $(($AdminConsentReviewerIds | ForEach-Object { & $q $_ }) -join ',')" }
            if ($Force) { $argText += ' -Force' }
            if ($WhatIfPreference) { $argText += ' -WhatIf' }
            $exe = (Get-Process -Id $PID).Path
            & $exe -NoProfile -ExecutionPolicy Bypass -Command "& $(& $q $PSCommandPath) $argText"
        }
        else { Write-Host 'No changes made. Re-run with -Mode Enforce whenever you are ready.' -ForegroundColor Green }
    }
}
#endregion

