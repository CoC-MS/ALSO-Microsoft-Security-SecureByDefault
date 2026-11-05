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
    [ValidateSet('Licensing', 'AuditLog', 'SecurityDefaults', 'UserSettings', 'Consent', 'BreakGlass', 'ConditionalAccess', 'PrivilegedAccess', 'Fido2', 'AuthMethods', 'SharePoint',
        'IntuneEnrollment', 'Laps', 'IntunePolicies', 'MdoPresets', 'DefenderEndpoint', 'DefenderGuidance', 'Purview', 'GuideManual')]
    [string[]]$Steps = @('Licensing', 'AuditLog', 'SecurityDefaults', 'UserSettings', 'Consent', 'BreakGlass', 'ConditionalAccess', 'PrivilegedAccess', 'Fido2', 'AuthMethods', 'SharePoint',
        'IntuneEnrollment', 'Laps', 'IntunePolicies', 'MdoPresets', 'DefenderEndpoint', 'DefenderGuidance', 'Purview', 'GuideManual'),
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
    $script:Results.Add([pscustomobject]@{ Step = $Step; Setting = $Setting; Current = "$Current"; Expected = "$Expected"; Status = $Status; Link = $Link; Detail = "$Detail"; Group = $script:Group; Doc = $Doc; DocText = $(if ($DocText) { $DocText } else { 'Read the ALSO guide' }) })
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

function Set-Group([string]$Name) { $script:Group = $Name }

function Write-Step([string]$Title, [string]$Why) {
    $script:Group = $null
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
    try { & $Body } catch { Add-Result $Step 'Step could not be completed' "$($_.Exception.Message) (script line $($_.InvocationInfo.ScriptLineNumber))" 'Completed' Error $null 'The step stopped unexpectedly. The checks before this point are still listed. Send this message to ALSO if it persists.' }
}

function Graph($Method, $Uri, $Body) {
    $p = @{ Method = $Method; Uri = $Uri }
    if ($Body) { $p.Body = ($Body | ConvertTo-Json -Depth 30); $p.ContentType = 'application/json' }
    try { Invoke-MgGraphRequest @p }
    catch {
        $m = $_.Exception.Message
        if ($_.ErrorDetails.Message) { try { $m = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message } catch { $m = $_.ErrorDetails.Message } }
        throw "$m [$Method $(($Uri -split '\?')[0] -replace 'https://graph.microsoft.com/','')]"
    }
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
    'SharePointTenantSettings.ReadWrite.All', 'Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess',
    'DeviceManagementApps.ReadWrite.All', 'Application.Read.All', 'AccessReview.Read.All'
}
else {
    'Policy.Read.All', 'User.Read.All', 'Group.Read.All', 'AdministrativeUnit.Read.All', 'RoleManagement.Read.Directory',
    'DeviceManagementServiceConfig.Read.All',     'DeviceManagementConfiguration.Read.All', 'Directory.Read.All', 'Organization.Read.All',
        'SharePointTenantSettings.Read.All', 'DeviceManagementApps.Read.All', 'Application.Read.All', 'AccessReview.Read.All'
    }
    Write-Host "ALSO Secure by Default - mode: $Mode" -ForegroundColor Cyan
if ($Mode -eq 'Discover') { Write-Host "Read-only discovery. Nothing will be changed." -ForegroundColor Green }

Initialize-Module Microsoft.Graph.Authentication
$needsExo = [bool]($Steps | Where-Object { $_ -in 'AuditLog', 'MdoPresets' })
$needsPurview = [bool]($Steps -contains 'Purview')
$signInCount = 1 + [int]$needsExo + [int]$needsPurview
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
if ($needsPurview) {
    Show-SignIn 'Microsoft Purview (Security & Compliance)' $(if ($Mode -eq 'Enforce') { 'ENFORCE mode: checks whether the ALSO Purview baseline (sensitivity labels, label policy, DLP and retention policies) exists. The baseline itself is deployed with ALSO''s Purview toolkit, so this sign-in is used to read only.' } else { 'DISCOVER mode: only READS sensitivity labels, label policies, DLP and retention policies. Nothing is changed.' }) 'Security & Compliance administration (Global Administrator role)'
    Initialize-Module ExchangeOnlineManagement
    try { Connect-IPPSSession -ShowBanner:$false -DisableWAM -ErrorAction Stop }
    catch {
        if ($_.Exception.Message -match 'parameter') { try { Connect-IPPSSession -ShowBanner:$false -ErrorAction Stop } catch { throw "Purview sign-in failed: $($_.Exception.Message)" } }
        else { throw "Purview sign-in failed: $($_.Exception.Message)" }
    }
    Write-Host '  Signed in to Microsoft Purview.' -ForegroundColor Green
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
    $script:LicenseInfo = [pscustomobject]@{ Tier = $tier; Skus = ($parts -join ', '); HasP2 = [bool]($plans -contains 'AAD_PREMIUM_P2') }
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
    $ca = @((Graph GET 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$select=id,state').value | Where-Object { $_.state -ne 'disabled' })
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
    Write-Step 'Emergency access (break-glass) accounts' 'Two cloud-only Global Admins on onmicrosoft.com, in a security group, inside a restricted-management administrative unit.'
    $start = $script:Results.Count
    $link = 'https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers'
    $pdf = 'Break-glass best practices (PDF)'
    $refUpns = @($script:Reference.breakGlass.accountNames | ForEach-Object { "$_@$initialDomain".ToLower() })
    $gaId = '62e90394-69f5-4237-9190-012177145e10'
    $found = @()
    try {
        $words = 'emergency', 'break', 'breakglass', 'glass', 'bg'
        $q = (($words | ForEach-Object { "`"displayName:$_`" OR `"userPrincipalName:$_`"" }) -join ' OR ')
        $res = Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/users?$count=true&$top=100&$select=id,displayName,userPrincipalName,onPremisesSyncEnabled&$search=' + [uri]::EscapeDataString($q)) -Headers @{ ConsistencyLevel = 'eventual' }
        $found = @($res.value | Where-Object { $_.userPrincipalName.ToLower() -notin $refUpns })
    }
    catch { Write-Warning "Could not search for existing emergency accounts: $($_.Exception.Message)" }

    Set-Group '1. Do you already have emergency accounts?'
    if ($found) {
        Write-Host '   Existing accounts were found. Creating new ones below is optional.' -ForegroundColor Yellow
        $list = ($found | ForEach-Object { $_.userPrincipalName }) -join ', '
        Add-Result 'BreakGlass' 'Accounts that look like emergency accounts' $list 'Each one meets the four checks below' Info $link 'These accounts have emergency, break, breakglass, glass or bg in their name, so they are treated as your existing break-glass accounts. Each one is checked below for the four requirements: cloud-only, permanent Global Administrator, member of a security group, and that group inside a restricted management administrative unit. If they all pass, you do not need the new accounts from section 3.' $BreakGlassPdf $pdf
        Add-Result 'BreakGlass' 'Naming of the existing accounts' 'Names reveal their purpose' 'Generic, unremarkable names' Info $link 'It is not recommended to name break-glass accounts breakglass, emergency or similar: attackers search for those names first. Rename them to something generic (the new accounts from this script are called svr_ea_01 and svr_ea_02).' $BreakGlassPdf $pdf
    }
    else {
        Add-Result 'BreakGlass' 'Accounts that look like emergency accounts' 'None found by name' 'Double-check, then create two if you have none' Manual $link 'No account with emergency, break, breakglass, glass or bg in its name was found. This only means none exist under those names. Look in Entra ID (Users, and Roles and administrators > Global Administrator) for accounts that serve this purpose under another name. If there are none, create the two accounts in section 3 (Enforce mode offers this).' $BreakGlassPdf $pdf
        if ($Mode -eq 'Enforce') { Write-Host '   No accounts named emergency / break / breakglass / bg were found - please double-check in Entra ID first.' -ForegroundColor Yellow }
    }

    foreach ($e in $found) {
        $who = $e.userPrincipalName
        Set-Group "2. Existing account: $who"
        Invoke-Part 'BreakGlass' "Checks for $who" {
            Add-Result 'BreakGlass' "$who is cloud-only" $(if ($e.onPremisesSyncEnabled) { 'No, synced from on-premises' } else { 'Yes' }) 'Yes' $(if ($e.onPremisesSyncEnabled) { 'Drift' } else { 'Compliant' }) $link 'A break-glass account must be cloud-only so it still works when on-premises Active Directory or Entra Connect is down.' $BreakGlassPdf $pdf
            $ga = @((Graph GET "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($e.id)' and roleDefinitionId eq '$gaId'").value)
            Add-Result 'BreakGlass' "$who has a permanent Global Administrator role" $(if ($ga) { 'Yes' } else { 'No' }) 'Yes' $(if ($ga) { 'Compliant' } else { 'Drift' }) $link 'The role must be permanently active, not eligible through PIM and not only inherited through a group, so the account works when other systems fail.' $BreakGlassPdf $pdf
            $grps = @((Graph GET "https://graph.microsoft.com/v1.0/users/$($e.id)/memberOf/microsoft.graph.group?`$select=id,displayName,securityEnabled").value | Where-Object { $_.securityEnabled })
            Add-Result 'BreakGlass' "$who is a member of a security group" $(if ($grps) { ($grps.displayName -join ', ') } else { 'No' }) 'Yes' $(if ($grps) { 'Compliant' } else { 'Drift' }) $link 'A dedicated security group lets you exclude all break-glass accounts from Conditional Access and protect them as one set.' $BreakGlassPdf $pdf
            $auName = ''
            foreach ($gr in $grps) {
                $a = @((Graph GET "https://graph.microsoft.com/v1.0/groups/$($gr.id)/memberOf/microsoft.graph.administrativeUnit?`$select=id,displayName,isMemberManagementRestricted").value | Where-Object { $_.isMemberManagementRestricted })
                if ($a.Count) { $auName = $a[0].displayName }
            }
            Add-Result 'BreakGlass' "The group of $who is inside a restricted management administrative unit" $(if ($auName) { "Yes: $auName" } else { 'No' }) 'Yes' $(if ($auName) { 'Compliant' } else { 'Drift' }) $link 'A restricted management administrative unit (RMAU) means only the trusted admins assigned to it can change the group or its accounts.' $BreakGlassPdf $pdf
        }
    }
    Set-Group '2. Existing emergency security groups'
    Invoke-Part 'BreakGlass' 'Security group search' {
        $gw = 'emergency', 'break', 'breakglass', 'glass', 'bg'
        $gq = (($gw | ForEach-Object { "`"displayName:$_`"" }) -join ' OR ')
        $fg = @((Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/groups?$count=true&$top=50&$select=displayName,securityEnabled&$search=' + [uri]::EscapeDataString($gq)) -Headers @{ ConsistencyLevel = 'eventual' }).value | Where-Object { $_.securityEnabled -and $_.displayName -ne $BreakGlassGroupName })
        if ($fg) { Add-Result 'BreakGlass' 'Security groups that look like break-glass groups' ($fg.displayName -join ', ') 'Contains only the break-glass accounts' Info 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/AllGroups' 'Check that the group contains only the break-glass accounts, is excluded from Conditional Access and sits inside a restricted management administrative unit. Avoid obvious names like breakglass or emergency.' $BreakGlassPdf $pdf }
    }

    Set-Group '3. The two ALSO break-glass accounts'
    $users = @(foreach ($n in $script:Reference.breakGlass.accountNames) {
        $upn = "$n@$initialDomain"
        try {
            $u = (Graph GET "https://graph.microsoft.com/v1.0/users?`$filter=userPrincipalName eq '$upn'").value | Select-Object -First 1
            if ($u) { Add-Result 'BreakGlass' "Account $upn exists" 'Yes' 'Yes' Compliant $link; $u; continue }
            if (Confirm-Change "Create break-glass account $upn") {
                $pw = New-StrongPassword
                $u = Graph POST 'https://graph.microsoft.com/v1.0/users' @{
                    accountEnabled = $true; displayName = "Emergency Access $n"; mailNickname = $n; userPrincipalName = $upn
                    passwordPolicies = 'DisablePasswordExpiration'; passwordProfile = @{ password = $pw; forceChangePasswordNextSignIn = $false }
                }
                Write-Host "   >>> ONE-TIME PASSWORD for ${upn}: $pw  (store offline now; not shown again)" -ForegroundColor Black -BackgroundColor Yellow
                Remove-Variable pw
                Add-Result 'BreakGlass' "Account $upn exists" 'No' 'Created' Fixed $link; $u
            }
            elseif ($found) { Add-Result 'BreakGlass' "Account $upn exists" 'No' 'Optional: create only if your existing accounts fail a check above' Info $link 'You already have accounts that look like break-glass accounts, so creating these two is optional. Create them if an existing account fails any check above.' $BreakGlassPdf $pdf }
            else { Add-Result 'BreakGlass' "Account $upn exists" 'No' 'Yes' Drift $link 'Break-glass accounts guarantee you can still get in if Conditional Access, MFA or federation fails. Enforce mode creates them with a long random password that is shown once on the console.' $BreakGlassPdf $pdf }
        }
        catch { Add-Result 'BreakGlass' "Account $upn" $_.Exception.Message 'Created or found' Error $link }
    })

    Set-Group '4. Security group'
    $g = $null
    Invoke-Part 'BreakGlass' 'Security group' {
        $script:bgG = (Graph GET "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$BreakGlassGroupName'").value | Select-Object -First 1
        if (-not $script:bgG -and (Confirm-Change "Create security group $BreakGlassGroupName")) {
            $script:bgG = Graph POST 'https://graph.microsoft.com/v1.0/groups' @{ displayName = $BreakGlassGroupName; mailNickname = ($BreakGlassGroupName -replace '\W', ''); mailEnabled = $false; securityEnabled = $true; description = 'Emergency access accounts' }
            Add-Result 'BreakGlass' "Security group $BreakGlassGroupName exists" 'No' 'Created' Fixed $null
        }
        elseif ($script:bgG) { Add-Result 'BreakGlass' "Security group $BreakGlassGroupName exists" 'Yes' 'Yes' Compliant $null }
        elseif ($found) { Add-Result 'BreakGlass' "Security group $BreakGlassGroupName exists" 'No' 'Optional: only needed for the new accounts' Info $null 'You already have emergency accounts, so a second group is optional.' $BreakGlassPdf $pdf }
        else { Add-Result 'BreakGlass' "Security group $BreakGlassGroupName exists" 'No' 'Yes' Drift $null 'One group holds all break-glass accounts so they can be excluded from Conditional Access and protected together.' $BreakGlassPdf $pdf }
    }
    $g = $script:bgG
    if ($g) {
        Invoke-Part 'BreakGlass' 'Group membership' {
            $members = @((Graph GET "https://graph.microsoft.com/v1.0/groups/$($g.id)/members?`$select=id").value.id)
            foreach ($u in $users) {
                $nm = "$($u.userPrincipalName) is a member of $BreakGlassGroupName"
                if ($u.id -in $members) { Add-Result 'BreakGlass' $nm 'Yes' 'Yes' Compliant $null; continue }
                if (Confirm-Change "Add $($u.userPrincipalName) to $BreakGlassGroupName") {
                    Graph POST "https://graph.microsoft.com/v1.0/groups/$($g.id)/members/`$ref" @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($u.id)" } | Out-Null
                    Add-Result 'BreakGlass' $nm 'No' 'Added' Fixed $null
                }
                else { Add-Result 'BreakGlass' $nm 'No' 'Yes' Drift $null }
            }
        }
    }

    Set-Group '5. Global Administrator role'
    foreach ($u in $users) {
        Invoke-Part 'BreakGlass' "Role for $($u.userPrincipalName)" {
            $nm = "$($u.userPrincipalName) has a permanent Global Administrator role"
            $has = (Graph GET "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($u.id)' and roleDefinitionId eq '$gaId'").value
            if ($has) { Add-Result 'BreakGlass' $nm 'Yes' 'Yes' Compliant $null; return }
            if (Confirm-Change "Assign Global Administrator (permanent) to $($u.userPrincipalName)") {
                Graph POST 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments' @{ principalId = $u.id; roleDefinitionId = $gaId; directoryScopeId = '/' } | Out-Null
                Add-Result 'BreakGlass' $nm 'No' 'Assigned' Fixed $null
            }
            else { Add-Result 'BreakGlass' $nm 'No' 'Yes' Drift $null }
        }
    }

    Set-Group '6. Restricted management administrative unit (RMAU)'
    $auLink = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AdministrativeUnitsMenuBlade/~/AdminUnits'
    $script:bgAu = $null
    Invoke-Part 'BreakGlass' 'Administrative unit' {
        $script:bgAu = (Graph GET "https://graph.microsoft.com/v1.0/directory/administrativeUnits?`$filter=displayName eq '$BreakGlassAuName'").value | Select-Object -First 1
        if (-not $script:bgAu -and (Confirm-Change "Create restricted-management AU $BreakGlassAuName")) {
            $script:bgAu = Graph POST 'https://graph.microsoft.com/v1.0/directory/administrativeUnits' @{ displayName = $BreakGlassAuName; description = 'Protects emergency access objects'; isMemberManagementRestricted = $true }
            Add-Result 'BreakGlass' "Administrative unit $BreakGlassAuName exists" 'No' 'Created (restricted)' Fixed $auLink
        }
        elseif ($script:bgAu) {
            Add-Result 'BreakGlass' "Administrative unit $BreakGlassAuName exists" 'Yes' 'Yes' Compliant $auLink
            Compare-Setting 'BreakGlass' "$BreakGlassAuName has restricted management turned on" (YN $script:bgAu.isMemberManagementRestricted) 'Yes' $null $auLink 'Restricted management is what stops regular admins from changing the group and the accounts. It can only be set when the unit is created, so if it is off, create a new restricted unit.'
        }
        elseif ($found) { Add-Result 'BreakGlass' "Administrative unit $BreakGlassAuName exists" 'No' 'Optional: only needed for the new accounts' Info $auLink 'You already have emergency accounts. Make sure their group is inside a restricted management administrative unit (see section 2).' $BreakGlassPdf $pdf }
        else { Add-Result 'BreakGlass' "Administrative unit $BreakGlassAuName exists" 'No' 'Yes' Drift $auLink 'A restricted management administrative unit makes the break-glass group and accounts editable only by the trusted admins you assign to it.' $BreakGlassPdf $pdf }
    }
    $au = $script:bgAu
    if ($au -and $g) {
        Invoke-Part 'BreakGlass' 'Group in administrative unit' {
            $nm = "Group $BreakGlassGroupName is inside administrative unit $BreakGlassAuName"
            $auMembers = @((Graph GET "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$($au.id)/members?`$select=id").value.id)
            if ($g.id -in $auMembers) { Add-Result 'BreakGlass' $nm 'Yes' 'Yes' Compliant $null }
            elseif (Confirm-Change "Add group to AU $BreakGlassAuName") {
                Graph POST "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$($au.id)/members/`$ref" @{ '@odata.id' = "https://graph.microsoft.com/v1.0/groups/$($g.id)" } | Out-Null
                Add-Result 'BreakGlass' $nm 'No' 'Added' Fixed $null
            }
            else { Add-Result 'BreakGlass' $nm 'No' 'Yes' Drift $null }
        }
    }

    Set-Group '7. To do by a person'
    $bgDoc = 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access'
    $caLink = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'
    Add-Result 'BreakGlass' "Add 1-2 trusted admins as administrators of the '$BreakGlassAuName' administrative unit" 'Cannot be checked automatically' 'Only these admins can manage the group and accounts' Manual $auLink "Only the trusted admins you add as administrators of the unit (Entra ID > Roles and administrators > Administrative units) can reset passwords, change membership or delete the break-glass objects. Add 1-2 trusted admins only." $BreakGlassPdf $pdf
    Add-Result 'BreakGlass' 'Set up monitoring and an alert on every sign-in of the break-glass accounts' 'Cannot be checked automatically' 'Alert goes to the security team on any sign-in' Manual $bgDoc 'Any sign-in with a break-glass account means something went wrong or an attack is under way. Send sign-in logs to Log Analytics or Sentinel and create an alert rule (or a Defender XDR custom detection) that notifies the security team immediately.' $BreakGlassPdf $pdf
    if (-not ($Steps -contains 'ConditionalAccess')) { Add-Result 'BreakGlass' 'Exclude the break-glass group from ALL Conditional Access policies' 'Cannot be checked automatically' 'Excluded from every policy' Manual $caLink "If a Conditional Access policy breaks sign-in the break-glass accounts must still be able to get in. Exclude the group '$BreakGlassGroupName' from every policy, including new ones." $BreakGlassPdf $pdf }
    Add-Result 'BreakGlass' 'Register at least one FIDO2 security key on EACH break-glass account' 'Cannot be checked automatically' 'Each account has its own key' Manual 'https://mysignins.microsoft.com/security-info' 'The accounts are excluded from Conditional Access, so they need their own phishing-resistant sign-in. Register a FIDO2 key per account at My Security Info and store the keys in separate secure places.' $BreakGlassPdf $pdf

    $mine = @($script:Results | Select-Object -Skip $start)
    $ok = @($mine | Where-Object { $_.Status -in 'Compliant', 'Fixed' }).Count
    $bad = @($mine | Where-Object { $_.Status -eq 'Drift' }).Count
    $verdict = if ($found -and $bad -eq 0) { 'Your existing accounts meet the checks. Creating new accounts is optional.' } elseif ($found) { "Your existing accounts fail $bad check(s). Fix them, or create the two new accounts." } elseif ($bad -eq 0) { 'The two ALSO break-glass accounts are set up.' } else { "$bad item(s) still need to be created or fixed." }
    Set-Group 'Summary'
    Add-Result 'BreakGlass' 'Break-glass readiness' "$ok check(s) pass, $bad need action" 'All checks pass' $(if ($bad) { 'Info' } else { 'Compliant' }) $link "$verdict How to read this section: 1 shows whether you already have emergency accounts, 2 checks them, 3 to 6 cover the two new ALSO accounts (optional if yours pass), 7 lists what a person must do." $BreakGlassPdf $pdf
    $sum = $script:Results[$script:Results.Count - 1]
    $script:Results.RemoveAt($script:Results.Count - 1)
    $sum.Group = '0. Summary'
    $script:Results.Insert($start, $sum)
    if ($Mode -eq 'Enforce') {
        Write-Host ''
        Write-Host '   NEXT STEPS for the break-glass accounts (do these now):' -ForegroundColor Yellow
        Write-Host "   1. Add 1-2 trusted admins to the administrative unit '$BreakGlassAuName' in Entra ID." -ForegroundColor Yellow
        Write-Host '   2. Set up monitoring and a sign-in alert on the accounts.' -ForegroundColor Yellow
        Write-Host '   3. Exclude the group from ALL Conditional Access policies.' -ForegroundColor Yellow
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
#region guide automation helpers
function Get-AllPages([string]$Uri) {
    $out = @()
    while ($Uri) { $r = Graph GET $Uri; $out += @($r.value); $Uri = $r.'@odata.nextLink' }
    $out
}

function Find-GroupByName([string]$Name) {
    $q = [uri]::EscapeDataString("displayName eq '$($Name.Replace("'", "''"))'")
    (Graph GET ('https://graph.microsoft.com/v1.0/groups?$filter=' + $q + '&$select=id,displayName')).value | Select-Object -First 1
}

function Get-GuidePackage([string]$Name) {
    $root = Join-Path ([IO.Path]::GetTempPath()) 'sbd-packages'
    $dir = Join-Path $root $Name
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Force $root | Out-Null
        $zip = Join-Path $root "$Name.zip"
        Invoke-WebRequest -Uri "${GuideBase}downloads/$Name.zip" -OutFile $zip -UseBasicParsing
        Expand-Archive $zip -DestinationPath $dir -Force
    }
    $dir
}

function Get-PackageJson([string]$Dir, [string]$Folder) {
    Get-ChildItem $Dir -Recurse -Filter *.json | Where-Object { (-not $Folder) -or $_.Directory.Name -eq $Folder } | ForEach-Object {
        [pscustomobject]@{ File = $_; Json = (Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json) }
    }
}

# Turns a Graph export (Intune/Entra JSON) into a body Graph accepts on create.
function ConvertTo-CleanBody {
    param($Node, [bool]$Top = $true)
    $dropTop = 'id', 'createdDateTime', 'lastModifiedDateTime', 'modifiedDateTime', 'version', 'isAssigned', 'deployedAppCount', 'settingCount',
    'assignments', 'apps', 'creationSource', 'deviceStatuses', 'userStatuses', 'deviceStatusOverview', 'userStatusOverview',
    'deviceStatusSummary', 'userStatusSummary', 'deviceSettingStateSummaries'
    if ($null -eq $Node) { return $null }
    if ($Node -is [string] -or $Node -is [ValueType]) { return $Node }
    if ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [System.Collections.IDictionary]) {
        $arr = @(foreach ($i in $Node) { ConvertTo-CleanBody $i $false })
        return , $arr
    }
    $pairs = if ($Node -is [System.Collections.IDictionary]) { foreach ($k in $Node.Keys) { [pscustomobject]@{ Name = $k; Value = $Node[$k] } } } else { $Node.PSObject.Properties }
    $h = [ordered]@{}
    foreach ($p in $pairs) {
        $k = "$($p.Name)"; $v = $p.Value
        if ($k -like '*@odata.*' -and $k -ne '@odata.type') { continue }
        if ($k -like '#microsoft.graph.*') { continue }
        if ($Top -and $k -in $dropTop) { continue }
        if (-not $Top -and $k -eq 'id' -and "$v" -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { continue }
        if ($null -eq $v) { continue }
        $h[$k] = ConvertTo-CleanBody $v $false
    }
    return $h
}
#endregion

function Invoke-Part([string]$Step, [string]$Name, [scriptblock]$Body) {
    try { & $Body }
    catch { Add-Result $Step $Name "Could not be completed: $($_.Exception.Message)" 'Completed' Error $null 'This part failed, the other checks in this step still ran. The message above comes from Microsoft Graph and normally says which permission or license is missing.' }
}

function ConvertTo-Canonical($Node) {
    if ($null -eq $Node) { return $null }
    if ($Node -is [string] -or $Node -is [ValueType]) { return $Node }
    if ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [System.Collections.IDictionary]) {
        $items = @(foreach ($i in $Node) { $c = ConvertTo-Canonical $i; if ($null -ne $c) { $c } })
        if (-not $items.Count) { return $null }
        return , @($items | Sort-Object { if ($_ -is [string] -or $_ -is [ValueType]) { "$_" } else { $_ | ConvertTo-Json -Compress -Depth 20 } })
    }
    $keys = if ($Node -is [System.Collections.IDictionary]) { @($Node.Keys) } else { @($Node.PSObject.Properties.Name) }
    $h = [ordered]@{}
    foreach ($k in ($keys | Sort-Object)) {
        if ($k -eq '@odata.type') { continue }
        $v = if ($Node -is [System.Collections.IDictionary]) { $Node[$k] } else { $Node.$k }
        $c = ConvertTo-Canonical $v
        if ($null -ne $c) { $h[$k] = $c }
    }
    if (-not $h.Count) { return $null }
    $h
}

# Same settings regardless of name, state or the groups that are targeted.
function Get-CaFingerprint($Pol, [bool]$Strict) {
    $b = ConvertTo-CleanBody $Pol
    foreach ($k in 'displayName', 'state', 'description', 'templateId', 'partialEnablementStrategy') { if ($b.Contains($k)) { $b.Remove($k) } }
    if ($b.Contains('conditions') -and $b['conditions'] -is [System.Collections.IDictionary] -and $b['conditions'].Contains('users')) {
        $u = $b['conditions']['users']
        foreach ($k in 'excludeGroups', 'excludeUsers') { if ($u.Contains($k)) { $u.Remove($k) } }
        if (-not $Strict -and $u.Contains('includeGroups')) { $u['includeGroups'] = @(@($u['includeGroups']).Count) }
    }
    $as = $Pol.grantControls.authenticationStrength
    if ($as -and $b.Contains('grantControls') -and $b['grantControls'] -is [System.Collections.IDictionary]) { $b['grantControls']['authenticationStrength'] = [ordered]@{ id = "$($as.id)" } }
    ConvertTo-Canonical $b | ConvertTo-Json -Compress -Depth 20
}

function Get-IntuneFingerprint($Pol) {
    $b = ConvertTo-CleanBody $Pol
    foreach ($k in 'displayName', 'description', 'name', 'roleScopeTagIds', 'scheduledActionsForRule', 'templateReference') { if ($b.Contains($k)) { $b.Remove($k) } }
    ConvertTo-Canonical $b | ConvertTo-Json -Compress -Depth 20
}

function Step-ConditionalAccess {
    Write-Step 'Conditional Access baseline' 'Imports ALSO''s Conditional Access policies (switched OFF), recognises policies you already have, and keeps the break-glass group excluded from every policy.'
    $doc = $GuideBase + '#identity-policies'
    $docText = 'ALSO guide: Conditional Access baseline (Identity and access, step 10)'
    $link = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'
    $lic = Get-LicenseTier
    $caBase = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
    $stateTxt = @{ enabled = 'On'; disabled = 'Off'; enabledForReportingButNotEnforced = 'Report-only' }
    $dir = Get-GuidePackage 'conditional-access'
    $polFiles = @(Get-PackageJson $dir 'ConditionalAccess')
    $grpFiles = @(Get-PackageJson $dir 'Groups')
    $ctxFiles = @(Get-PackageJson $dir 'AuthenticationContext')
    $bgGroup = Find-GroupByName $BreakGlassGroupName
    $bgId = $bgGroup.id
    $e5ok = ($lic.Tier -eq 'Full') -or $lic.HasP2
    $wanted = @($polFiles | Where-Object { $e5ok -or $_.File.Name -notmatch '^E5-' })
    $skippedE5 = @($polFiles | Where-Object { -not $e5ok -and $_.File.Name -match '^E5-' })
    $existing = @(Get-AllPages $caBase)
    $exFp = @{}
    foreach ($e in $existing) { $exFp["$($e.id)"] = Get-CaFingerprint $e $false }
    $why = 'ALSO''s baseline blocks legacy authentication, requires MFA for users and admins, protects admin portals and guests and requires compliant devices. Policies are created switched OFF so nothing changes until you review them. A policy counts as present when one with the same name exists, or when a policy with a different name has the same settings.'

    $rows = @(foreach ($p in $wanted) {
            $nm = $p.Json.displayName
            $byName = $existing | Where-Object { $_.displayName -eq $nm } | Select-Object -First 1
            $byCfg = $null
            if (-not $byName) { $fp = Get-CaFingerprint $p.Json $false; $byCfg = $existing | Where-Object { $exFp["$($_.id)"] -eq $fp } | Select-Object -First 1 }
            [pscustomobject]@{ P = $p; Name = $nm; ByName = $byName; ByCfg = $byCfg }
        })
    $missing = @($rows | Where-Object { -not $_.ByName -and -not $_.ByCfg })
    $do = $false
    $map = @{}
    if ($missing.Count) { $do = Confirm-Change "Import $($missing.Count) missing ALSO Conditional Access policies (switched off)" }
    if ($do) {
        try {
            $ref = @()
            foreach ($m in $missing) { foreach ($k in 'includeGroups', 'excludeGroups') { $ref += @($m.P.Json.conditions.users.$k) } }
            $ref = @($ref | Where-Object { $_ } | Sort-Object -Unique)
            foreach ($g in $grpFiles) {
                if ($g.Json.id -notin $ref) { continue }
                $gn = $g.Json.displayName
                if ($gn -like '*BSAccounts*' -and $bgId) { $map["$($g.Json.id)"] = $bgId; continue }
                $f = Find-GroupByName $gn
                if (-not $f) {
                    $nick = ($gn -replace '[^A-Za-z0-9]', ''); if ($nick.Length -gt 60) { $nick = $nick.Substring(0, 60) }
                    $f = Graph POST 'https://graph.microsoft.com/v1.0/groups' @{ displayName = $gn; description = 'ALSO Conditional Access baseline group'; mailEnabled = $false; securityEnabled = $true; mailNickname = $nick }
                    Write-Host "   Created group: $gn" -ForegroundColor DarkGray
                }
                $map["$($g.Json.id)"] = $f.id
            }
            foreach ($c in $ctxFiles) {
                $have = $true
                try { Graph GET "https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences/$($c.Json.id)" | Out-Null } catch { $have = $false }
                if (-not $have) { Graph POST 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences' @{ id = $c.Json.id; displayName = $c.Json.displayName; description = "$($c.Json.description)"; isAvailable = $true } | Out-Null }
            }
        }
        catch { Add-Result 'ConditionalAccess' 'Preparing groups and authentication context' $_.Exception.Message 'Prepared' Error $link $null $doc $docText; $do = $false }
    }

    Set-Group 'ALSO baseline policies (one row per policy)'
    if ($skippedE5.Count) { Add-Result 'ConditionalAccess' "ALSO E5 policies not checked ($($skippedE5.Count))" 'Not licensed' 'Requires Entra ID P2 (Microsoft 365 E5, E7 or a security suite)' Skipped $link 'These policies use Entra ID Protection (risk) or Privileged Identity Management features that are only included with Entra ID P2.' $doc $docText }
    foreach ($r in $rows) {
        $nm = $r.Name
        if ($r.ByName) { Add-Result 'ConditionalAccess' $nm "Present - $($stateTxt["$($r.ByName.state)"])" 'Present' Compliant $link $why $doc $docText; continue }
        if ($r.ByCfg) { Add-Result 'ConditionalAccess' $nm "Equivalent policy exists: '$($r.ByCfg.displayName)' ($($stateTxt["$($r.ByCfg.state)"]))" 'Present' Info $link "A policy with a different name but the same settings already covers this ALSO policy, so it is not imported again. Consider renaming it to the ALSO name or keep only one of them." $doc $docText; continue }
        if (-not $do) { Add-Result 'ConditionalAccess' $nm 'Missing' 'Present (switched off)' Drift $link $why $doc $docText; continue }
        try {
            $p = $r.P
            $b = ConvertTo-CleanBody $p.Json
            $b['state'] = 'disabled'
            $u = $b['conditions']['users']
            foreach ($k in 'includeGroups', 'excludeGroups') { if ($u.Contains($k)) { $u[$k] = [object[]]@(@($u[$k]) | ForEach-Object { $map["$_"] } | Where-Object { $_ }) } }
            if ($bgId) {
                $ex = if ($u.Contains('excludeGroups')) { @($u['excludeGroups']) } else { @() }
                if ($bgId -notin $ex) { $u['excludeGroups'] = [object[]]($ex + $bgId) }
            }
            $as = $p.Json.grantControls.authenticationStrength
            if ($as -and $b['grantControls']) { $b['grantControls']['authenticationStrength'] = [ordered]@{ id = $as.id } }
            Graph POST $caBase $b | Out-Null
            Add-Result 'ConditionalAccess' $nm 'Missing' 'Imported (switched off)' Fixed $link $why $doc $docText
        }
        catch { Add-Result 'ConditionalAccess' $nm 'Missing' 'Imported (switched off)' Error $link "Import failed: $($_.Exception.Message)" $doc $docText }
    }

    Set-Group 'Your other Conditional Access policies'
    $known = @($rows | ForEach-Object { $_.ByName.id; $_.ByCfg.id } | Where-Object { $_ })
    foreach ($e in $existing) {
        if ("$($e.id)" -in $known) { continue }
        Add-Result 'ConditionalAccess' "$($e.displayName)" "Not part of the ALSO baseline - $($stateTxt["$($e.state)"])" 'Reviewed' Info $link 'This policy was created by you or someone else. It is listed so you have one overview of everything that is active. Check that it does not conflict with the ALSO baseline.' $doc $docText
    }

    Set-Group 'Duplicate policies'
    $strict = @{}
    foreach ($e in $existing) { $k = Get-CaFingerprint $e $true; if (-not $strict.ContainsKey($k)) { $strict[$k] = @() }; $strict[$k] += $e }
    $dups = @($strict.Values | Where-Object { $_.Count -gt 1 })
    if (-not $dups.Count) { Add-Result 'ConditionalAccess' 'Policies with identical settings' 'None found' 'No duplicates' Compliant $link 'Two policies with the same users, apps and controls do the same job twice and make troubleshooting harder.' $doc $docText }
    foreach ($d in $dups) { Add-Result 'ConditionalAccess' "Duplicate policies: $(($d | ForEach-Object { $_.displayName }) -join '  |  ')" "$($d.Count) policies with identical settings" 'One policy' Drift $link 'These policies target the same users and apps and require the same controls. Keep one and remove or merge the others, otherwise changes have to be made twice and the result is hard to explain.' $doc $docText }

    Set-Group 'Break-glass protection'
    Invoke-Part 'ConditionalAccess' 'Break-glass group excluded from policies' {
        if (-not $bgId) { Add-Result 'ConditionalAccess' "Break-glass group '$BreakGlassGroupName' excluded from all policies" 'Break-glass group not found' 'Excluded everywhere' Manual $link 'Create the break-glass accounts and group first (Break-glass step), then run this step again.' $BreakGlassPdf 'Break-glass best practices (PDF)'; return }
        $cur = @(Get-AllPages $caBase)
        $need = @($cur | Where-Object { @($_.conditions.users.excludeGroups) -notcontains $bgId })
        if (-not $cur.Count) { return }
        $detail = 'If a Conditional Access policy breaks sign-in, or MFA is unavailable, the break-glass accounts must still get in. ' + $(if ($need) { 'Missing in: ' + (($need | ForEach-Object { $_.displayName }) -join '; ') } else { 'Every policy excludes the group.' })
        Compare-Setting 'ConditionalAccess' "Break-glass group '$BreakGlassGroupName' excluded from all Conditional Access policies" "$($cur.Count - $need.Count) of $($cur.Count) policies exclude it" "$($cur.Count) of $($cur.Count) policies exclude it" {
            foreach ($pol in $need) {
                $u = ConvertTo-CleanBody $pol.conditions.users $false
                $ex = if ($u.Contains('excludeGroups')) { @($u['excludeGroups']) } else { @() }
                $u['excludeGroups'] = [object[]]($ex + $bgId)
                Graph PATCH "$caBase/$($pol.id)" @{ conditions = @{ users = $u } } | Out-Null
            }
        } $link $detail $BreakGlassPdf 'Break-glass best practices (PDF)'
    }

    Invoke-Part 'ConditionalAccess' 'Conditional Access groups in restricted management' {
        $au = (Graph GET ('https://graph.microsoft.com/v1.0/directory/administrativeUnits?$filter=' + [uri]::EscapeDataString("displayName eq '$BreakGlassAuName'"))).value | Select-Object -First 1
        if (-not $au) { return }
        $auMembers = @(Get-AllPages "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$($au.id)/members?`$select=id" | ForEach-Object { $_.id })
        $ids = @()
        foreach ($g in $grpFiles) { if ($g.Json.displayName -like '*BSAccounts*') { continue }; $f = Find-GroupByName $g.Json.displayName; if ($f) { $ids += $f.id } }
        if (-not $ids.Count) { return }
        $notIn = @($ids | Where-Object { $_ -notin $auMembers })
        Compare-Setting 'ConditionalAccess' "ALSO Conditional Access groups inside restricted management unit '$BreakGlassAuName'" "$($ids.Count - $notIn.Count) of $($ids.Count) groups inside" "$($ids.Count) of $($ids.Count) groups inside" {
            foreach ($id in $notIn) { Graph POST "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$($au.id)/members/`$ref" @{ '@odata.id' = "https://graph.microsoft.com/v1.0/groups/$id" } | Out-Null }
        } 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AdministrativeUnitsMenuBlade/~/AdminUnits' 'Groups used in Conditional Access decide who is protected or excluded. Inside the restricted management unit only the administrators of that unit can change their membership.' ($GuideBase + '#restricted-management-admin-units') 'ALSO guide: Restricted management administrative units (Identity and access, step 11)'
    }
    Add-Result 'ConditionalAccess' 'Review, test and switch on the imported policies' 'Imported policies are switched off' 'Each policy tested in report-only, then enabled' Manual $link 'Open each ALSO policy, set it to Report-only, review the impact in the sign-in logs, then enable it. Turn security defaults off once the policies are on. Policies for Entra ID P2 and the Tier 0 authentication context also need the matching role settings in Privileged Identity Management.' $doc $docText
}

function Step-PrivilegedAccess {
    Write-Step 'Administrator roles and access reviews' 'Few permanent Global Administrators, eligible (just-in-time) roles and regular reviews.'
    $doc = $GuideBase + '#admin-role-review'
    $docText = 'ALSO guide: Review administrator roles (Identity and access, step 4)'
    $lic = Get-LicenseTier
    $link = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/RolesManagementMenuBlade/~/AllRoles'
    $gaId = '62e90394-69f5-4237-9190-012177145e10'
    Set-Group 'Global Administrators'
    Invoke-Part 'PrivilegedAccess' 'Permanent Global Administrators' {
        $ids = @()
        try {
            $inst = @(Get-AllPages ('https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$filter=' + [uri]::EscapeDataString("roleDefinitionId eq '$gaId'")))
            $ids = @($inst | Where-Object { $_.assignmentType -eq 'Assigned' } | ForEach-Object { $_.principalId } | Sort-Object -Unique)
        }
        catch {
            $ids = @(Get-AllPages ('https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter=' + [uri]::EscapeDataString("roleDefinitionId eq '$gaId'")) | ForEach-Object { $_.principalId } | Sort-Object -Unique)
        }
        $names = ''
        try {
            if ($ids.Count) {
                $o = (Graph POST 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds' @{ ids = @($ids); types = @('user', 'group', 'servicePrincipal') }).value
                $names = ($o | ForEach-Object { if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName } }) -join '; '
            }
        }
        catch { }
        $why = 'Global Administrators can change everything. Keep permanent assignments to a minimum (at most 5, including the two break-glass accounts) and give everyone else eligible, time-limited access through Privileged Identity Management. ' + $(if ($names) { "Today: $names" })
        if ($ids.Count -le 5) { Add-Result 'PrivilegedAccess' 'Number of permanent Global Administrators' "$($ids.Count)" '5 or fewer' Compliant $link $why $doc $docText }
        else { Add-Result 'PrivilegedAccess' 'Number of permanent Global Administrators' "$($ids.Count)" '5 or fewer' Drift $link "$why Review the list and convert surplus accounts to eligible, or remove the role." $doc $docText }
    }
    Set-Group 'Just-in-time access and reviews'
    if ($lic.Tier -eq 'Full' -or $lic.HasP2) {
        Invoke-Part 'PrivilegedAccess' 'Eligible role assignments' {
            $elig = @(Get-AllPages 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances')
            Add-Result 'PrivilegedAccess' 'Eligible (just-in-time) role assignments' "$($elig.Count)" 'Used for day-to-day administration' Info $link 'Eligible assignments must be activated (with MFA and a reason) before they work, which limits the time an admin account is powerful.' $doc $docText
        }
        $arDoc = $GuideBase + '#access-reviews'; $arText = 'ALSO guide: Access reviews (Extend identity, step 2)'
        $arLink = 'https://entra.microsoft.com/#view/Microsoft_AAD_ERM/DashboardBlade/~/elmEntitlement'
        Invoke-Part 'PrivilegedAccess' 'Access reviews' {
            $ar = @(Get-AllPages 'https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions')
            if ($ar.Count) { Add-Result 'PrivilegedAccess' 'Access reviews' "$($ar.Count) review(s): $(($ar | ForEach-Object { $_.displayName }) -join '; ')" 'At least one recurring review for privileged roles and guests' Compliant $arLink 'Regular reviews remove access that is no longer needed.' $arDoc $arText }
            else { Add-Result 'PrivilegedAccess' 'Access reviews' 'None configured' 'At least one recurring review for privileged roles and guests' Manual $arLink 'Create recurring access reviews for privileged roles, guest users and sensitive groups. They depend on your reviewers, so they cannot be created from a baseline file.' $arDoc $arText }
        }
    }
    else { Add-Result 'PrivilegedAccess' 'Eligible roles and access reviews' 'Not licensed' 'Requires Entra ID P2 (Microsoft 365 E5, E7 or a security suite)' Skipped $link 'Privileged Identity Management and access reviews need Entra ID P2, so this part is skipped.' ($GuideBase + '#access-reviews') 'ALSO guide: Access reviews (Extend identity, step 2)' }
    Set-Group 'To do by a person'
    Add-Result 'PrivilegedAccess' 'Review application owners and admin role holders' 'Cannot be judged automatically' 'Reviewed and documented' Manual $link 'Check every administrator and the owners of enterprise applications. Remove people who do not need access. Need4Admin (linked in the ALSO guide) lists administrators and their roles in one report.' $doc $docText
}

function Get-IntunePlatform($Json, $File) {
    $t = "$($Json.'@odata.type')"; $pl = "$($Json.platforms)"
    if ($pl -match 'windows' -or $t -match 'windows|win32') { return 'windows' }
    if ($pl -match 'macOS' -or $t -match 'macOS') { return 'macos' }
    if ($t -match 'ios' -or $pl -match 'ios') { return 'ios' }
    if ($t -match 'android|aosp' -or $pl -match 'android|aosp') { return 'android' }
    if ($File.FullName -match 'macOS|[ _-]Mac[ _-]') { return 'macos' }
    return 'other'
}

function Get-IntuneTarget($Json) {
    $b = 'https://graph.microsoft.com/beta/'
    $t = "$($Json.'@odata.type')"
    if ($t -match 'mobileApp|win32|macOSLobApp|macOSDmg|macOSPkg') { return $null }
    if ($null -ne $Json.settings -and $Json.platforms) { return $b + 'deviceManagement/configurationPolicies' }
    if ($t -match 'iosManagedAppProtection') { return $b + 'deviceAppManagement/iosManagedAppProtections' }
    if ($t -match 'androidManagedAppProtection') { return $b + 'deviceAppManagement/androidManagedAppProtections' }
    if ($t -match 'CompliancePolicy') { return $b + 'deviceManagement/deviceCompliancePolicies' }
    if ($t -match 'Configuration$') { return $b + 'deviceManagement/deviceConfigurations' }
    return $null
}

function Step-IntunePolicies {
    Write-Step 'Intune policy baseline' 'Imports ALSO''s compliance, app protection, device security, Defender and browser policies (unassigned) and recognises policies you already have.'
    $all = 'windows', 'macos', 'ios', 'android'
    $sel = $all
    if ($Mode -eq 'Enforce' -and -not $Force) {
        $in = Read-Host '   Platforms to import: windows, macos, ios, android (comma separated, Enter = all)'
        if ($in -and $in.Trim()) { $sel = @($in -split '[ ,;]+' | Where-Object { $_ } | ForEach-Object { $_.ToLower() }) }
    }
    Write-Host "   Platforms: $($sel -join ', ')" -ForegroundColor DarkGray
    $pk = [ordered]@{
        'device-compliance'   = @('Device compliance policies', '#compliance', 'ALSO guide: Device compliance (Endpoints, step 9)')
        'app-protection'      = @('App protection policies (iOS and Android)', '#app-protection', 'ALSO guide: App protection (Endpoints, step 8)')
        'device-security'     = @('Device security: BitLocker and local admin passwords (LAPS)', '#local-admin', 'ALSO guide: Local admin and LAPS (Endpoints, step 4)')
        'defender-onboarding' = @('Defender for Endpoint onboarding profiles', '#defender-onboarding', 'ALSO guide: Defender provisioning and onboarding (Endpoints, step 10)')
        'defender-security'   = @('Defender and firewall baseline', '#endpoint-baseline', 'ALSO guide: Defender and firewall minimum configuration (Endpoints, step 11)')
        'browser-protection'  = @('Microsoft Edge browser protection', '#browser', 'ALSO guide: Browser protection (Endpoints, step 12)')
    }
    $link = 'https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/overview'
    $norm = { param($s) ("$s" -replace '[^\p{L}\p{N}]', '').ToLower() }
    $cache = @{}
    $manualBits = @()
    foreach ($pkg in $pk.Keys) {
        $meta = $pk[$pkg]; $doc = $GuideBase + $meta[1]
        Set-Group $meta[0]
        try { $dir = Get-GuidePackage $pkg }
        catch { Add-Result 'IntunePolicies' $meta[0] "Package could not be downloaded: $($_.Exception.Message)" 'Imported' Manual $link 'Download the policy package from the ALSO guide and import it in Intune.' $doc $meta[2]; continue }
        $items = @()
        foreach ($x in (Get-PackageJson $dir $null)) {
            if ($x.File.Name -eq 'MigrationTable.json') { continue }
            $t = "$($x.Json.'@odata.type')"
            if ($t -match 'mobileApp|LobApp|macOSDmg|macOSPkg|DefenderApp' -or $x.File.Directory.Name -eq 'Applications') { $manualBits += "$($x.Json.displayName)"; continue }
            if ($x.File.Name -match 'Auto Onboarding') { $manualBits += "$($x.File.BaseName) (tenant-specific onboarding file)"; continue }
            $target = Get-IntuneTarget $x.Json
            if (-not $target) { continue }
            $plat = Get-IntunePlatform $x.Json $x.File
            if ($plat -ne 'other' -and $plat -notin $sel) { continue }
            $nm = if ($x.Json.displayName) { $x.Json.displayName } else { $x.Json.name }
            if (-not $cache.ContainsKey($target)) { $cache[$target] = @(Get-AllPages $target) }
            $byName = $cache[$target] | Where-Object { (& $norm $(if ($_.displayName) { $_.displayName } else { $_.name })) -eq (& $norm $nm) } | Select-Object -First 1
            $byCfg = $null
            if (-not $byName -and $null -eq $x.Json.settings) {
                $fp = Get-IntuneFingerprint $x.Json
                $byCfg = $cache[$target] | Where-Object { (Get-IntuneFingerprint $_) -eq $fp } | Select-Object -First 1
            }
            $items += [pscustomobject]@{ Name = $nm; Plat = $plat; Target = $target; Json = $x.Json; ByName = $byName; ByCfg = $byCfg }
        }
        if (-not $items.Count) { continue }
        $miss = @($items | Where-Object { -not $_.ByName -and -not $_.ByCfg })
        $do = $false
        if ($miss.Count) { $do = Confirm-Change "Import $($miss.Count) missing policies: $($meta[0])" }
        $why = 'Policies are created unassigned, so nothing changes on devices yet. Assign each policy to a pilot group, check the results, then widen the scope.'
        foreach ($i in ($items | Sort-Object Name)) {
            $label = "$($i.Name)  [$($i.Plat)]"
            if ($i.ByName) { Add-Result 'IntunePolicies' $label 'Present' 'Present' Compliant $link $why $doc $meta[2]; continue }
            if ($i.ByCfg) { $en = if ($i.ByCfg.displayName) { $i.ByCfg.displayName } else { $i.ByCfg.name }; Add-Result 'IntunePolicies' $label "Equivalent policy exists: '$en'" 'Present' Info $link 'A policy with a different name but the same settings already exists, so this one is not imported again.' $doc $meta[2]; continue }
            if (-not $do) { Add-Result 'IntunePolicies' $label 'Missing' 'Present (unassigned)' Drift $link $why $doc $meta[2]; continue }
            try { Graph POST $i.Target (ConvertTo-CleanBody $i.Json) | Out-Null; Add-Result 'IntunePolicies' $label 'Missing' 'Imported (unassigned)' Fixed $link $why $doc $meta[2] }
            catch { Add-Result 'IntunePolicies' $label 'Missing' 'Imported (unassigned)' Error $link "Import failed: $($_.Exception.Message)" $doc $meta[2] }
        }
    }
    Set-Group 'Apple and enrollment'
    if ($manualBits.Count) {
        Add-Result 'IntunePolicies' 'Defender for Endpoint macOS app and tenant-specific onboarding files' ($manualBits -join '; ') 'Added by an administrator' Manual 'https://security.microsoft.com/securitysettings/endpoints/onboarding' 'The macOS Defender app is a software package and the macOS onboarding file contains a key that belongs to one tenant. Download the onboarding package from the Defender portal (Settings > Endpoints > Onboarding), then add the app and profile in Intune.' ($GuideBase + '#defender-onboarding') 'ALSO guide: Defender provisioning and onboarding (Endpoints, step 10)'
    }
    if ($sel -contains 'ios' -or $sel -contains 'macos') {
        $apDoc = $GuideBase + '#apple-enrollment'; $apText = 'ALSO guide: Supported platforms and Apple enrollment (Endpoints, step 3)'
        $apLink = 'https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesEnrollmentMenu/~/appleEnrollment'
        try {
            $apns = Graph GET 'https://graph.microsoft.com/beta/deviceManagement/applePushNotificationCertificate'
            $days = ([datetime]$apns.expirationDateTime - (Get-Date)).Days
            $exp = ([datetime]$apns.expirationDateTime).ToString('yyyy-MM-dd')
            if ($days -lt 0) { Add-Result 'IntunePolicies' 'Apple MDM push certificate' "Expired on $exp" 'Valid' Manual $apLink 'iPhones, iPads and Macs stop syncing with Intune when this certificate expires. Renew it with the same Apple ID that created it.' $apDoc $apText }
            elseif ($days -lt 30) { Add-Result 'IntunePolicies' 'Apple MDM push certificate' "Expires in $days days ($exp)" 'Valid for 30 days or more' Manual $apLink 'Renew the certificate with the same Apple ID that created it before it expires.' $apDoc $apText }
            else { Add-Result 'IntunePolicies' 'Apple MDM push certificate' "Valid until $exp" 'Valid' Compliant $apLink 'Needed to manage iPhones, iPads and Macs.' $apDoc $apText }
        }
        catch { Add-Result 'IntunePolicies' 'Apple MDM push certificate' 'Not configured' 'Configured (only needed for iPhone, iPad and Mac)' Manual $apLink 'Apple devices can only be managed after you create an MDM push certificate in Intune with an Apple ID owned by your company. Skip this if you do not manage Apple devices.' $apDoc $apText }
    }
    try {
        $er = @(Get-AllPages 'https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations' | Where-Object { "$($_.'@odata.type')" -match 'PlatformRestriction' })
        Add-Result 'IntunePolicies' 'Enrollment platform restrictions' "$($er.Count) restriction policy(ies)" 'Only supported platforms can enroll' Info 'https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesEnrollmentMenu/~/restrictions' 'Limit enrollment to the platforms you support and decide whether personally owned devices may enroll.' ($GuideBase + '#apple-enrollment') 'ALSO guide: Supported platforms (Endpoints, step 3)'
    }
    catch { }
}

function Step-Purview {
    Write-Step 'Microsoft Purview baseline' 'Checks every part of ALSO''s Purview baseline: tenant switches, labels, label policy, DLP, AI protection and retention, plus other Purview protections.'
    $repo = 'https://github.com/CoC-MS/ALSO-Microsoft-Security-Purview'
    $doc = $GuideBase + '#purview-baseline'
    $docText = 'ALSO guide: Purview baseline (Data security and governance, step 1)'
    $tier = (Get-LicenseTier).Tier
    $lbl = 'https://purview.microsoft.com/informationprotection/labels'
    $dlpL = 'https://purview.microsoft.com/datalossprevention/policies'
    $script:pvMissing = 0
    $row = {
        param($Setting, $Ok, $CurOk, $CurMiss, $Exp, $Detail, $Lnk)
        if ($Ok) { Add-Result 'Purview' $Setting $CurOk $Exp Compliant $Lnk $Detail $doc $docText }
        else { $script:pvMissing++; Add-Result 'Purview' $Setting $CurMiss $Exp Drift $Lnk $Detail $doc $docText }
    }
    $modeTxt = { param($p) switch ("$($p.Mode)") { 'Enable' { 'On' } 'TestWithNotifications' { 'Simulation with notifications' } 'TestWithoutNotifications' { 'Simulation' } 'Disable' { 'Off' } default { "$($p.Mode)" } } }
    $sim = @()

    Set-Group 'Tenant settings'
    Invoke-Part 'Purview' 'Audit' {
        $a = Get-AdminAuditLogConfig
        & $row 'Unified audit log' ($a.UnifiedAuditLogIngestionEnabled -eq $true) 'On' 'Off' 'On' 'Purview and Defender rely on the audit log for investigations, DLP reports and Copilot interaction logging.' 'https://purview.microsoft.com/audit/auditsearch'
    }
    Add-Result 'Purview' 'Sensitivity labels for PDF files and labels in SharePoint and OneDrive' 'Cannot be read automatically' 'Turned on' Manual $lbl 'The toolkit turns on labeling for PDF files and the SharePoint and OneDrive integration (SharePoint Online setting). Check in Purview under Information protection > Labels.' $doc $docText

    Set-Group 'Sensitivity labels (one row per label)'
    Invoke-Part 'Purview' 'Sensitivity labels' {
        $labels = @(Get-Label -ErrorAction Stop)
        $byId = @{}; foreach ($l in $labels) { $byId["$($l.Guid)"] = $l }
        $tree = [ordered]@{ 'Public' = @(); 'General' = @('Anyone (unrestricted)', 'All Employees (unrestricted)'); 'Confidential' = @('All Employees', 'Trusted People'); 'Highly Confidential' = @('All Employees', 'Specific People') }
        foreach ($p in $tree.Keys) {
            $parent = $labels | Where-Object { $_.DisplayName -eq $p -and -not $_.ParentId } | Select-Object -First 1
            & $row "Label: $p" ([bool]$parent) 'Present' 'Missing' 'Present' 'Sensitivity labels classify documents and e-mail so that protection can follow the data.' $lbl
            foreach ($s in $tree[$p]) {
                $child = $labels | Where-Object { $_.DisplayName -eq $s -and $_.ParentId -and $parent -and "$($_.ParentId)" -eq "$($parent.Guid)" } | Select-Object -First 1
                & $row "Sub-label: $p > $s" ([bool]$child) 'Present' 'Missing' 'Present' 'Sub-labels give the same classification different protection, for example encryption for specific people.' $lbl
            }
        }
        $extra = @($labels | Where-Object { -not $_.ParentId -and $_.DisplayName -notin $tree.Keys })
        if ($extra) { Add-Result 'Purview' 'Other sensitivity labels in your tenant' (($extra | ForEach-Object { $_.DisplayName }) -join '; ') 'Reviewed' Info $lbl 'These labels are not part of the ALSO baseline. Check that they do not overlap with it, because two label sets confuse users.' $doc $docText }
    }

    Set-Group 'Label policy'
    Invoke-Part 'Purview' 'Label policy' {
        $lps = @(Get-LabelPolicy -ErrorAction Stop)
        $lp = $lps | Where-Object { $_.Name -eq 'BP-ALSO - Default Label Policy' } | Select-Object -First 1
        & $row 'Label policy: BP-ALSO - Default Label Policy' ([bool]$lp) 'Present' 'Not found' 'Present' 'The label policy publishes the labels to users, sets the default label and requires a label on documents.' $lbl
        if ($lp) {
            $cnt = @($lp.Labels).Count
            & $row 'Label policy publishes the four baseline labels' ($cnt -ge 4) "$cnt labels published" "$cnt labels published" 'At least 4 labels' 'Public, Anyone (unrestricted), All Employees and All Employees (Highly Confidential) are published to users.' $lbl
            & $row 'Label policy is switched on' ($lp.Enabled -ne $false) 'On' 'Off' 'On' 'A disabled policy does not show the labels to users.' $lbl
        }
        $others = @($lps | Where-Object { $_.Name -ne 'BP-ALSO - Default Label Policy' })
        if ($others) { Add-Result 'Purview' 'Other label policies in your tenant' (($others | ForEach-Object { $_.Name }) -join '; ') 'Reviewed' Info $lbl 'Several label policies can give users different labels or defaults. Check they do not conflict with the baseline.' $doc $docText }
    }

    Set-Group 'Data loss prevention (one row per policy)'
    Invoke-Part 'Purview' 'Data loss prevention' {
        $dlp = @(Get-DlpCompliancePolicy -ErrorAction Stop)
        $names = [ordered]@{
            'BP-ALSO - DLP - Confidential and HC external (EXO)'                = 'Blocks mail labelled Confidential or Highly Confidential from leaving the organization.'
            'BP-ALSO - DLP - Confidential and HC external (SPO+ODB)'            = 'Blocks external sharing of SharePoint and OneDrive files labelled Confidential or Highly Confidential.'
            'BP-ALSO - DLP - Credit Card Numbers (EXO)'                         = 'Detects credit card numbers in external mail.'
            'BP-ALSO - DLP - IBAN and Bank Account Numbers (EXO)'               = 'Detects IBAN numbers in external mail.'
            'BP-ALSO - DLP - EU Social Security Numbers (EXO)'                  = 'Detects EU social security numbers in external mail.'
            'BP-ALSO - DLP - Swiss AHV Numbers (EXO)'                           = 'Detects Swiss AHV numbers in external mail.'
            'BP-ALSO - DLP - Passport Numbers DACH-EU (EXO)'                    = 'Detects DACH and EU passport numbers in external mail.'
            'BP-ALSO - DLP - Tax ID and VAT DACH (EXO)'                         = 'Detects DACH tax and VAT numbers in external mail.'
        }
        foreach ($n in $names.Keys) {
            $p = $dlp | Where-Object { $_.Name -eq $n } | Select-Object -First 1
            $cur = if ($p) { "Present - $(& $modeTxt $p)" } else { 'Not found' }
            & $row $n ([bool]$p) $cur $cur 'Present' $names[$n] $dlpL
            if ($p -and $p.Mode -ne 'Enable') { $sim += $n }
        }
        $e5 = [ordered]@{
            'E5-PS-ALSO - DLP - Endpoint Confidential and HC'          = 'Endpoint DLP audits copy, print, USB and network-share activity for labelled content.'
            'E5-PS-ALSO - AI - Block Copilot for Highly Confidential' = 'Stops Microsoft 365 Copilot from processing content labelled Highly Confidential.'
        }
        foreach ($n in $e5.Keys) {
            if ($tier -ne 'Full') { Add-Result 'Purview' $n 'Not licensed' 'Requires Microsoft 365 E5, E7 or the Purview suite' Skipped $dlpL $e5[$n] $doc $docText; continue }
            $p = $dlp | Where-Object { $_.Name -eq $n } | Select-Object -First 1
            $cur = if ($p) { "Present - $(& $modeTxt $p)" } else { 'Not found' }
            & $row $n ([bool]$p) $cur $cur 'Present' $e5[$n] $dlpL
            if ($p -and $p.Mode -ne 'Enable') { $sim += $n }
        }
        $other = @($dlp | Where-Object { $_.Name -notlike 'BP-ALSO*' -and $_.Name -notlike 'E5-PS-ALSO*' })
        if ($other) { Add-Result 'Purview' 'Your other DLP policies' (($other | ForEach-Object { "$($_.Name) ($(& $modeTxt $_))" }) -join '; ') 'Reviewed' Info $dlpL 'These DLP policies are not part of the ALSO baseline. Check for overlap with the baseline policies so users are not warned twice.' $doc $docText }
    }
    if ($sim.Count) { Add-Result 'Purview' 'DLP policies still in simulation mode' ($sim -join '; ') 'Switched on after reviewing the simulation results' Manual $dlpL 'The baseline starts every DLP policy in simulation mode so nothing is blocked by surprise. Review the matches in Activity explorer, then switch each policy to On.' $doc $docText }

    Set-Group 'Retention'
    Invoke-Part 'Purview' 'Retention' {
        $ret = @(Get-RetentionCompliancePolicy -ErrorAction Stop)
        $r = $ret | Where-Object { $_.Name -eq 'BP-ALSO - Exchange 7-year retention' } | Select-Object -First 1
        Add-Result 'Purview' 'Optional: BP-ALSO - Exchange 7-year retention' $(if ($r) { 'Present' } else { 'Not deployed' }) 'Only after legal review' Info 'https://purview.microsoft.com/datalifecyclemanagement/policies' 'Retention keeps mail for seven years and then deletes it. It is optional and should only be switched on after a legal and compliance review.' $doc $docText
        $o = @($ret | Where-Object { $_.Name -ne 'BP-ALSO - Exchange 7-year retention' })
        Add-Result 'Purview' 'Your other retention policies' $(if ($o) { ($o | ForEach-Object { $_.Name }) -join '; ' } else { 'None' }) 'Reviewed' Info 'https://purview.microsoft.com/datalifecyclemanagement/policies' 'Retention policies decide how long data is kept or deleted. Make sure they match your legal requirements.' $doc $docText
    }

    Set-Group 'Other Purview protections (not part of the ALSO baseline)'
    $extras = @(
        @{ N = 'Auto-labeling policies'; C = { @(Get-AutoSensitivityLabelPolicy -ErrorAction Stop) }; D = 'Auto-labeling applies labels to content that contains sensitive information, without relying on users.'; L = 'https://purview.microsoft.com/informationprotection/autolabeling' }
        @{ N = 'Insider risk management policies'; C = { @(Get-InsiderRiskPolicy -ErrorAction Stop) }; D = 'Insider risk policies detect risky activity such as data leaks by departing employees. Needs Microsoft 365 E5 or the Purview suite.'; L = 'https://purview.microsoft.com/insiderriskmanagement' }
        @{ N = 'Communication compliance policies'; C = { @(Get-SupervisoryReviewPolicyV2 -ErrorAction Stop) }; D = 'Communication compliance reviews messages for policy violations. Needs Microsoft 365 E5 or the Purview suite.'; L = 'https://purview.microsoft.com/communicationcompliance' }
    )
    foreach ($x in $extras) {
        try { $c = & $x.C; Add-Result 'Purview' $x.N $(if ($c.Count) { "$($c.Count) configured: $((($c | ForEach-Object { $_.Name }) -join '; '))" } else { 'None configured' }) 'Considered for your organization' Info $x.L $x.D $doc $docText }
        catch { Add-Result 'Purview' $x.N 'Not available or not readable' 'Considered for your organization' Info $x.L "$($x.D) The check returned: $($_.Exception.Message)" $doc $docText }
    }

    if ($script:pvMissing -gt 0) {
        Add-Result 'Purview' "Deploy the missing Purview baseline items ($($script:pvMissing))" 'Not deployed' 'Deployed with ALSO''s Purview toolkit' Manual $repo "Run Deploy-PurviewBestPractice.ps1 from ALSO's Purview toolkit ($repo) in PowerShell 7 or later, from the complete repository folder. Review Purview/Config/PurviewConfig.psd1 first and start with -WhatIf. DLP policies start in simulation mode." $doc $docText
    }
}

function Step-GuideManual {
    Write-Step 'Remaining guide steps (manual)' 'Steps in the ALSO guide that need people or portal-only decisions.'
    $rows = @(
        @('Data Access Governance report (find oversharing before Copilot)', 'Not started', 'Run and reviewed', 'https://admin.microsoft.com/sharepoint?page=dataAccessGovernance', 'Data Access Governance reports show sites with broad sharing or sensitive content. Review the reports and fix oversharing before enabling Copilot.', '#data-access-governance', 'ALSO guide: Data Access Governance (Identity and access, step 8)'),
        @('Self-service password reset pilot', 'Cannot be judged automatically', 'Enabled for a pilot group, then everyone', 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/PasswordResetMenuBlade/~/Properties', 'Self-service password reset reduces help desk calls. Start with a pilot group, confirm that users have registered methods, then widen the scope.', '#sspr', 'ALSO guide: Self-service password reset (Identity and access, step 9)'),
        @('Apple Business Manager / automated device enrollment', 'Cannot be checked automatically', 'Connected if you manage Apple devices', 'https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesEnrollmentMenu/~/appleEnrollment', 'Apple Business Manager lets you enroll company iPhones, iPads and Macs automatically. It needs an Apple ID and a decision by your organization.', '#apple-enrollment', 'ALSO guide: Supported platforms and Apple enrollment (Endpoints, step 3)'),
        @('Assign the imported Intune policies to pilot groups', 'Imported policies have no assignments', 'Assigned to a pilot group, then widened', 'https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/overview', 'Who gets each policy is your decision. Assign to a pilot group first, review reports for conflicts, then widen.', '#compliance', 'ALSO guide: Device compliance (Endpoints, step 9)'),
        @('Information protection classification and user training', 'Not started', 'Labels explained to users', 'https://purview.microsoft.com/informationprotection/labels', 'Labels only protect data when people use them. Explain the label meanings and let users practice before enforcing.', '#classification', 'ALSO guide: Classification (Data security and governance, step 2)'),
        @('Restricted content discovery for Copilot', 'Cannot be read automatically', 'Applied to sensitive sites', 'https://admin.microsoft.com/sharepoint?page=sites', 'Restricted content discovery stops Copilot and search from surfacing content on selected SharePoint sites. Choose the sites together with the business.', '#restricted-content-discovery', 'ALSO guide: Restricted content discovery (Copilot preparation, step 1)'),
        @('Copilot settings (web search, agents, data sharing)', 'Cannot be read automatically', 'Reviewed', 'https://admin.cloud.microsoft/?#/copilot/settings', 'Decide which Copilot features are allowed for your users and review agent and web search settings.', '#copilot-settings', 'ALSO guide: Copilot settings (Copilot preparation, step 2)'),
        @('Copilot adoption and user guidance', 'Not started', 'Rollout plan with a pilot group and training', 'https://adoption.microsoft.com/copilot/', 'A pilot group, training and champions make the Copilot rollout successful. This is an organizational task.', '#copilot-adoption-guidance', 'ALSO guide: Copilot adoption guidance (Copilot preparation, step 3)')
    )
    foreach ($r in $rows) { Add-Result 'GuideManual' $r[0] $r[1] $r[2] Manual $r[3] $r[4] ($GuideBase + $r[5]) $r[6] }
}

#endregion

$basicSkip = 'IntuneEnrollment', 'IntunePolicies', 'ConditionalAccess', 'MdoPresets', 'DefenderEndpoint', 'DefenderGuidance'
foreach ($s in $Steps) {
    if ($s -in $basicSkip) {
        $tier = $null
        try { $tier = (Get-LicenseTier).Tier } catch { }
        if ($tier -eq 'Basic') {
            Write-Step "$s (skipped)" 'Not part of Business Basic / Standard licenses.'
            Add-Result $s 'Intune, Conditional Access and Defender recommendations' 'Not included in Business Basic or Standard licenses' 'Requires Business Premium, E3/E5 or a Defender suite' Skipped $null 'Intune and the Defender products are not part of this license level, so these recommendations are skipped. Upgrade the license (for example Microsoft 365 Business Premium) to use them.'
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
    ConditionalAccess = 'Identity: Conditional Access & admin roles'; PrivilegedAccess = 'Identity: Conditional Access & admin roles'
    IntunePolicies = 'Devices: Intune policy baseline'; Purview = 'Data: Microsoft Purview'; GuideManual = 'Other guide steps'
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
    $lastGrp = '~'
    $rows = foreach ($r in $items) {
        if ($r.Group -and $r.Group -ne $lastGrp) { "<tr class='grp'><td colspan='5'>$(& $enc $r.Group)</td></tr>" }
        $lastGrp = $r.Group
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
.grp td{background:#eef6f6;font-weight:600;color:#00575d;padding:8px;border-bottom:1px solid #d3e6e7}
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

