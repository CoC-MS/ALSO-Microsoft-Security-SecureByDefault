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
    [ValidateSet('AuditLog', 'UserSettings', 'Consent', 'BreakGlass', 'Fido2', 'AuthMethods', 'SharePoint',
        'IntuneEnrollment', 'Laps', 'MdoPresets', 'DefenderEndpoint', 'DefenderGuidance')]
    [string[]]$Steps = @('AuditLog', 'UserSettings', 'Consent', 'BreakGlass', 'Fido2', 'AuthMethods', 'SharePoint',
        'IntuneEnrollment', 'Laps', 'MdoPresets', 'DefenderEndpoint', 'DefenderGuidance'),
    [string]$SharePointAdminUrl,
    [string]$OutputPath = (Join-Path (Get-Location) 'sbd-reports'),
    [string]$PilotGroupId,
    [string]$BreakGlassGroupName = 'SBD-BreakGlass-Accounts',
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

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Results = [System.Collections.Generic.List[object]]::new()
$script:Reference = Get-Content (Join-Path $PSScriptRoot '..\config\reference-state.json') -Raw | ConvertFrom-Json

#region helpers
function Add-Result {
    param($Step, $Setting, $Current, $Expected, [ValidateSet('Compliant', 'Drift', 'Fixed', 'Manual', 'Info', 'Error', 'Skipped')]$Status, $Link)
    $script:Results.Add([pscustomobject]@{ Step = $Step; Setting = $Setting; Current = "$Current"; Expected = "$Expected"; Status = $Status; Link = $Link })
    $color = @{ Compliant = 'Green'; Fixed = 'Green'; Drift = 'Yellow'; Manual = 'Cyan'; Info = 'Gray'; Error = 'Red'; Skipped = 'DarkGray' }[$Status]
    Write-Host ("  [{0,-9}] {1}: {2} (expected {3})" -f $Status, $Setting, $Current, $Expected) -ForegroundColor $color
    if ($Link -and $Status -in 'Manual', 'Drift') { Write-Host "              -> $Link" -ForegroundColor DarkCyan }
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
    param($Step, $Setting, $Current, $Expected, [scriptblock]$Fix, $Link)
    if ("$Current" -eq "$Expected") { Add-Result $Step $Setting $Current $Expected Compliant $Link; return }
    if ($Fix -and (Confirm-Change "$Setting -> $Expected")) {
        try { & $Fix; Add-Result $Step $Setting $Current $Expected Fixed $Link }
        catch { Add-Result $Step $Setting $Current $Expected Error $Link; Write-Warning $_.Exception.Message }
    }
    else { Add-Result $Step $Setting $Current $Expected Drift $Link }
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
    'Policy.ReadWrite.AuthorizationPolicy', 'Policy.ReadWrite.AuthenticationMethod', 'Policy.ReadWrite.ConsentRequest',
    'Policy.ReadWrite.PermissionGrant', 'Policy.ReadWrite.DeviceConfiguration', 'User.ReadWrite.All', 'Group.ReadWrite.All',
    'AdministrativeUnit.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'DeviceManagementServiceConfig.ReadWrite.All',
    'DeviceManagementConfiguration.Read.All', 'Directory.Read.All', 'Organization.Read.All'
}
else {
    'Policy.Read.All', 'User.Read.All', 'Group.Read.All', 'AdministrativeUnit.Read.All', 'RoleManagement.Read.Directory',
    'DeviceManagementServiceConfig.Read.All', 'DeviceManagementConfiguration.Read.All', 'Directory.Read.All', 'Organization.Read.All'
}
Write-Host "ALSO Secure by Default - mode: $Mode" -ForegroundColor Cyan
if ($Mode -eq 'Discover') { Write-Host "Read-only discovery. Nothing will be changed." -ForegroundColor Green }

Initialize-Module Microsoft.Graph.Authentication
$needsExo = [bool]($Steps | Where-Object { $_ -in 'AuditLog', 'MdoPresets' })
$needsSpo = $Steps -contains 'SharePoint'
$signInCount = 1 + [int]$needsExo + [int]$needsSpo
$script:signInNo = 0
function Show-SignIn([string]$Service, [string]$Why, [string]$Access) {
    $script:signInNo++
    Write-Host ''
    Write-Host "SIGN-IN $($script:signInNo) of ${signInCount}: $Service" -ForegroundColor Yellow
    Write-Host "  Why    : $Why"
    Write-Host "  Access : $Access"
    Write-Host '  A browser window opens. Sign in with your Global Administrator account.'
}

Show-SignIn 'Microsoft Graph (Entra ID, Intune, tenant settings)' 'Reads and, in Enforce mode, changes tenant-wide settings.' ($graphScopes -join ', ')
Write-Host '  First run only: approve the request for the "Microsoft Graph Command Line Tools" enterprise application ("Consent on behalf of your organization").' -ForegroundColor DarkGray
try { Set-MgGraphOption -DisableLoginByWAM $true -ErrorAction SilentlyContinue } catch { }
try { Connect-MgGraph -Scopes $graphScopes -NoWelcome -ErrorAction Stop }
catch { throw "Microsoft Graph sign-in failed: $($_.Exception.Message). Close any stuck sign-in windows and run the script again." }
Write-Host '  Signed in to Microsoft Graph.' -ForegroundColor Green$gaRole = '62e90394-69f5-4237-9190-012177145e10'
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
    Show-SignIn 'Exchange Online / Security & Compliance' 'Unified audit log and Defender for Office 365 preset policies.' 'Exchange Online administration (Global Administrator role)'
    Initialize-Module ExchangeOnlineManagement
    try { Connect-ExchangeOnline -ShowBanner:$false -DisableWAM -ErrorAction Stop }
    catch { throw "Exchange Online sign-in failed: $($_.Exception.Message)" }
    Write-Host '  Signed in to Exchange Online.' -ForegroundColor Green
}
#endregion

#region steps
function Step-AuditLog {
    Write-Step 'Unified audit log' 'Required for investigations, Defender and Purview.'
    $cfg = Get-AdminAuditLogConfig
    Compare-Setting 'AuditLog' 'UnifiedAuditLogIngestionEnabled' $cfg.UnifiedAuditLogIngestionEnabled 'True' {
        Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
    } 'https://purview.microsoft.com/audit/auditsearch'
}

function Step-UserSettings {
    Write-Step 'Entra user settings & external collaboration' 'Default user permissions and guest restrictions.'
    $ref = $script:Reference.userSettings
    $uri = 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
    $p = Graph GET $uri
    $d = $p.defaultUserRolePermissions
    $link = 'https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/UserSettings'
    Compare-Setting 'UserSettings' 'Users can register applications' $d.allowedToCreateApps $ref.usersCanRegisterApps { Graph PATCH $uri @{ defaultUserRolePermissions = @{ allowedToCreateApps = $ref.usersCanRegisterApps } } } $link
    Compare-Setting 'UserSettings' 'Restrict non-admin users from creating tenants' (-not $d.allowedToCreateTenants) $ref.restrictTenantCreation { Graph PATCH $uri @{ defaultUserRolePermissions = @{ allowedToCreateTenants = (-not $ref.restrictTenantCreation) } } } $link
    Compare-Setting 'UserSettings' 'Users can create security groups' $d.allowedToCreateSecurityGroups $ref.usersCanCreateSecurityGroups { Graph PATCH $uri @{ defaultUserRolePermissions = @{ allowedToCreateSecurityGroups = $ref.usersCanCreateSecurityGroups } } } $link
    Compare-Setting 'UserSettings' 'Guest user access (guestUserRoleId)' $p.guestUserRoleId $ref.guestUserRoleId { Graph PATCH $uri @{ guestUserRoleId = $ref.guestUserRoleId } } 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AllowlistPolicyBlade'
    try {
        $beta = Graph GET 'https://graph.microsoft.com/beta/policies/authorizationPolicy'
        $prop = $beta.defaultUserRolePermissions.Keys | Where-Object { $_ -match 'agentIdentityBlueprint' } | Select-Object -First 1
        if ($prop) {
            Compare-Setting 'UserSettings' 'Users can register agent identity blueprints' $beta.defaultUserRolePermissions[$prop] $ref.usersCanRegisterAgentBlueprints {
                Graph PATCH 'https://graph.microsoft.com/beta/policies/authorizationPolicy' @{ defaultUserRolePermissions = @{ $prop = $ref.usersCanRegisterAgentBlueprints } } } $link
        }
        else { Add-Result 'UserSettings' 'Users can register agent identity blueprints' 'not exposed by API' $ref.usersCanRegisterAgentBlueprints Manual $link }
    }
    catch { Add-Result 'UserSettings' 'Users can register agent identity blueprints' 'not readable' $ref.usersCanRegisterAgentBlueprints Manual $link }
    Add-Result 'UserSettings' 'Restrict access to Microsoft Entra admin center' 'portal-only' $ref.restrictAdminCenter Manual $link
    Add-Result 'UserSettings' 'LinkedIn account connections' 'portal-only' "$($ref.linkedIn) (business/privacy decision)" Manual $link
    Add-Result 'UserSettings' 'Show keep user signed in' 'portal-only' $ref.showKeepSignedIn Manual 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/CompanyBrandingMenuBlade/~/CompanyBranding'
}

function Step-Consent {
    Write-Step 'User consent & admin consent workflow' 'Limit OAuth consent phishing.'
    $ref = $script:Reference.consent
    $uri = 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
    $p = Graph GET $uri
    $current = @($p.defaultUserRolePermissions.permissionGrantPoliciesAssigned) -join ','
    Compare-Setting 'Consent' 'User consent policy' $current $ref.userConsentPolicy {
        Graph PATCH $uri @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @($ref.userConsentPolicy) } }
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
            Add-Result 'BreakGlass' "Account $upn" 'missing' 'created' Fixed $link; $u
        }
        else { Add-Result 'BreakGlass' "Account $upn" 'missing' 'exists' Drift $link }
    })

    $g = (Graph GET "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$BreakGlassGroupName'").value | Select-Object -First 1
    if (-not $g -and (Confirm-Change "Create security group $BreakGlassGroupName")) {
        $g = Graph POST 'https://graph.microsoft.com/v1.0/groups' @{ displayName = $BreakGlassGroupName; mailNickname = ($BreakGlassGroupName -replace '\W', ''); mailEnabled = $false; securityEnabled = $true; description = 'Emergency access accounts' }
        Add-Result 'BreakGlass' 'Security group' 'missing' 'created' Fixed $null
    }
    elseif ($g) { Add-Result 'BreakGlass' 'Security group' 'exists' 'exists' Compliant $null }
    else { Add-Result 'BreakGlass' 'Security group' 'missing' 'exists' Drift $null }

    if ($g) {
        $members = @((Graph GET "https://graph.microsoft.com/v1.0/groups/$($g.id)/members?`$select=id").value.id)
        foreach ($u in $users) {
            if ($u.id -in $members) { continue }
            if (Confirm-Change "Add $($u.userPrincipalName) to $BreakGlassGroupName") {
                Graph POST "https://graph.microsoft.com/v1.0/groups/$($g.id)/members/`$ref" @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($u.id)" } | Out-Null
                Add-Result 'BreakGlass' "Membership $($u.userPrincipalName)" 'missing' 'member' Fixed $null
            }
            else { Add-Result 'BreakGlass' "Membership $($u.userPrincipalName)" 'missing' 'member' Drift $null }
        }
    }

    $gaTemplate = '62e90394-69f5-4237-9190-012177145e10'
    foreach ($u in $users) {
        $has = (Graph GET "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($u.id)' and roleDefinitionId eq '$gaTemplate'").value
        if ($has) { Add-Result 'BreakGlass' "Global Admin $($u.userPrincipalName)" 'assigned' 'assigned' Compliant $null; continue }
        if (Confirm-Change "Assign Global Administrator (permanent) to $($u.userPrincipalName)") {
            Graph POST 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments' @{ principalId = $u.id; roleDefinitionId = $gaTemplate; directoryScopeId = '/' } | Out-Null
            Add-Result 'BreakGlass' "Global Admin $($u.userPrincipalName)" 'missing' 'assigned' Fixed $null
        }
        else { Add-Result 'BreakGlass' "Global Admin $($u.userPrincipalName)" 'missing' 'assigned' Drift $null }
    }

    $auLink = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AdministrativeUnitsMenuBlade/~/AdminUnits'
    $au = (Graph GET "https://graph.microsoft.com/v1.0/directory/administrativeUnits?`$filter=displayName eq '$BreakGlassAuName'").value | Select-Object -First 1
    if (-not $au -and (Confirm-Change "Create restricted-management AU $BreakGlassAuName")) {
        $au = Graph POST 'https://graph.microsoft.com/v1.0/directory/administrativeUnits' @{ displayName = $BreakGlassAuName; description = 'Protects emergency access objects'; isMemberManagementRestricted = $true }
        Add-Result 'BreakGlass' 'Restricted management AU' 'missing' 'created' Fixed $auLink
    }
    elseif ($au) { Compare-Setting 'BreakGlass' 'AU restricted management' $au.isMemberManagementRestricted 'True' $null $auLink }
    else { Add-Result 'BreakGlass' 'Restricted management AU' 'missing' 'exists' Drift $auLink }
    if ($au -and $g) {
        $auMembers = @((Graph GET "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$($au.id)/members?`$select=id").value.id)
        if ($g.id -in $auMembers) { Add-Result 'BreakGlass' 'Group in AU' 'yes' 'yes' Compliant $null }
        elseif (Confirm-Change "Add group to AU $BreakGlassAuName") {
            Graph POST "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$($au.id)/members/`$ref" @{ '@odata.id' = "https://graph.microsoft.com/v1.0/groups/$($g.id)" } | Out-Null
            Add-Result 'BreakGlass' 'Group in AU' 'no' 'yes' Fixed $null
        }
        else { Add-Result 'BreakGlass' 'Group in AU' 'no' 'yes' Drift $null }
    }
    Add-Result 'BreakGlass' 'FIDO2 key registration + TAP, CA exclusions, SSPR exclusion, sign-in alert' 'manual' 'done' Manual 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access'
}

function Step-Fido2 {
    Write-Step 'Passkey (FIDO2) authentication method' 'Allow phishing-resistant sign-in for all users.'
    $uri = 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2'
    $f = Graph GET $uri
    Compare-Setting 'Fido2' 'FIDO2 state' $f.state 'enabled' {
        Graph PATCH $uri @{ '@odata.type' = '#microsoft.graph.fido2AuthenticationMethodConfiguration'; state = 'enabled'; includeTargets = @(@{ targetType = 'group'; id = 'all_users'; isRegistrationRequired = $false }) }
    } 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods'
}

function Step-AuthMethods {
    Write-Step 'Authentication methods review' 'Passwordless first, then phishing-resistant MFA; review weak methods.'
    $link = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods'
    $pol = Graph GET 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'
    foreach ($m in $pol.authenticationMethodConfigurations) {
        $weak = $m.id -in 'Sms', 'Voice', 'Email'
        $status = if ($m.state -eq 'enabled' -and $weak) { 'Drift' } else { 'Info' }
        Add-Result 'AuthMethods' $m.id $m.state $(if ($weak) { 'disabled/limited' } else { 'review targets' }) $status $link
    }
    Add-Result 'AuthMethods' 'Authenticator phone sign-in is not phishing-resistant' 'review' 'use CA authentication strengths' Manual 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/AuthStrengths'
}

function Step-SharePoint {
    Write-Step 'SharePoint & OneDrive external sharing' 'Tighten tenant-level sharing and default links.'
    Initialize-Module Microsoft.Online.SharePoint.PowerShell
    Show-SignIn 'SharePoint Online admin' 'Tenant-level external sharing settings.' "SharePoint administration at $SharePointAdminUrl"
    Connect-SPOService -Url $SharePointAdminUrl
    Write-Host '  Signed in to SharePoint Online.' -ForegroundColor Green
    $t = Get-SPOTenant
    $ref = $script:Reference.sharePoint
    $link = "$SharePointAdminUrl/_layouts/15/online/AdminHome.aspx#/sharing"
    Compare-Setting 'SharePoint' 'SharingCapability' $t.SharingCapability $ref.sharingCapability { Set-SPOTenant -SharingCapability $ref.sharingCapability } $link
    Compare-Setting 'SharePoint' 'DefaultSharingLinkType' $t.DefaultSharingLinkType $ref.defaultSharingLinkType { Set-SPOTenant -DefaultSharingLinkType $ref.defaultSharingLinkType } $link
    Compare-Setting 'SharePoint' 'Anonymous links expire within 30 days' ([int]$t.RequireAnonymousLinksExpireInDays -in 1..30) 'True' { Set-SPOTenant -RequireAnonymousLinksExpireInDays 30 } $link
    Compare-Setting 'SharePoint' 'ExternalUserExpirationRequired' $t.ExternalUserExpirationRequired 'True' { Set-SPOTenant -ExternalUserExpirationRequired $true -ExternalUserExpireInDays 30 } $link
}

function Step-IntuneEnrollment {
    Write-Step 'Intune automatic enrollment (MDM user scope)' 'Devices joining Entra are enrolled in Intune automatically.'
    $link = 'https://intune.microsoft.com/#view/Microsoft_AAD_IAM/MdmConfiguration.ReactView'
    $base = 'https://graph.microsoft.com/beta/policies/mobileDeviceManagementPolicies'
    $pol = (Graph GET $base).value | Where-Object { $_.displayName -match 'Intune' } | Select-Object -First 1
    if (-not $pol) { Add-Result 'IntuneEnrollment' 'MDM policy' 'not found' 'Intune' Manual $link; return }
    $want = if ($PilotGroupId) { 'selected' } else { 'all' }
    Compare-Setting 'IntuneEnrollment' 'MDM user scope' $pol.appliesTo $want {
        Graph PATCH "$base/$($pol.id)" @{ appliesTo = $want }
        if ($PilotGroupId) { Graph POST "$base/$($pol.id)/includedGroups/`$ref" @{ '@odata.id' = "https://graph.microsoft.com/beta/groups/$PilotGroupId" } | Out-Null }
    } $link
}

function Step-Laps {
    Write-Step 'Local admin & LAPS (Entra device settings)' 'Remove standing local admin; enable Entra LAPS.'
    $link = 'https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings'
    $uri = 'https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy'
    $dr = Graph GET $uri
    Compare-Setting 'Laps' 'Entra LAPS enabled' $dr.localAdminPassword.isEnabled 'True' { Graph PATCH $uri @{ localAdminPassword = @{ isEnabled = $true } } } $link
    Compare-Setting 'Laps' 'Global admins added as local admin on join' $dr.azureADJoin.localAdmins.enableGlobalAdmins 'False' {
        Graph PATCH $uri @{ azureADJoin = @{ localAdmins = @{ enableGlobalAdmins = $false } } } } $link
    Compare-Setting 'Laps' 'Registering user added as local admin' $dr.azureADJoin.localAdmins.registeringUsers.'@odata.type' '#microsoft.graph.noDeviceRegistrationMembership' {
        Graph PATCH $uri @{ azureADJoin = @{ localAdmins = @{ registeringUsers = @{ '@odata.type' = '#microsoft.graph.noDeviceRegistrationMembership' } } } } } $link
    Add-Result 'Laps' 'Windows LAPS policy deployment' 'manual' 'deployed via Intune' Manual 'https://intune.microsoft.com/#view/Microsoft_Intune_Workflows/SecurityManagementMenu/~/accountprotection'
}

function Step-MdoPresets {
    Write-Step 'Defender for Office 365 preset security policies' 'Standard/Strict presets for EOP and Safe Links/Attachments.'
    $link = 'https://security.microsoft.com/presetSecurityPolicies'
    foreach ($kind in 'EOP', 'ATP') {
        foreach ($r in @(& "Get-${kind}ProtectionPolicyRule")) {
            if ($r.Identity -match 'Standard') {
                Compare-Setting 'MdoPresets' "$kind $($r.Identity) state" $r.State 'Enabled' { & "Enable-${kind}ProtectionPolicyRule" -Identity $r.Identity } $link
            }
            else { Add-Result 'MdoPresets' "$kind $($r.Identity)" $r.State 'review recipients' Info $link }
        }
    }
}

function Step-DefenderEndpoint {
    Write-Step 'Defender for Endpoint & Intune connection' 'Verify provisioning and connector status.'
    $atp = 'https://intune.microsoft.com/#view/Microsoft_Intune_Workflows/SecurityManagementMenu/~/atp'
    Add-Result 'DefenderEndpoint' 'Defender for Business/Endpoint provisioned (Assets > Devices)' 'portal check' 'devices page loads' Manual 'https://security.microsoft.com/machines?category=all-devices'
    Add-Result 'DefenderEndpoint' 'Intune connection ON (Settings > Endpoints > Advanced features)' 'portal check' 'On' Manual 'https://security.microsoft.com/securitysettings/endpoints/integration'
    try {
        $c = @((Graph GET 'https://graph.microsoft.com/beta/deviceManagement/mobileThreatDefenseConnectors').value)
        $mde = @($c | Where-Object { $_.id })
        if (-not $mde) { Add-Result 'DefenderEndpoint' 'Intune MDE connector' 'none' 'enabled' Drift $atp }
        foreach ($x in $mde) { Compare-Setting 'DefenderEndpoint' "Intune connector $($x.id)" $x.partnerState 'enabled' $null $atp }
    }
    catch { Add-Result 'DefenderEndpoint' 'Intune MDE connector status' 'not readable' 'Enabled' Manual $atp }
}

function Step-DefenderGuidance {
    Write-Step 'Defender XDR guidance' 'Items with no supported automation API today.'
    Add-Result 'DefenderGuidance' 'Incident email notifications to the right people' 'portal' 'configured' Manual 'https://security.microsoft.com/securitysettings/defender/email_notifications'
    Add-Result 'DefenderGuidance' 'Defender for Identity readiness / sensor deployment' 'portal' 'ready' Manual 'https://security.microsoft.com/securitysettings/identities'
    Add-Result 'DefenderGuidance' 'Defender for Cloud Apps <-> Defender for Endpoint integration' 'portal' 'enabled' Manual 'https://security.microsoft.com/cloudapps/settings?tabid=mdatp'
    Add-Result 'DefenderGuidance' 'App governance / OAuth app policies' 'portal' 'turned on' Manual 'https://security.microsoft.com/cloudapps/app-governance'
}
#endregion

foreach ($s in $Steps) { Invoke-Safe $s { & "Step-$s" } }

#region report
New-Item -ItemType Directory -Force $OutputPath | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$json = Join-Path $OutputPath "sbd-$Mode-$stamp.json"
$html = Join-Path $OutputPath "sbd-$Mode-$stamp.html"
$script:Results | ConvertTo-Json -Depth 4 | Set-Content $json -Encoding UTF8
$enc = { param($s) [Net.WebUtility]::HtmlEncode("$s") }
$rows = $script:Results | ForEach-Object {
    $l = if ($_.Link) { "<a href='$(& $enc $_.Link)'>open</a>" } else { '' }
    "<tr class='$($_.Status)'><td>$($_.Step)</td><td>$(& $enc $_.Setting)</td><td>$(& $enc $_.Current)</td><td>$(& $enc $_.Expected)</td><td>$($_.Status)</td><td>$l</td></tr>"
}
@"
<html><head><meta charset='utf-8'><title>ALSO Secure by Default report</title><style>body{font-family:Segoe UI;margin:2em}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:6px}th{background:#0a2540;color:#fff}.Drift{background:#fff3cd}.Error{background:#f8d7da}.Compliant,.Fixed{background:#d4edda}.Manual{background:#d1ecf1}</style></head><body><h1>ALSO Secure by Default - $Mode</h1><p>$(& $enc $org.displayName) - $(Get-Date)</p><table><tr><th>Step</th><th>Setting</th><th>Current</th><th>Expected</th><th>Status</th><th>Portal</th></tr>$($rows -join '')</table></body></html>
"@ | Set-Content $html -Encoding UTF8

Write-Host "`nSummary:" -ForegroundColor Cyan
$script:Results | Group-Object Status | ForEach-Object { Write-Host ("  {0,-10} {1}" -f $_.Name, $_.Count) }
Write-Host "Reports: $json`n         $html"
if ($Mode -eq 'Discover' -and ($script:Results | Where-Object Status -eq 'Drift')) {
    Write-Host "Drift found. Review the report, then re-run with -Mode Enforce." -ForegroundColor Yellow
}
#endregion

