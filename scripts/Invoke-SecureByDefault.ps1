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

Set-StrictMode -Off
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
    'DeviceManagementConfiguration.ReadWrite.All', 'Directory.ReadWrite.All', 'Organization.Read.All',
    'SharePointTenantSettings.ReadWrite.All', 'Policy.Read.All'
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

Show-SignIn 'Microsoft Graph (Entra ID, Intune, tenant settings)' 'Reads and, in Enforce mode, changes tenant-wide settings.' ($graphScopes -join ', ')
Write-Host '  First run only: approve the request for the "Microsoft Graph Command Line Tools" enterprise application ("Consent on behalf of your organization").' -ForegroundColor DarkGray
try { Set-MgGraphOption -DisableLoginByWAM $true -ErrorAction SilentlyContinue } catch { }
try { Connect-MgGraph -Scopes $graphScopes -NoWelcome -ErrorAction Stop }
catch { throw "Microsoft Graph sign-in failed: $($_.Exception.Message). Close any stuck sign-in windows and run the script again." }
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

function YN($v) { if ($v -eq $true) { 'Yes' } elseif ($v -eq $false) { 'No' } else { 'Unknown' } }
function Cap($s) { if ($s) { "$s".Substring(0, 1).ToUpper() + "$s".Substring(1) } else { 'Unknown' } }
$script:GuestRoles = @{
    'a0b1b346-4d3e-4e8b-98f8-753987be4970' = 'Same access as members (most inclusive)'
    '10dae51f-b6af-4016-8d66-8c2a99b929b3' = 'Limited access to properties and memberships of directory objects (default)'
    '2af84b1e-32c8-42b7-82bc-daa82404023b' = 'Restricted access to properties and memberships of directory objects (most restrictive)'
}
function Get-GuestRoleName($id) { if ($script:GuestRoles.ContainsKey("$id")) { $script:GuestRoles["$id"] } else { "Unknown role ($id)" } }

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
        if ($beta.value) { $beta = @($beta.value)[0] }
        $prop = @($beta.defaultUserRolePermissions.Keys) | Where-Object { $_ -match 'agentIdentityBlueprint' } | Select-Object -First 1
        if ($prop) {
            Compare-Setting 'UserSettings' 'Users can register agent identity blueprints' (YN $beta.defaultUserRolePermissions[$prop]) (YN $ref.usersCanRegisterAgentBlueprints) {
                Graph PATCH $buri @{ defaultUserRolePermissions = @{ $prop = $ref.usersCanRegisterAgentBlueprints } } } $link
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
    Compare-Setting 'Fido2' 'Passkey (FIDO2)' (Cap $f.state) 'Enabled' {
        Graph PATCH $uri @{ '@odata.type' = '#microsoft.graph.fido2AuthenticationMethodConfiguration'; state = 'enabled'; includeTargets = @(@{ targetType = 'group'; id = 'all_users'; isRegistrationRequired = $false }) }
    } 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods'
}

function Step-AuthMethods {
    Write-Step 'Authentication methods' 'Passwordless first, then phishing-resistant MFA; weak methods off.'
    $link = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods'
    $base = 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'
    $pol = Graph GET $base
    $names = @{ Fido2 = 'Passkey (FIDO2)'; MicrosoftAuthenticator = 'Microsoft Authenticator'; Sms = 'SMS'; TemporaryAccessPass = 'Temporary Access Pass'
        SoftwareOath = 'Third-party software OATH tokens'; Voice = 'Voice call'; Email = 'Email OTP'; X509Certificate = 'Certificate-based authentication'
        HardwareOath = 'Hardware OATH tokens'; VerifiableCredentials = 'Verified ID'; QRCodePin = 'QR code' }
    $wanted = @{ Fido2 = 'enabled'; MicrosoftAuthenticator = 'enabled'; TemporaryAccessPass = 'enabled'; Sms = 'disabled'; Voice = 'disabled'; Email = 'disabled' }
    foreach ($m in $pol.authenticationMethodConfigurations) {
        $mid = $m.id
        if ($mid -eq 'Fido2' -and $Steps -contains 'Fido2') { continue }
        $label = if ($names.ContainsKey($mid)) { $names[$mid] } else { $mid }
        if ($wanted.ContainsKey($mid)) {
            $otype = $m.'@odata.type'
            $newState = $wanted[$mid]
            Compare-Setting 'AuthMethods' $label (Cap $m.state) (Cap $newState) { Graph PATCH "$base/authenticationMethodConfigurations/$mid" @{ '@odata.type' = $otype; state = $newState } | Out-Null } $link
        }
        else { Add-Result 'AuthMethods' $label (Cap $m.state) 'Review for your organization' Info $link }
    }
    Add-Result 'AuthMethods' 'Authenticator push is not phishing-resistant' 'Enforce phishing-resistant MFA with Conditional Access authentication strengths' 'Authentication strength policy assigned' Manual 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/AuthStrengths'
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
    Compare-Setting 'Laps' 'Enable Microsoft Entra Local Administrator Password Solution (LAPS)' (YN $dr.localAdminPassword.isEnabled) 'Yes' { Graph PATCH $uri @{ localAdminPassword = @{ isEnabled = $true } } } $link
    Compare-Setting 'Laps' 'Global administrators become local admin on Entra-joined devices' (YN $dr.azureADJoin.localAdmins.enableGlobalAdmins) 'No' {
        Graph PATCH $uri @{ azureADJoin = @{ localAdmins = @{ enableGlobalAdmins = $false } } } } $link
    $ru = @{ '#microsoft.graph.noDeviceRegistrationMembership' = 'None (registering user is not local admin)'
        '#microsoft.graph.allDeviceRegistrationMembership' = 'All registering users'
        '#microsoft.graph.enumeratedDeviceRegistrationMembership' = 'Selected users and groups' }
    $curType = "$($dr.azureADJoin.localAdmins.registeringUsers.'@odata.type')"
    $curRu = if ($ru.ContainsKey($curType)) { $ru[$curType] } else { "Unknown ($curType)" }
    Compare-Setting 'Laps' 'Registering user is added as local administrator on join' $curRu $ru['#microsoft.graph.noDeviceRegistrationMembership'] {
        Graph PATCH $uri @{ azureADJoin = @{ localAdmins = @{ registeringUsers = @{ '@odata.type' = '#microsoft.graph.noDeviceRegistrationMembership' } } } } } $link
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
        Add-Result 'MdoPresets' 'Standard preset security policy' 'Not configured' 'Standard preset turned on for all recipients' Manual $link
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
    Add-Result 'DefenderGuidance' 'Incident email notifications to the right people' $na 'Configured' Manual 'https://security.microsoft.com/securitysettings/defender/email_notifications'
    Add-Result 'DefenderGuidance' 'Defender for Identity readiness / sensor deployment' $na 'Ready' Manual 'https://security.microsoft.com/securitysettings/identities'
    Add-Result 'DefenderGuidance' 'Defender for Cloud Apps and Defender for Endpoint integration' $na 'Enabled' Manual 'https://security.microsoft.com/cloudapps/settings?tabid=mdatp'
    Add-Result 'DefenderGuidance' 'App governance / OAuth app policies' $na 'Turned on' Manual 'https://security.microsoft.com/cloudapps/app-governance'
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
$cats = [ordered]@{
    AuditLog = 'Auditing & compliance'; UserSettings = 'Identity: users & external collaboration'; Consent = 'Identity: app consent'
    BreakGlass = 'Identity: emergency access'; Fido2 = 'Authentication'; AuthMethods = 'Authentication'
    SharePoint = 'Collaboration: SharePoint & OneDrive'; IntuneEnrollment = 'Devices: Intune & LAPS'; Laps = 'Devices: Intune & LAPS'
    MdoPresets = 'Defender'; DefenderEndpoint = 'Defender'; DefenderGuidance = 'Defender'
}
$label = @{ Compliant = 'Compliant'; Fixed = 'Fixed'; Drift = 'Needs change'; Manual = 'Manual action'; Info = 'Info'; Error = 'Error'; Skipped = 'Skipped' }
$total = @($script:Results).Count
$cards = foreach ($st in 'Compliant', 'Fixed', 'Drift', 'Manual', 'Error', 'Info') {
    $n = @($script:Results | Where-Object Status -eq $st).Count
    "<div class='card $st'><b>$n</b><span>$($label[$st])</span></div>"
}
$sections = foreach ($cat in ($cats.Values | Select-Object -Unique)) {
    $items = @($script:Results | Where-Object { $cats[$_.Step] -eq $cat })
    if (-not $items) { continue }
    $bad = @($items | Where-Object { $_.Status -in 'Drift', 'Error' }).Count
    $badge = if ($bad) { "<span class='pill Drift'>$bad to fix</span>" } else { "<span class='pill Compliant'>all good</span>" }
    $rows = foreach ($r in $items) {
        $l = if ($r.Link) { "<a href='$(& $enc $r.Link)' target='_blank'>Open in portal &rarr;</a>" } else { '' }
        "<tr><td class='st'><span class='pill $($r.Status)'>$($label[$r.Status])</span></td><td><b>$(& $enc $r.Setting)</b></td><td>$(& $enc $r.Current)</td><td>$(& $enc $r.Expected)</td><td>$l</td></tr>"
    }
    "<section><h2>$(& $enc $cat) $badge</h2><table><tr><th>State</th><th>Setting</th><th>Current value</th><th>Expected</th><th></th></tr>$($rows -join '')</table></section>"
}
$css = @'
body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f5f7fa;color:#1d2b3a}
header{background:#fff;border-bottom:1px solid #dde3ea;padding:20px 40px}
header h1{margin:0;font-size:1.5rem}header p{margin:4px 0 0;color:#5b6b7c}
main{max-width:1200px;margin:24px auto;padding:0 24px}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}
.card{flex:1;min-width:130px;background:#fff;border:1px solid #dde3ea;border-radius:10px;padding:14px 18px;border-top:4px solid #9aa7b4}
.card b{display:block;font-size:1.8rem}.card span{color:#5b6b7c;font-size:.85rem}
.card.Compliant,.card.Fixed{border-top-color:#2e8b57}.card.Drift{border-top-color:#d98e04}.card.Manual{border-top-color:#00757d}.card.Error{border-top-color:#c0392b}
section{background:#fff;border:1px solid #dde3ea;border-radius:10px;margin-bottom:20px;padding:6px 18px 14px}
h2{font-size:1.15rem;display:flex;align-items:center;gap:10px}
table{border-collapse:collapse;width:100%}th{text-align:left;font-size:.78rem;text-transform:uppercase;color:#5b6b7c;padding:6px 8px;border-bottom:2px solid #e6ebf0}
td{padding:9px 8px;border-bottom:1px solid #eef2f6;vertical-align:top;font-size:.9rem;word-break:break-word}td.st{white-space:nowrap}
a{color:#0b5cab;text-decoration:none}a:hover{text-decoration:underline}
.next{background:#fff;border:1px solid #dde3ea;border-left:5px solid #00757d;border-radius:10px;padding:8px 24px 22px;margin:28px 0}.next p{color:#5b6b7c;max-width:760px}.btn{display:inline-block;background:#0b5cab;color:#fff!important;padding:10px 20px;border-radius:8px;font-weight:600}.btn:hover{text-decoration:none;background:#094a8c}
.pill{display:inline-block;padding:2px 10px;border-radius:12px;font-size:.78rem;font-weight:600;color:#fff;background:#9aa7b4}
.pill.Compliant,.pill.Fixed{background:#2e8b57}.pill.Drift{background:#d98e04}.pill.Manual{background:#00757d}.pill.Error{background:#c0392b}
'@
$page = "<!DOCTYPE html><html><head><meta charset='utf-8'><title>ALSO Secure by Default report</title><style>$css</style></head><body><header><h1>ALSO Secure by Default &ndash; $Mode report</h1><p>$(& $enc $org.displayName) &middot; $(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; $total settings checked</p></header><main><div class='cards'>$($cards -join '')</div>$($sections -join '')<div class='next'><h2>Done reviewing these settings? Continue with deeper configuration.</h2><p>Secure by Default sets the tenant-wide prerequisites. Next, use the ALSO Microsoft Security Policy Templates Navigator to choose the policy templates and configuration that fit your licenses and platforms.</p><a class='btn' href='https://coc-ms.github.io/ALSO-security-policy-templates-navigator/' target='_blank'>Open the Navigator &rarr;</a></div></main></body></html>"
[IO.File]::WriteAllText($html, $page, (New-Object Text.UTF8Encoding($false)))

Write-Host "`nSummary:" -ForegroundColor Cyan
$script:Results | Group-Object Status | ForEach-Object { Write-Host ("  {0,-10} {1}" -f $_.Name, $_.Count) }
Write-Host "Reports: $json`n         $html"
Write-Host "
Done reviewing? Continue with deeper configuration in the ALSO Policy Templates Navigator:" -ForegroundColor Cyan
Write-Host '  https://coc-ms.github.io/ALSO-security-policy-templates-navigator/' -ForegroundColor Cyan
try { Invoke-Item $html } catch { Write-Host "Open the HTML report manually: $html" -ForegroundColor Yellow }
if ($Mode -eq 'Discover') {
    $driftSteps = @($script:Results | Where-Object Status -eq 'Drift' | Select-Object -ExpandProperty Step -Unique)
    if ($driftSteps) {
        Write-Host "`nDrift found in: $($driftSteps -join ', ')" -ForegroundColor Yellow
        Write-Host 'Enforce mode changes settings one at a time and asks you to confirm each change. It needs a new Global Administrator sign-in with write permissions.'
        if ((Read-Host 'Do you want to proceed with step-by-step enforce mode? [y/N]') -match '^(y|yes)$') {
            try { Disconnect-MgGraph | Out-Null } catch { }
            try { Disconnect-ExchangeOnline -Confirm:$false | Out-Null } catch { }
            $pass = @{ Mode = 'Enforce'; Steps = $driftSteps; OutputPath = $OutputPath; BreakGlassGroupName = $BreakGlassGroupName; BreakGlassAuName = $BreakGlassAuName }
            foreach ($k in 'SharePointAdminUrl', 'PilotGroupId', 'AdminConsentReviewerIds') { if ($PSBoundParameters.ContainsKey($k)) { $pass[$k] = $PSBoundParameters[$k] } }
            if ($Force) { $pass.Force = $true }
            if ($WhatIfPreference) { $pass.WhatIf = $true }
            & $PSCommandPath @pass
        }
        else { Write-Host 'No changes made. Re-run with -Mode Enforce whenever you are ready.' -ForegroundColor Green }
    }
}
#endregion

