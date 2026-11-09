<#
.SYNOPSIS
  ALSO Secure by Default - tenant-wide Microsoft 365 baseline automation.

.DESCRIPTION
  Automates tenant settings not covered by ALSO JSON configuration files.
  Default mode is Discover (read-only). Use -Mode Enforce to apply changes;
  each change is confirmed step by step (-Force skips prompts, -WhatIf dry-runs).


.PARAMETER Mode     Discover (read-only, default), Enforce, or Wipe (removes what this script deployed; asks per category: all, one by one or none).
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
  ./Invoke-SecureByDefault.ps1 -Mode Wipe -Steps ConditionalAccess,IntunePolicies   # remove what was deployed
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Discover', 'Enforce', 'Wipe')][string]$Mode = 'Discover',
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
    if ($Status -eq 'Error' -and $Detail) { Write-Host "              Reason: $Detail" -ForegroundColor Red }
    if ($Link -and $Status -in 'Manual', 'Drift') { Write-Host "              -> $Link" -ForegroundColor DarkCyan }
    if ($Doc -and $Status -in 'Manual', 'Drift', 'Skipped') { Write-Host "              Guide: $Doc" -ForegroundColor DarkCyan }
}

function Set-Group([string]$Name) { $script:Group = $Name }

function Write-Step([string]$Title, [string]$Why) {
    $script:Group = $null
    Write-Host "`n== $Title ==" -ForegroundColor Magenta
    Write-Host "   $Why" -ForegroundColor DarkGray
}

function Confirm-Change([string]$Action, [switch]$Always) {
    if ($Mode -ne 'Enforce') { return $false }
    if (-not $PSCmdlet.ShouldProcess($Action)) { return $false }
    if ($Force) { return $true }
    if ($script:SkipAll) { return $false }
    $script:ChangeNo++
    if ($script:ApplyAll -and -not $Always) { Write-Host "   Change $($script:ChangeNo): applying - $Action" -ForegroundColor DarkGray; return $true }
    Write-Host ''
    Write-Host "   Change $($script:ChangeNo): $Action" -ForegroundColor Yellow
    $a = Read-Host '   Apply this change? [y] yes  [n] no  [a] yes to all remaining  [s] skip all remaining (default: no)'
    switch -regex ($a) {
        '^(a|all)$' { if (-not $Always) { $script:ApplyAll = $true }; return $true }
        '^(s|skip)$' { $script:SkipAll = $true; return $false }
        '^(y|yes)$' { return $true }
        default { return $false }
    }
}

function Select-Deployment($Items, [string]$Noun, [scriptblock]$Name) {
    $Items = @($Items)
    if (-not $Items.Count -or $Mode -ne 'Enforce' -or $script:SkipAll) { return @() }
    if (-not $PSCmdlet.ShouldProcess("Deploy $($Items.Count) $Noun")) { return @() }
    if ($Force -or $script:ApplyAll) { return $Items }
    Write-Host ''
    Write-Host "   $($Items.Count) missing $Noun can be deployed:" -ForegroundColor Yellow
    $Items | ForEach-Object { Write-Host "     - $(& $Name $_)" }
    $a = Read-Host '   [a] deploy all  [o] choose one by one  [n] deploy none (default: none)'
    if ($a -match '^(a|all)$') { return $Items }
    if ($a -match '^(o|one)$') {
        $sel = @()
        foreach ($i in $Items) { if ((Read-Host "   Deploy '$(& $Name $i)'? [y/N]") -match '^(y|yes)$') { $sel += $i } }
        return $sel
    }
    return @()
}

function Compare-Setting {
    param($Step, $Setting, $Current, $Expected, [scriptblock]$Fix, $Link, $Detail, $Doc, $DocText)
    if ("$Current" -eq "$Expected") { Add-Result $Step $Setting $Current $Expected Compliant $Link $Detail $Doc $DocText; return }
    if ($Fix -and (Confirm-Change "$Setting - change from '$Current' to '$Expected'")) {
        try { & $Fix; Add-Result $Step $Setting $Current $Expected Fixed $Link $Detail $Doc $DocText }
        catch { Add-Result $Step $Setting $Current $Expected Error $Link "$($_.Exception.Message)" $Doc $DocText }
    }
    else { Add-Result $Step $Setting $Current $Expected Drift $Link $Detail $Doc $DocText }
}

$script:IppsTok = $null; $script:IppsWorker = $null
function Wait-Worker($ps, [int]$Seconds, [string]$What) {
    $ar = $ps.BeginInvoke()
    if (-not $ar.AsyncWaitHandle.WaitOne($Seconds * 1000)) {
        try { [void]$ps.BeginStop($null, $null) } catch {}
        throw "$What did not answer within $Seconds seconds and was skipped"
    }
    $out = @($ps.EndInvoke($ar))
    if ($ps.Streams.Error.Count) { throw $ps.Streams.Error[0].Exception.Message }
    $out
}
function Invoke-Timed([string]$Code, [int]$Seconds = 60) {
    if (-not $script:IppsTok) { return @(& ([scriptblock]::Create($Code))) }
    if (-not $script:IppsWorker) {
        $rs = [runspacefactory]::CreateRunspace(); $rs.Open()
        $ps = [powershell]::Create(); $ps.Runspace = $rs
        [void]$ps.AddScript('param($t,$o) Import-Module ExchangeOnlineManagement -ErrorAction Stop; Connect-IPPSSession -AccessToken $t -Organization $o -ShowBanner:$false -ErrorAction Stop').AddArgument($script:IppsTok).AddArgument($script:IppsOrg)
        try { [void](Wait-Worker $ps 120 'Connecting to Purview') } catch { try { $rs.Dispose() } catch {}; throw }
        $script:IppsWorker = $rs
    }
    $ps = [powershell]::Create(); $ps.Runspace = $script:IppsWorker
    [void]$ps.AddScript($Code)
    try { Wait-Worker $ps $Seconds 'Purview' }
    catch { if ($_.Exception.Message -like '*skipped') { $script:IppsWorker = $null }; throw }
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
        $raw = "$($_.ErrorDetails.Message)"
        if (-not $raw) { try { $raw = $_.Exception.Response.Content.ReadAsStringAsync().GetAwaiter().GetResult() } catch { } }
        if ($raw) {
            try { $e = ($raw | ConvertFrom-Json).error; $m = (@($e.code, $e.message) | Where-Object { $_ }) -join ': ' } catch { $m = $raw }
        }
        $status = ''
        try { if ($_.Exception.Response.StatusCode) { $status = " HTTP $([int]$_.Exception.Response.StatusCode)" } } catch { }
        if (-not "$m".Trim()) { $m = 'No error details returned' }
        throw "$m [$Method $(($Uri -split '\?')[0] -replace 'https://graph.microsoft.com/','')$status]"
    }
}

function New-StrongPassword {
    $chars = [char[]](33..126) | Where-Object { $_ -notin [char[]]'"''`\' }
    $bytes = [byte[]]::new(40)
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    -join ($bytes | ForEach-Object { $chars[$_ % $chars.Count] })
}

function Initialize-Module([string]$Name) {
    if (Get-Module $Name) { return }
    if (-not (Get-Module -ListAvailable $Name)) {
        Write-Host "   Installing module $Name (CurrentUser)..." -ForegroundColor DarkGray
        Install-Module $Name -Scope CurrentUser -Force -AllowClobber
    }
    if ($Name -like 'Microsoft.Online.SharePoint*' -and $PSVersionTable.PSEdition -eq 'Core') { Import-Module $Name -UseWindowsPowerShell -WarningAction SilentlyContinue -ErrorAction Stop }
    else { Import-Module $Name -ErrorAction Stop }
}
#endregion

#region connections
$graphScopes = if ($Mode -eq 'Wipe') {
    'Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All', 'Application.Read.All', 'Group.ReadWrite.All', 'User.ReadWrite.All',
    'AdministrativeUnit.ReadWrite.All', 'Directory.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'Organization.Read.All', 'DeviceManagementConfiguration.ReadWrite.All',
    'Policy.ReadWrite.Authorization', 'Policy.ReadWrite.ConsentRequest', 'Policy.ReadWrite.PermissionGrant', 'Policy.ReadWrite.DeviceConfiguration', 'Policy.ReadWrite.MobilityManagement', 'SharePointTenantSettings.ReadWrite.All',
    'DeviceManagementApps.ReadWrite.All', 'DeviceManagementServiceConfig.ReadWrite.All'
}
elseif ($Mode -eq 'Enforce') {
    'Policy.ReadWrite.Authorization', 'Policy.ReadWrite.AuthenticationMethod', 'Policy.ReadWrite.ConsentRequest',
    'Policy.ReadWrite.PermissionGrant', 'Policy.ReadWrite.DeviceConfiguration', 'User.ReadWrite.All', 'Group.ReadWrite.All',
    'AdministrativeUnit.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'DeviceManagementServiceConfig.ReadWrite.All',
    'DeviceManagementConfiguration.ReadWrite.All', 'Directory.ReadWrite.All', 'Organization.Read.All',
    'SharePointTenantSettings.ReadWrite.All', 'Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess',
    'DeviceManagementApps.ReadWrite.All', 'Application.Read.All', 'AccessReview.Read.All', 'Policy.ReadWrite.MobilityManagement'
}
else {
    'Policy.Read.All', 'User.Read.All', 'Group.Read.All', 'AdministrativeUnit.Read.All', 'RoleManagement.Read.Directory',
    'DeviceManagementServiceConfig.Read.All',     'DeviceManagementConfiguration.Read.All', 'Directory.Read.All', 'Organization.Read.All',
        'SharePointTenantSettings.Read.All', 'DeviceManagementApps.Read.All', 'Application.Read.All', 'AccessReview.Read.All'
    }
    Write-Host "ALSO Secure by Default - mode: $Mode" -ForegroundColor Cyan
if ($Mode -eq 'Discover') { Write-Host "Read-only discovery. Nothing will be changed." -ForegroundColor Green }

Initialize-Module Microsoft.Graph.Authentication
$needsExo = [bool](($Mode -ne 'Wipe') -and ($Steps | Where-Object { $_ -in 'AuditLog', 'MdoPresets' }))
$needsPurview = [bool]($Steps -contains 'Purview')
$needsSpo = [bool]($needsPurview -and $Mode -ne 'Wipe')
$signInCount = 1 + [int]$needsExo + [int]$needsPurview + [int]$needsSpo
$script:signInNo = 0
function Show-SignIn([string]$Service, [string]$Why, [string]$Access) {
    $script:signInNo++
    Write-Host ''
    Write-Host "SIGN-IN $($script:signInNo) of ${signInCount}: $Service" -ForegroundColor Yellow
    Write-Host "  Why    : $Why"
    Write-Host "  Access : $Access"
    Write-Host '  A browser window opens. Sign in with your Global Administrator account.'
}

$graphWhy = if ($Mode -eq 'Wipe') {
    'WIPE mode: the script REMOVES the Conditional Access policies, Intune policies, groups and emergency access accounts that it deployed earlier. You choose per category: all, one by one or none. This sign-in grants the write permissions listed below.'
} elseif ($Mode -eq 'Enforce') {
    'ENFORCE mode: the script will change tenant-wide settings (Entra user settings, consent, authentication methods, break-glass accounts, SharePoint sharing, Intune/Defender connection). You approve every change before it is applied. This sign-in grants the read AND write permissions listed below.'
} else {
    'DISCOVER mode: the script only READS your tenant settings (Entra, Intune, SharePoint, licensing) and compares them with the secure reference. Nothing is changed. This sign-in grants read-only permissions.'
}
Show-SignIn 'Microsoft Graph (Entra ID, Intune, SharePoint settings)' $graphWhy ($graphScopes -join ', ')
Write-Host '  First run only: approve the request for the "Microsoft Graph Command Line Tools" enterprise application ("Consent on behalf of your organization").' -ForegroundColor DarkGray
function Get-BrowserToken([string[]]$Scopes, [bool]$Last = $false, [string]$clientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e', [string]$Resource = 'https://graph.microsoft.com', [string]$Service = 'Microsoft', [string]$Next = '') {
    $port = Get-Random -Minimum 49200 -Maximum 65000
    $redirect = "http://localhost:$port"
    $b64 = { param([byte[]]$b) [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $rand = { param($n) $x = [byte[]]::new($n); $rng.GetBytes($x); & $b64 $x }
    $verifier = & $rand 48
    $challenge = & $b64 ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier)))
    $state = & $rand 16
    $scope = ($Scopes | ForEach-Object { "$Resource/$_" }) -join ' '
    $auth = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?client_id=$clientId&response_type=code&response_mode=query" +
        "&redirect_uri=$([uri]::EscapeDataString($redirect))&scope=$([uri]::EscapeDataString($scope))&state=$state&code_challenge=$challenge&code_challenge_method=S256&prompt=select_account"
    $listeners = @()
    foreach ($ip in [Net.IPAddress]::Loopback, [Net.IPAddress]::IPv6Loopback) {
        try { $l = [Net.Sockets.TcpListener]::new($ip, $port); $l.Start(); $listeners += $l } catch { }
    }
    if (-not $listeners) { throw "Could not listen on localhost port $port for the sign-in response." }
    try {
        Start-Process $auth
        $deadline = (Get-Date).AddMinutes(5); $q = $null
        # Browsers often open empty or favicon connections first; keep listening until the real sign-in response arrives.
        while (-not $q -and (Get-Date) -lt $deadline) {
            $client = $null
            foreach ($l in $listeners) { if ($l.Pending()) { $client = $l.AcceptTcpClient(); break } }
            if (-not $client) { Start-Sleep -Milliseconds 200; continue }
            try {
                $client.ReceiveTimeout = 3000
                $stream = $client.GetStream(); $buf = [byte[]]::new(8192); $n = 0
                try { $n = $stream.Read($buf, 0, $buf.Length) } catch { }
                $line = if ($n -gt 0) { ([Text.Encoding]::ASCII.GetString($buf, 0, $n) -split "`r?`n")[0] } else { '' }
                $parts = $line -split ' '
                $cand = $null
                if ($parts.Count -gt 1 -and $parts[1].Contains('?')) { $cand = [Web.HttpUtility]::ParseQueryString($parts[1].Split('?', 2)[1]) }
                if ($cand -and ($cand['code'] -or $cand['error'])) {
                    $q = $cand
                    $ok = [bool]$q['code']
                    $msg = if (-not $ok) { "Sign-in to $Service failed. Return to PowerShell for details." } elseif ($Next) { "Signed in to <b>$Service</b> (sign-in $($script:signInNo) of $signInCount).<br>You can close this tab. Next: <b>$Next</b>. A new sign-in window opens in a few seconds (if you are already signed in with that service it may continue without a window)." } else { "Signed in to <b>$Service</b> (sign-in $($script:signInNo) of $signInCount).<br>This was the <b>last</b> sign-in. You can close this tab, return to the PowerShell window and wait while the report is generated." }
                    $body = [Text.Encoding]::UTF8.GetBytes("<html><head><title>ALSO Secure by Default</title></head><body style='font-family:Segoe UI;margin:3em'><h2>ALSO Secure by Default</h2><p>$msg</p></body></html>")
                    $hdr = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/html; charset=utf-8`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n")
                    $stream.Write($hdr, 0, $hdr.Length); $stream.Write($body, 0, $body.Length); $stream.Flush()
                }
                elseif ($n -gt 0) {
                    $hdr = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 404 Not Found`r`nContent-Length: 0`r`nConnection: close`r`n`r`n")
                    $stream.Write($hdr, 0, $hdr.Length); $stream.Flush()
                }
            }
            catch { }
            finally { $client.Close() }
        }
        if (-not $q) { throw 'Timed out waiting for browser sign-in (5 minutes).' }
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
    $nextName = if ($needsExo) { 'Exchange Online' } elseif ($needsPurview) { 'Microsoft Purview' } else { '' }
    $token = Get-BrowserToken $graphScopes $false '14d82eec-204b-4c2f-b7e8-296a70dab67e' 'https://graph.microsoft.com' 'Microsoft Graph (Entra ID, Intune, SharePoint settings)' $nextName
    Connect-MgGraph -AccessToken (ConvertTo-SecureString $token -AsPlainText -Force) -NoWelcome -ErrorAction Stop
}
catch { throw "Microsoft Graph sign-in failed: $($_.Exception.Message)" }
Write-Host '  Signed in to Microsoft Graph.' -ForegroundColor Green
$gaRole = '62e90394-69f5-4237-9190-012177145e10'
$myRoles = (Graph GET 'https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole?$select=roleTemplateId').value.roleTemplateId
if ($gaRole -notin $myRoles) {
    $msg = 'The signed-in account is not an active Global Administrator. All steps require Global Administrator.'
    if ($Mode -ne 'Discover') { throw $msg }
    Write-Warning "$msg Discovery results may be incomplete."
}
$org = (Graph GET 'https://graph.microsoft.com/v1.0/organization').value[0]
$me = Graph GET 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName'
$script:MeId = $me.id; $script:MeUpn = $me.userPrincipalName
$initialDomain = ($org.verifiedDomains | Where-Object { $_.isInitial }).name
Write-Host "Tenant: $($org.displayName) ($($org.id)), initial domain: $initialDomain"
if (-not $SharePointAdminUrl) { $SharePointAdminUrl = "https://$($initialDomain.Split('.')[0])-admin.sharepoint.com" }

if ($needsExo) {
    Show-SignIn 'Exchange Online / Security & Compliance' $(if ($Mode -eq 'Enforce') { 'ENFORCE mode: turns on the unified audit log and enables Defender for Office 365 preset protection rules, after you approve each change.' } else { 'DISCOVER mode: only READS whether the unified audit log is on and whether Defender for Office 365 preset protection rules are enabled. Nothing is changed.' }) 'Exchange Online administration (Global Administrator role)'
    Write-Host '  Loading the Exchange module...' -ForegroundColor DarkGray
    Initialize-Module ExchangeOnlineManagement
    $exOk = $false
    try {
        $exTok = Get-BrowserToken @('.default') (-not $needsPurview) 'fb78d390-0c51-40cd-8e17-fdbfab77341b' 'https://outlook.office365.com' 'Exchange Online' $(if ($needsPurview) { 'Microsoft Purview' } else { '' })
    }
    catch { $exTok = $null; Write-Host "  Direct sign-in was not accepted ($($_.Exception.Message)). Microsoft's own sign-in window will be used instead." -ForegroundColor DarkGray }
}
if ($needsPurview) {
    Show-SignIn 'Microsoft Purview (Security & Compliance)' $(if ($Mode -eq 'Wipe') { 'WIPE mode: finds the ALSO Purview DLP policies, label policy, retention policy and sensitivity labels in your tenant and removes the ones you choose.' } elseif ($Mode -eq 'Enforce') { 'ENFORCE mode: reads your sensitivity labels, label policy, DLP and retention policies, compares them with the ALSO Purview baseline and, after you approve, creates or updates the baseline items (DLP policies start in simulation mode).' } else { 'DISCOVER mode: only READS sensitivity labels, label policies, DLP and retention policies. Nothing is changed.' }) 'Security & Compliance administration (Global Administrator role)'
    Initialize-Module ExchangeOnlineManagement
    $ippsOk = $false
    try {
        $ippsTok = Get-BrowserToken @('.default') $false 'fb78d390-0c51-40cd-8e17-fdbfab77341b' 'https://ps.compliance.protection.outlook.com'         'Microsoft Purview' $(if ($needsSpo) { 'SharePoint admin center' } else { '' })
    }
    catch { $ippsTok = $null; Write-Host "  Direct sign-in was not accepted ($($_.Exception.Message)). Microsoft's own sign-in window will be used instead." -ForegroundColor DarkGray }
}
$script:SpoOk = $false
$script:SpoToken = $null
if ($needsSpo) {
    Show-SignIn 'SharePoint admin center' $(if ($Mode -eq 'Enforce') { 'ENFORCE mode: reads and, after you approve, turns on sensitivity label support for SharePoint, OneDrive and PDF files (a tenant setting that belongs to the Purview baseline).' } else { 'DISCOVER mode: only READS whether sensitivity label support is on for SharePoint, OneDrive and PDF files. Nothing is changed.' }) 'SharePoint tenant administration (Global Administrator role)'
    try {
        $script:SpoToken = Get-BrowserToken @('.default') $true '9bc3ab49-b65d-410a-85ad-de819febfddc' $SharePointAdminUrl 'SharePoint admin center' ''
        $script:SpoOk = $true; $script:SpoMode = 'csom'
        Write-Host '  Signed in to SharePoint admin center.' -ForegroundColor Green
    }
    catch {
        Write-Host '  Direct sign-in was not accepted. Using Microsoft''s own SharePoint sign-in window instead.' -ForegroundColor DarkGray
        try {
            Initialize-Module Microsoft.Online.SharePoint.PowerShell
            Connect-SPOService -Url $SharePointAdminUrl -ErrorAction Stop
            $script:SpoOk = $true; $script:SpoMode = 'module'
            Write-Host '  Signed in to SharePoint admin center.' -ForegroundColor Green
        }
        catch { Write-Host "  SharePoint sign-in failed ($($_.Exception.Message)). The SharePoint label setting will be a manual step." -ForegroundColor Yellow }
    }
}
$script:ExoConnected = $false
function Connect-ExoNow {
    if ($script:ExoConnected) { return }
    $exOk = $false
    if ($exTok) {
        try { Write-Host '  Connecting to Exchange Online (about 10-20 seconds)...' -ForegroundColor DarkGray; Connect-ExchangeOnline -AccessToken $exTok -Organization $initialDomain -ShowBanner:$false -ErrorAction Stop; $exOk = $true }
        catch { Write-Host "  Direct connection was not accepted ($($_.Exception.Message)). Using Microsoft's own sign-in window instead." -ForegroundColor DarkGray }
    }
    if (-not $exOk) {
        try { Connect-ExchangeOnline -ShowBanner:$false -DisableWAM -ErrorAction Stop }
        catch { throw "Exchange Online sign-in failed: $($_.Exception.Message)" }
    }
    $script:ExoConnected = $true
    Write-Host '  Connected to Exchange Online.' -ForegroundColor Green
}
$exoNeededNow = [bool]($needsExo -and ($Steps -contains 'MdoPresets' -or -not $exTok))
if ($exoNeededNow -or $needsPurview) {
    Write-Host ''
    Write-Host 'All sign-ins are done. Connecting to the Microsoft services now (about 10-20 seconds)...' -ForegroundColor Cyan
}
if ($exoNeededNow) { Connect-ExoNow }
if ($needsPurview) {
    $ippsOk = $false
    if ($ippsTok) {
        try { Write-Host '  Connecting to Purview...' -ForegroundColor DarkGray; Connect-IPPSSession -AccessToken $ippsTok -Organization $initialDomain -ShowBanner:$false -ErrorAction Stop; $ippsOk = $true; $script:IppsTok = $ippsTok; $script:IppsOrg = $initialDomain }
        catch { Write-Host "  Direct connection was not accepted ($($_.Exception.Message)). Using Microsoft's own sign-in window instead." -ForegroundColor DarkGray }
    }
    if (-not $ippsOk) { try { Connect-IPPSSession -ShowBanner:$false -DisableWAM -ErrorAction Stop }
    catch {
        if ($_.Exception.Message -match 'parameter') { try { Connect-IPPSSession -ShowBanner:$false -ErrorAction Stop } catch { throw "Purview sign-in failed: $($_.Exception.Message)" } }
        else { throw "Purview sign-in failed: $($_.Exception.Message)" }
    } }
    Write-Host '  Connected to Microsoft Purview.' -ForegroundColor Green
}
function Invoke-SpoCsom([string]$Actions, [string]$Paths) {
    $xml = "<Request AddExpandoFieldTypeSuffix=`"true`" SchemaVersion=`"15.0.0.0`" LibraryVersion=`"16.0.0.0`" ApplicationName=`"ALSO`" xmlns=`"http://schemas.microsoft.com/sharepoint/clientquery/2009`"><Actions>$Actions</Actions><ObjectPaths>$Paths</ObjectPaths></Request>"
    $resp = Invoke-RestMethod -Method Post -Uri "$SharePointAdminUrl/_vti_bin/client.svc/ProcessQuery" -Headers @{ Authorization = "Bearer $($script:SpoToken)" } -ContentType 'text/xml' -Body $xml -TimeoutSec 30 -ErrorAction Stop
    $err = @($resp) | Where-Object { $_.ErrorInfo } | Select-Object -First 1
    if ($err) { throw $err.ErrorInfo.ErrorMessage }
    $resp
}
$spoTenantPath = '<Constructor Id="1" TypeId="{268004ae-ef6b-4e9b-8425-127220d84719}" />'
function Get-SpoTenantCsom {
    if ($script:SpoMode -eq 'module') { return (Get-SPOTenant -ErrorAction Stop) }
    $r = Invoke-SpoCsom '<ObjectPath Id="2" ObjectPathId="1" /><Query Id="3" ObjectPathId="1"><Query SelectAllProperties="true"><Properties /></Query></Query>' $spoTenantPath
    @($r) | Where-Object { $_ -and $_.PSObject.Properties['EnableAIPIntegration'] } | Select-Object -First 1
}
function Set-SpoTenantCsom([string]$Name) {
    if ($script:SpoMode -eq 'module') {
        if ($Name -eq 'EnableSensitivityLabelforPDF') { Set-SPOTenant -EnableSensitivityLabelforPDF $true -ErrorAction Stop } else { Set-SPOTenant -EnableAIPIntegration $true -ErrorAction Stop }
        return
    }
    [void](Invoke-SpoCsom "<ObjectPath Id=`"2`" ObjectPathId=`"1`" /><SetProperty Id=`"3`" ObjectPathId=`"1`" Name=`"$Name`"><Parameter Type=`"Boolean`">true</Parameter></SetProperty>" $spoTenantPath)
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

function Invoke-ExoRest([string]$Cmdlet, [hashtable]$Params = @{}) {
    if (-not $script:exTok) { throw 'No Exchange token available.' }
    $body = @{ CmdletInput = @{ CmdletName = $Cmdlet; Parameters = $Params } } | ConvertTo-Json -Depth 6
    $r = Invoke-RestMethod -Method Post -Uri "https://outlook.office365.com/adminapi/beta/$($org.id)/InvokeCommand" -Headers @{ Authorization = "Bearer $($script:exTok)"; 'Content-Type' = 'application/json'; 'X-AnchorMailbox' = "UPN:$($script:MeUpn)" } -Body $body -TimeoutSec 60 -ErrorAction Stop
    @($r.value)
}

function Step-AuditLog {
    Write-Step 'Unified audit log' 'Required for investigations, Defender and Purview.'
    Write-Host '   ...reading the audit log setting from Exchange' -ForegroundColor DarkGray
    $cfg = $null
    try { $cfg = Invoke-ExoRest 'Get-AdminAuditLogConfig' | Select-Object -First 1 } catch { Write-Host "   Direct read did not work ($($_.Exception.Message)); using the Exchange module." -ForegroundColor DarkGray }
    if (-not $cfg) { Connect-ExoNow; $cfg = Get-AdminAuditLogConfig }
    Compare-Setting 'AuditLog' 'UnifiedAuditLogIngestionEnabled' $cfg.UnifiedAuditLogIngestionEnabled 'True' {
        try { try { [void](Invoke-ExoRest 'Set-AdminAuditLogConfig' @{ UnifiedAuditLogIngestionEnabled = $true }) } catch { if ("$($_.Exception.Message)" -match 'Enable-OrganizationCustomization') { throw }; Connect-ExoNow; Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true -ErrorAction Stop } }
        catch {
            if ("$($_.Exception.Message)" -notmatch 'Enable-OrganizationCustomization') { throw }
            Write-Host '   Exchange needs "organization customization" turned on first. Doing that now (can take a minute)...' -ForegroundColor DarkGray
            Connect-ExoNow; Enable-OrganizationCustomization -ErrorAction Stop
            $done = $false
            foreach ($try in 1..6) {
                try { Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true -ErrorAction Stop; $done = $true; break }
                catch { Start-Sleep -Seconds 10 }
            }
            if (-not $done) { throw 'Organization customization is still being enabled. Run the script again in a few minutes.' }
        }
        $chk = $null; try { $chk = Invoke-ExoRest 'Get-AdminAuditLogConfig' | Select-Object -First 1 } catch { Connect-ExoNow; $chk = Get-AdminAuditLogConfig }; if (-not $chk.UnifiedAuditLogIngestionEnabled) { throw 'The setting was sent but the audit log still reports Off. It can take up to an hour to show On.' }
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
        $adminWhy = 'When this is Yes, people who are not administrators cannot browse the Microsoft Entra admin center (entra.microsoft.com or the Azure portal) to look up users, groups and apps. Group and app owners also cannot manage what they own there. It reduces what an attacker can learn from a compromised normal account.'
        $adminNow = if ("$($u.restrictNonAdminAccess)" -eq 'true') { 'Yes' } else { 'No' }
        Compare-Setting 'UserSettings' 'Restrict access to Microsoft Entra admin center' $adminNow $ref.restrictAdminCenter {
            $want = if ($ref.restrictAdminCenter -eq 'Yes') { 'true' } else { 'false' }
            Graph PATCH $ux @{ restrictNonAdminAccess = $want } | Out-Null
            $chk = Graph GET $ux
            if ("$($chk.restrictNonAdminAccess)" -ne $want) { throw 'Microsoft accepted the request but the setting did not change. Turn it on in the Entra admin center (Entra ID > Users > User settings > Administration center).' }
        } $link $adminWhy
    }
    catch { Add-Result 'UserSettings' 'Restrict access to Microsoft Entra admin center' "Could not be read or set: $($_.Exception.Message)" $ref.restrictAdminCenter Manual $link 'Microsoft only allows this setting to be changed by a signed-in Global Administrator, and the request was refused. Turn it on manually: Entra ID > Users > User settings > Administration center > Restrict access to Microsoft Entra admin center = Yes.' }
    Add-Result 'UserSettings' 'Allow users to connect work or school account with LinkedIn' 'Cannot be read automatically (no Microsoft API)' "$($ref.linkedIn) - business/privacy decision" Manual $link
    Add-Result 'UserSettings' 'Show keep user signed in' 'Cannot be read automatically (no Microsoft API)' $ref.showKeepSignedIn Manual 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/CompanyBrandingMenuBlade/~/CompanyBranding'
}

function Select-Reviewers {
    $ids = @($AdminConsentReviewerIds | Where-Object { $_ })
    if ($ids.Count) { return $ids }
    if (-not $script:MeId) { $meNow = Graph GET 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName'; $script:MeId = $meNow.id; $script:MeUpn = $meNow.userPrincipalName }
    if ($Force) { return @($script:MeId) }
    Write-Host ''
    Write-Host '   Who should review admin consent requests? Reviewers receive each request and approve or deny it.' -ForegroundColor Yellow
    Write-Host "     [1] The account running this script ($($script:MeUpn))"
    Write-Host '     [2] Another account (you type the user name)'
    Write-Host '     [3] Both'
    $out = @()
    while (-not $out.Count) {
        $c = Read-Host '   Choose 1, 2 or 3 (default 1)'
        if (-not $c) { $c = '1' }
        if ($c -in '1', '3') { $out += $script:MeId }
        if ($c -in '2', '3') {
            $upn = Read-Host '   User name (UPN, for example anna@contoso.com) of the reviewer'
            try { $u = Graph GET "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($upn.Trim()))?`$select=id,userPrincipalName"; if ($u.id) { $out += $u.id; Write-Host "   Added reviewer $($u.userPrincipalName)" -ForegroundColor DarkGray } }
            catch { Write-Host "   That user was not found ($($_.Exception.Message))." -ForegroundColor Yellow }
        }
        if (-not $out.Count) { Write-Host '   Please try again.' -ForegroundColor Yellow }
    }
    $out | Select-Object -Unique
}

function Step-Consent {
    Write-Step 'User consent & admin consent workflow' 'Limit OAuth consent phishing.'
    $ref = $script:Reference.consent
    $uri = 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
    $p = Graph GET $uri
    $assigned = @($p.defaultUserRolePermissions.permissionGrantPoliciesAssigned)
    $low = $ref.userConsentPolicy
    $consentName = {
        param($list)
        $list = @($list)
        if (-not $list.Count) { 'Do not allow user consent' }
        elseif ($list | Where-Object { $_ -match 'legacy' }) { 'Allow user consent for all apps (least secure)' }
        elseif ($list | Where-Object { $_ -match 'default-low' }) { 'Allow user consent for verified publishers, low-impact permissions only' }
        else { 'Allow user consent with a custom or Microsoft-managed policy' }
    }
    $consentNow = & $consentName $assigned
    $consentWant = & $consentName @($low)
    $consentWhy = 'When users can consent to apps on their own, an attacker can trick them into granting a malicious app access to their mail and files (consent phishing). Limiting consent to apps from verified publishers and low-impact permissions keeps normal use working while blocking the risky cases. Anything beyond that goes through an admin.'
    Compare-Setting 'Consent' 'User consent for apps: only verified publishers and low-impact permissions' $consentNow $consentWant {
        $keep = @($assigned | Where-Object { $_ -notmatch '^ManagePermissionGrantsForSelf\.' })
        Graph PATCH $uri @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @($low) + $keep } } | Out-Null
        $again = @((Graph GET $uri).defaultUserRolePermissions.permissionGrantPoliciesAssigned)
        if ($low -notin $again) { throw 'Microsoft accepted the request but the user consent setting did not change. Set it in the Entra admin center: Enterprise apps > Consent and permissions > User consent settings.' }
    } 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/UserSettings' $consentWhy
    $wUri = 'https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy'
    $w = Graph GET $wUri
    $revCount = @($w.reviewers).Count
    $wfOn = ($w.isEnabled -eq $true) -and $revCount -gt 0
    $wfNow = if ($wfOn) { "Yes ($revCount reviewer(s))" } elseif ($w.isEnabled -eq $true) { 'No (switched on but has no reviewers)' } else { 'No' }
    $wfWhy = 'The admin consent workflow lets users ask an administrator to approve an app they cannot consent to themselves, instead of being stuck or looking for a workaround. It needs at least one reviewer. You choose who the reviewers are.'
    Compare-Setting 'Consent' 'Admin consent request workflow enabled' $wfNow 'Yes' {
        $revIds = @(Select-Reviewers)
        $reviewerList = @(foreach ($rid in $revIds) { @{ query = "/users/$rid"; queryType = 'MicrosoftGraph' } })
        Graph PUT $wUri @{
            isEnabled = $true; notifyReviewers = $true; remindersEnabled = $true; requestDurationInDays = $ref.requestDurationInDays
            reviewers = $reviewerList
        } | Out-Null
        $chk = Graph GET $wUri
        if (-not ($chk.isEnabled -eq $true -and @($chk.reviewers).Count -gt 0)) { throw 'Microsoft accepted the request but the workflow is still off. Turn it on in the Entra admin center: Enterprise apps > Consent and permissions > Admin consent settings.' }
    } 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/AdminConsentSettings' $wfWhy
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
                    accountEnabled = $true; displayName = $n; mailNickname = $n; userPrincipalName = $upn; department = 'ALSO Secure by Default'
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
            $script:bgG = Graph POST 'https://graph.microsoft.com/v1.0/groups' @{ displayName = $BreakGlassGroupName; mailNickname = ($BreakGlassGroupName -replace '\W', ''); mailEnabled = $false; securityEnabled = $true; description = 'Protected service accounts' }
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
            $script:bgAu = Graph POST 'https://graph.microsoft.com/v1.0/directory/administrativeUnits' @{ displayName = $BreakGlassAuName; description = 'Protects critical access objects'; isMemberManagementRestricted = $true }
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
    if ($au) {
        Invoke-Part 'BreakGlass' 'Administrator of the administrative unit' {
            $nm = "You ($script:MeUpn) are Groups Administrator and User Administrator of $BreakGlassAuName"
            $roleLink = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AdministrativeUnitsMenuBlade/~/AdminUnits"
            $roleWhy = 'Objects inside a restricted management unit can only be changed or deleted by administrators assigned to that unit, even Global Administrators cannot. The account that runs this script is added as Groups Administrator and User Administrator of the unit so that it can manage (and later remove) the protected group and accounts.'
            $haveAll = @((Graph GET "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$($au.id)/scopedRoleMembers").value | Where-Object { $_.roleMemberInfo.id -eq $script:MeId -and $_.roleId -in 'fdd7a751-b60b-444a-984c-02652fe8fa1c', 'fe930be7-5e62-47db-91af-98c3a49a38b1' }).Count -ge 2
            if ($haveAll) { Add-Result 'BreakGlass' $nm 'Yes' 'Yes' Compliant $roleLink $roleWhy }
            elseif (Confirm-Change "Make $script:MeUpn Groups Administrator and User Administrator of $BreakGlassAuName") {
                [void](Grant-AuAdmin $au.id)
                Add-Result 'BreakGlass' $nm 'No' 'Assigned' Fixed $roleLink $roleWhy
            }
            else { Add-Result 'BreakGlass' $nm 'No' 'Yes' Drift $roleLink $roleWhy }
        }
    }
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
    $drift = @($mine | Where-Object { $_.Status -eq 'Drift' })
    $bad = $drift.Count
    $existFail = @($drift | Where-Object { $_.Group -like '2. Existing account*' })
    $alsoMissing = @($drift | Where-Object { $_.Group -match '^[3-6]\.' })
    $lines = @()
    if ($found.Count) {
        $lines += "Existing accounts: found $($found.Count) ($(($found | ForEach-Object { $_.userPrincipalName }) -join ', ')). $(if ($existFail.Count) { "$($existFail.Count) of their checks fail: $(($existFail | ForEach-Object { $_.Setting }) -join '; ')." } else { 'All of their checks pass.' })"
    }
    else { $lines += 'Existing accounts: none found by name. This only means none use words like emergency, break or glass. Check Entra ID before creating new ones.' }
    $madeNow = @($mine | Where-Object { $_.Status -eq 'Fixed' }).Count
    if ($alsoMissing.Count) { $lines += "ALSO accounts (svr_ea_01 / svr_ea_02): $($alsoMissing.Count) item(s) missing: $(($alsoMissing | ForEach-Object { $_.Setting }) -join '; ')." }
    elseif ($found.Count -and -not (@($mine | Where-Object { $_.Group -like '3.*' -and $_.Status -in 'Compliant', 'Fixed' }).Count)) { $lines += 'ALSO accounts (svr_ea_01 / svr_ea_02): not created. Optional, because your existing accounts are being used.' }
    else { $lines += "ALSO accounts (svr_ea_01 / svr_ea_02): in place$(if ($madeNow) { " ($madeNow item(s) created or fixed in this run)" })." }
    $lines += 'People still have to do the four items in section 7 (trusted admins on the unit, sign-in alert, Conditional Access exclusion, FIDO2 keys).'
    $outcome = if ($found.Count -and $existFail.Count -eq 0 -and -not $alsoMissing.Count) { 'Ready' } elseif ($found.Count -and $existFail.Count -gt 0 -and $Mode -eq 'Discover') { 'Existing accounts need fixing' } elseif (-not $bad) { 'Ready' } elseif ($Mode -eq 'Discover') { 'Not set up yet' } else { 'Needs action' }
    $verdict = switch ($outcome) {
        'Ready' { 'Emergency access is in place. Only the manual items in section 7 remain.' }
        'Existing accounts need fixing' { 'You already have emergency accounts, but they do not meet every requirement. Fix them, or run Enforce to create the two ALSO accounts.' }
        'Not set up yet' { 'No complete emergency access setup was found. Run Enforce mode to create the two ALSO accounts, their group and the restricted management unit.' }
        default { "$bad item(s) still need to be created or fixed." }
    }
    Set-Group 'Summary'
    Add-Result 'BreakGlass' 'Break-glass readiness' $outcome 'Ready' $(if ($outcome -eq 'Ready') { 'Compliant' } else { 'Drift' }) $link "$verdict $($lines -join ' ') Sections: 1 existing accounts, 2 their checks, 3 to 6 the two ALSO accounts, 7 what a person must do." $BreakGlassPdf $pdf
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

function Set-DeviceRegPolicy([scriptblock]$Edit) {
    $uri = 'https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy'
    $cur = Graph GET $uri
    foreach ($k in @($cur.Keys | Where-Object { $_ -like '@odata.*' })) { $cur.Remove($k) }
    & $Edit $cur
    Graph PUT $uri $cur | Out-Null
}

function Step-Laps {
    Write-Step 'Local admin & LAPS (Entra device settings)' 'Remove standing local admin; enable Entra LAPS.'
    $link = 'https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings'
    $uri = 'https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy'
    $dr = Graph GET $uri
    $lapsDoc = $GuideBase + '#local-admin'
    $lapsText = 'ALSO guide: LAPS via policy templates (Endpoints, step 4)'
    $lapsWhy = 'Entra LAPS lets devices store a unique, rotating local administrator password in Entra ID, so one stolen local password cannot be reused on other devices. This switch only allows the feature. To actually deploy it, create the Windows LAPS policy in Intune (Endpoint security > Account protection) using ALSO''s policy templates and test password recovery - see step 4 under Endpoint management and protection in the ALSO guide.'
    Compare-Setting 'Laps' 'Enable Microsoft Entra Local Administrator Password Solution (LAPS)' (YN $dr.localAdminPassword.isEnabled) 'Yes' { Set-DeviceRegPolicy { param($d) if (-not $d.localAdminPassword) { $d.localAdminPassword = @{} }; $d.localAdminPassword.isEnabled = $true } } $link $lapsWhy $lapsDoc $lapsText
    $regDoc = $GuideBase + '#device-registration'
    $mfaCur = if ("$($dr.multiFactorAuthConfiguration)" -eq 'required') { 'Yes' } else { 'No' }
    Compare-Setting 'Laps' 'Require multifactor authentication to register or join devices (legacy device setting)' $mfaCur 'No' { Set-DeviceRegPolicy { param($d) $d.multiFactorAuthConfiguration = 'notRequired' } } $link 'This old per-tenant switch is replaced by a Conditional Access policy (user action: Register or join devices) that requires MFA. The legacy switch and the Conditional Access policy conflict, so the reference state is No here and MFA is enforced through Conditional Access instead. Deploy that policy from ALSO''s templates - see step 1 under Endpoint management and protection in the ALSO guide.' $regDoc 'ALSO guide: MFA when registering devices (Endpoints, step 1)'
    Compare-Setting 'Laps' 'Global administrators become local admin on Entra-joined devices' (YN $dr.azureADJoin.localAdmins.enableGlobalAdmins) 'No' {
        Set-DeviceRegPolicy { param($d) $d.azureADJoin.localAdmins.enableGlobalAdmins = $false } } $link 'Global administrators should not automatically be local admins on every Entra-joined device. This limits the damage if a global admin account is compromised. Use LAPS for controlled local admin access instead.' $lapsDoc $lapsText
    $ru = @{ '#microsoft.graph.noDeviceRegistrationMembership' = 'None (registering user is not local admin)'
        '#microsoft.graph.allDeviceRegistrationMembership' = 'All registering users'
        '#microsoft.graph.enumeratedDeviceRegistrationMembership' = 'Selected users and groups' }
    $curType = "$($dr.azureADJoin.localAdmins.registeringUsers.'@odata.type')"
    $curRu = if ($ru.ContainsKey($curType)) { $ru[$curType] } else { "Unknown ($curType)" }
    Compare-Setting 'Laps' 'Registering user is added as local administrator on join' $curRu $ru['#microsoft.graph.noDeviceRegistrationMembership'] {
        Set-DeviceRegPolicy { param($d) $d.azureADJoin.localAdmins.registeringUsers = @{ '@odata.type' = '#microsoft.graph.noDeviceRegistrationMembership' } } } $link 'The user who joins a device should not become its local administrator. Set to None so users run as standard users.' $lapsDoc $lapsText
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

function ConvertTo-FlatMap($Node, [string]$Path, [hashtable]$Map) {
    if ($null -eq $Node) { return }
    if ($Node -is [string] -or $Node -is [ValueType]) { $Map[$Path] = "$Node"; return }
    if ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [System.Collections.IDictionary]) {
        $arr = @($Node)
        if (-not @($arr | Where-Object { $_ -isnot [string] -and $_ -isnot [ValueType] }).Count) { $Map[$Path] = (@($arr | ForEach-Object { "$_" } | Sort-Object) -join ', '); return }
        for ($i = 0; $i -lt $arr.Count; $i++) { ConvertTo-FlatMap $arr[$i] "$Path[$i]" $Map }
        return
    }
    $names = if ($Node -is [System.Collections.IDictionary]) { @($Node.Keys) } else { @($Node.PSObject.Properties.Name) }
    foreach ($n in $names) { $v = if ($Node -is [System.Collections.IDictionary]) { $Node[$n] } else { $Node.$n }; ConvertTo-FlatMap $v $(if ($Path) { "$Path > $n" } else { $n }) $Map }
}

function Compare-Fingerprints([string]$Mine, [string]$Ref) {
    $a = @{}; $b = @{}
    if ($Mine) { ConvertTo-FlatMap ($Mine | ConvertFrom-Json) '' $a }
    if ($Ref) { ConvertTo-FlatMap ($Ref | ConvertFrom-Json) '' $b }
    $same = @(); $diff = @(); $missing = @(); $extra = @()
    foreach ($k in ($b.Keys | Sort-Object)) {
        if (-not $a.ContainsKey($k)) { $missing += "$k is not set (ALSO: '$($b[$k])')" }
        elseif ($a[$k] -eq $b[$k]) { $same += "$k = '$($b[$k])'" }
        else { $diff += "$k is '$($a[$k])' (ALSO: '$($b[$k])')" }
    }
    foreach ($k in ($a.Keys | Sort-Object)) { if (-not $b.ContainsKey($k)) { $extra += "$k is '$($a[$k])' (not in ALSO)" } }
    $tot = $same.Count + $diff.Count + $missing.Count + $extra.Count
    [pscustomobject]@{ Percent = $(if ($tot) { [int][Math]::Round(100 * $same.Count / $tot) } else { 0 }); Same = $same; Diff = $diff; Missing = $missing; Extra = $extra }
}

function Format-Comparison($C, [int]$Max = 6) {
    $n = $C.Diff.Count + $C.Missing.Count + $C.Extra.Count
    $l = @("$($C.Percent)% of the settings are the same ($($C.Same.Count) same, $n different)")
    $d = @($C.Diff) + @($C.Missing) + @($C.Extra)
    if ($d.Count) { $l += 'Different:'; $l += @($d | Select-Object -First $Max | ForEach-Object { "- $_" }); if ($d.Count -gt $Max) { $l += "- ...and $($d.Count - $Max) more" } }
    if ($C.Same.Count) { $l += 'Same:'; $l += @($C.Same | Select-Object -First $Max | ForEach-Object { "- $_" }); if ($C.Same.Count -gt $Max) { $l += "- ...and $($C.Same.Count - $Max) more" } }
    $l -join "`n"
}

function Find-SimilarPolicy([string]$Fp, $Candidates, [int]$Min = 50) {
    $best = $null
    foreach ($c in $Candidates) {
        $r = Compare-Fingerprints $c.Fp $Fp
        if ($r.Percent -ge $Min -and (-not $best -or $r.Percent -gt $best.Cmp.Percent)) { $best = [pscustomobject]@{ Name = $c.Name; Cmp = $r } }
    }
    $best
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
            $wfp = Get-CaFingerprint $p.Json $false
            [pscustomobject]@{ P = $p; Name = $nm; ByName = $byName; ByCfg = $byCfg }
        })
    $missing = @($rows | Where-Object { -not $_.ByName -and -not $_.ByCfg })
    $map = @{}
    $ref = @()
    foreach ($r0 in $rows) { foreach ($k in 'includeGroups', 'excludeGroups') { $ref += @($r0.P.Json.conditions.users.$k) } }
    $ref = @($ref | Where-Object { $_ } | Sort-Object -Unique)
    $grpState = @()
    foreach ($g in $grpFiles) {
        if ($g.Json.id -notin $ref) { continue }
        $gn = $g.Json.displayName
        if ($gn -like '*BSAccounts*' -and $bgId) { $map["$($g.Json.id)"] = $bgId; continue }
        $f = $null; try { $f = Find-GroupByName $gn } catch { }
        if ($f) { $map["$($g.Json.id)"] = $f.id }
        $grpState += [pscustomobject]@{ G = $g; Name = $gn; Found = $f }
    }
    $needGrp = @($grpState | Where-Object { -not $_.Found })
    $haveCtx = @{}
    try { foreach ($c0 in @(Get-AllPages 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences')) { $haveCtx["$($c0.id)"] = $true } } catch { }
    $needCtx = @($ctxFiles | Where-Object { -not $haveCtx.ContainsKey("$($_.Json.id)") })

    Set-Group 'Groups and authentication contexts used by the ALSO policies'
    $grpWhy = 'Some ALSO Conditional Access policies include or exclude specific groups (for example admins, service accounts or exclusions). The policies need these groups to exist; they are created empty and you add the members.'
    $ctxWhy = 'Authentication contexts let a policy apply to a sensitive action, for example activating a Tier 0 role. The ALSO policies that refer to them only work when the contexts exist.'
    $doGrp = $false; $doCtx = $false
    if ($needGrp.Count) { $doGrp = Confirm-Change "Create $($needGrp.Count) missing group(s) used by ALSO Conditional Access policies: $(($needGrp | ForEach-Object { $_.Name }) -join ', ')" }
    if ($needCtx.Count) { $doCtx = Confirm-Change "Create $($needCtx.Count) missing authentication context(s): $(($needCtx | ForEach-Object { $_.Json.displayName }) -join ', ')" }
    foreach ($gs in $grpState) {
        if ($gs.Found) { Add-Result 'ConditionalAccess' "Group: $($gs.Name)" 'Exists' 'Exists' Compliant $link $grpWhy $doc $docText; continue }
        if (-not $doGrp) { Add-Result 'ConditionalAccess' "Group: $($gs.Name)" 'Missing' 'Created (empty)' Drift $link $grpWhy $doc $docText; continue }
        try {
            $nick = ($gs.Name -replace '[^A-Za-z0-9]', ''); if ($nick.Length -gt 60) { $nick = $nick.Substring(0, 60) }
            $f = Graph POST 'https://graph.microsoft.com/v1.0/groups' @{ displayName = $gs.Name; description = 'ALSO Conditional Access baseline group'; mailEnabled = $false; securityEnabled = $true; mailNickname = $nick }
            $map["$($gs.G.Json.id)"] = $f.id
            Add-Result 'ConditionalAccess' "Group: $($gs.Name)" 'Missing' 'Created (empty)' Fixed $link $grpWhy $doc $docText
        }
        catch { Add-Result 'ConditionalAccess' "Group: $($gs.Name)" 'Missing' 'Created (empty)' Error $link "Could not create the group: $($_.Exception.Message)" $doc $docText }
    }
    foreach ($c in $ctxFiles) {
        $cn = "Authentication context: $($c.Json.displayName)"
        if ($haveCtx.ContainsKey("$($c.Json.id)")) { Add-Result 'ConditionalAccess' $cn 'Exists' 'Exists' Compliant $link $ctxWhy $doc $docText; continue }
        if (-not $doCtx) { Add-Result 'ConditionalAccess' $cn 'Missing' 'Created' Drift $link $ctxWhy $doc $docText; continue }
        try {
            $ctxBody = @{ id = $c.Json.id; displayName = $c.Json.displayName; description = "$($c.Json.description)"; isAvailable = $true }
            $ctxUri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences'
            try { Graph POST $ctxUri $ctxBody | Out-Null }
            catch {
                $first = $_.Exception.Message
                try { Graph PATCH "$ctxUri/$($c.Json.id)" @{ displayName = $c.Json.displayName; description = "$($c.Json.description)"; isAvailable = $true } | Out-Null }
                catch { throw "$first | retry: $($_.Exception.Message)" }
            }
            Add-Result 'ConditionalAccess' $cn 'Missing' 'Created' Fixed $link $ctxWhy $doc $docText
        }
        catch { Add-Result 'ConditionalAccess' $cn 'Missing' 'Created' Error $link "Could not create it: $($_.Exception.Message)" $doc $docText }
    }

    $selPol = @(Select-Deployment $missing 'ALSO Conditional Access policies (they are imported switched off)' { $_.Name })
    Set-Group 'ALSO baseline policies (one row per policy)'
    if ($skippedE5.Count) { Add-Result 'ConditionalAccess' "ALSO E5 policies not checked ($($skippedE5.Count))" 'Not licensed' 'Requires Entra ID P2 (Microsoft 365 E5, E7 or a security suite)' Skipped $link 'These policies use Entra ID Protection (risk) or Privileged Identity Management features that are only included with Entra ID P2.' $doc $docText }
    foreach ($r in $rows) {
        $nm = $r.Name
        if ($r.ByName) {
            Add-Result 'ConditionalAccess' $nm "Present - $($stateTxt["$($r.ByName.state)"])" 'Present' Compliant $link $why $doc $docText
            continue
        }
        if ($r.ByCfg) { Add-Result 'ConditionalAccess' $nm "Equivalent policy exists: '$($r.ByCfg.displayName)' ($($stateTxt["$($r.ByCfg.state)"]))" 'Present' Info $link "A policy with a different name but the same settings already covers this ALSO policy, so it is not imported again. Consider renaming it to the ALSO name or keep only one of them." $doc $docText; continue }
        if ($selPol -notcontains $r) { Add-Result 'ConditionalAccess' $nm 'Missing' 'Present (switched off)' Drift $link $why $doc $docText; continue }
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
        Add-Result 'ConditionalAccess' "$($e.displayName)" "Existing policy, not part of the ALSO baseline - $($stateTxt["$($e.state)"])" 'Reviewed' Info $link 'This policy already exists in your tenant. It was created by you or someone else and is not changed by this script. Review it and check that it does not conflict with the ALSO baseline.' $doc $docText
    }

    Set-Group 'Duplicate policies'
    $strict = @{}
    foreach ($e in $existing) { $k = Get-CaFingerprint $e $true; if (-not $strict.ContainsKey($k)) { $strict[$k] = @() }; $strict[$k] += $e }
    $dups = @($strict.Values | Where-Object { $_.Count -gt 1 })
    if (-not $dups.Count) { Add-Result 'ConditionalAccess' 'Policies with identical settings' 'None found' 'No duplicates' Compliant $link 'Two policies with the same users, apps and controls do the same job twice and make troubleshooting harder.' $doc $docText }
    $dn = 0
foreach ($d in $dups) { $dn++; Add-Result 'ConditionalAccess' "Duplicate group ${dn}: $($d.Count) policies do the same thing" "Identical settings in:`n$(($d | ForEach-Object { '- ' + $_.displayName }) -join "`n")" 'One policy' Drift $link 'These policies target the same users and apps and require the same controls. Keep one and remove or merge the others, otherwise changes have to be made twice and the result is hard to explain.' $doc $docText }

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
    $known = @()
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
        foreach ($k in $items) { if ($k.ByName) { $known += "$($k.ByName.id)" }; if ($k.ByCfg) { $known += "$($k.ByCfg.id)" } }
        if (-not $items.Count) { continue }
        $miss = @($items | Where-Object { -not $_.ByName -and -not $_.ByCfg })
        $selPol = @(Select-Deployment $miss "missing policies: $($meta[0])" { "$($_.Name) [$($_.Plat)]" })
        $why = 'Policies are created unassigned, so nothing changes on devices yet. Assign each policy to a pilot group, check the results, then widen the scope.'
        foreach ($i in ($items | Sort-Object Name)) {
            $label = "$($i.Name)  [$($i.Plat)]"
            if ($i.ByName) { Add-Result 'IntunePolicies' $label 'Present' 'Present' Compliant $link $why $doc $meta[2]; continue }
            if ($i.ByCfg) { $en = if ($i.ByCfg.displayName) { $i.ByCfg.displayName } else { $i.ByCfg.name }; Add-Result 'IntunePolicies' $label "Equivalent policy exists: '$en'" 'Present' Info $link 'A policy with a different name but the same settings already exists, so this one is not imported again.' $doc $meta[2]; continue }
            if ($selPol -notcontains $i) { Add-Result 'IntunePolicies' $label 'Missing' 'Present (unassigned)' Drift $link $why $doc $meta[2]; continue }
            try { Graph POST $i.Target (ConvertTo-CleanBody $i.Json) | Out-Null; Add-Result 'IntunePolicies' $label 'Missing' 'Imported (unassigned)' Fixed $link $why $doc $meta[2] }
            catch {
                if ($pkg -eq 'defender-onboarding') { Add-Result 'IntunePolicies' $label 'Missing' 'Imported (unassigned)' Manual $link "This Defender onboarding profile could not be imported automatically ($($_.Exception.Message)). It usually needs the Defender for Endpoint connection and your tenant's onboarding file first: finish the Defender connection steps, then import it in Intune." $doc $meta[2] }
                else { Add-Result 'IntunePolicies' $label 'Missing' 'Imported (unassigned)' Error $link "$($_.Exception.Message)" $doc $meta[2] }
            }
        }
    }
    Set-Group 'Your existing Intune policies (already in your tenant)'
    $seen = @{}
    $anyEx = $false
    foreach ($tg in $cache.Keys) {
        foreach ($ex in $cache[$tg]) {
            $id = "$($ex.id)"
            if ($id -in $known -or $seen.ContainsKey($id)) { continue }
            $seen[$id] = $true; $anyEx = $true
            $en = if ($ex.displayName) { $ex.displayName } else { $ex.name }
            $kind = ("$($ex.'@odata.type')" -replace '^#?microsoft\.graph\.', '')
            Add-Result 'IntunePolicies' "$en" "Existing policy$(if ($kind) { " ($kind)" })" 'Reviewed' Info $link 'This policy already exists in your tenant. It is not part of the ALSO baseline and is not changed by this script. Review it and check that it does not conflict with the ALSO policies.' $GuideBase 'ALSO guide: Endpoints'
        }
    }
    if (-not $anyEx) { Add-Result 'IntunePolicies' 'Other Intune policies' 'None found' 'Reviewed' Info $link 'No other policies of these types exist in your tenant yet.' $GuideBase 'ALSO guide: Endpoints' }
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

function Get-PurviewToolkit {
    $root = Join-Path ([IO.Path]::GetTempPath()) 'sbd-packages'
    $dir = Join-Path $root 'purview-toolkit'
    $tmp = Join-Path $root 'purview-extract'
    New-Item -ItemType Directory -Force $root | Out-Null
    foreach ($d in $dir, $tmp) { if (Test-Path $d) { Remove-Item $d -Recurse -Force } }
    $zip = Join-Path $root 'purview-toolkit.zip'
    Invoke-WebRequest -Uri 'https://github.com/CoC-MS/ALSO-Microsoft-Security-Purview/archive/refs/heads/main.zip' -OutFile $zip -UseBasicParsing
    Expand-Archive $zip -DestinationPath $tmp -Force
    Move-Item (Get-ChildItem $tmp -Directory | Select-Object -First 1).FullName $dir
    Remove-Item $tmp -Recurse -Force
    $dir
}

function Get-PvProp($O, [string]$N) {
    if ($null -eq $O) { return $null }
    if ($O -is [System.Collections.IDictionary]) { foreach ($k in $O.Keys) { if ("$k" -ieq $N) { return $O[$k] } }; return $null }
    $p = $O.PSObject.Properties | Where-Object { $_.Name -ieq $N } | Select-Object -First 1
    if ($p) { $p.Value }
}

# Purview stores policy options as text such as "[mandatory, true]".
function Get-PvSetting($O, [string]$Key) {
    foreach ($s in @($O.Settings)) { if ("$s" -match "(?i)^\W*$([regex]::Escape($Key))\s*,\s*([^\]]*?)\s*\]?$") { return $Matches[1] } }
    $null
}

function Step-Purview {
    Write-Step 'Microsoft Purview baseline' 'Reads your existing Purview labels and policies, compares each setting with ALSO''s Purview baseline, and (in Enforce mode) deploys what is missing.'
    $repo = 'https://github.com/CoC-MS/ALSO-Microsoft-Security-Purview'
    $doc = $GuideBase + '#purview-baseline'
    $docText = 'ALSO guide: Purview baseline (Data security and governance, step 1)'
    $tier = (Get-LicenseTier).Tier
    $lbl = 'https://purview.microsoft.com/informationprotection/labels'
    $lpL = 'https://purview.microsoft.com/informationprotection/labelpolicies'
    $dlpL = 'https://purview.microsoft.com/datalossprevention/policies'
    $retL = 'https://purview.microsoft.com/datalifecyclemanagement/policies'
    $modeTxt = { param($p) switch ("$($p.Mode)") { 'Enable' { 'On' } 'TestWithNotifications' { 'Simulation with notifications' } 'TestWithoutNotifications' { 'Simulation' } 'Disable' { 'Off' } default { "$($p.Mode)" } } }
    $yn = { param($v) if ($v) { 'On' } else { 'Off' } }
    $isTrue = { param($v) "$v" -match '^(true|1|yes)$' }

    try { $tk = Get-PurviewToolkit 3>$null; $cfgPath = Join-Path $tk 'Purview\Config\PurviewConfig.psd1'; $config = Import-PowerShellDataFile $cfgPath }
    catch { Add-Result 'Purview' 'ALSO Purview baseline configuration' "Could not be downloaded: $($_.Exception.Message)" 'Downloaded from GitHub' Error $repo 'The script compares your tenant with the baseline file in ALSO''s Purview repository. Check your internet connection and that github.com is reachable.' $doc $docText; return }
    if (-not (Get-Command Get-Label -ErrorAction SilentlyContinue)) {
        Add-Result 'Purview' 'Purview connection' 'Signed in, but the Purview commands are not available' 'Commands such as Get-Label are available' Error 'https://purview.microsoft.com' 'The sign-in worked, but the Security & Compliance commands did not load. Close PowerShell, open a new PowerShell 7 window as administrator, and run the script again. If it persists, update the ExchangeOnlineManagement module (Update-Module ExchangeOnlineManagement).' $doc $docText
        return
    }

    $spoLink = "$SharePointAdminUrl/_layouts/15/online/AdminHome.aspx#/settings"
    $check = {
        $rows = [System.Collections.Generic.List[object]]::new()
        $addRow = { param($Grp, $Setting, $Cur, $Exp, $Status, $Detail, $Lnk, $Deploy)
            $rows.Add([pscustomobject]@{ Group = $Grp; Setting = $Setting; Current = $Cur; Expected = $Exp; Status = $Status; Detail = $Detail; Link = $Lnk; Deployable = [bool]$Deploy }) }
        $emit = { param($Grp, $Setting, $Exists, $Diffs, $Why, $Lnk, $Equiv)
            if ($Exists -and -not $Diffs.Count) { & $addRow $Grp $Setting 'Matches the ALSO baseline' 'Matches the ALSO baseline' Compliant $Why $Lnk $false }
            elseif ($Exists) { & $addRow $Grp $Setting 'Exists, but differs from the baseline' 'Matches the ALSO baseline' Drift "$Why What differs: $($Diffs -join '; '). Enforce mode can update it to the baseline." $Lnk $true }
            elseif ($Equiv) { & $addRow $Grp $Setting "Not deployed. Your policy '$Equiv' already covers the same data" 'Matches the ALSO baseline' Info "$Why Deploying the ALSO policy as well would warn users twice, so it is not needed unless you want ALSO's exact settings." $Lnk $false }
            else { & $addRow $Grp $Setting 'Missing' 'Matches the ALSO baseline' Drift "$Why This item is not in your tenant yet. Enforce mode can deploy it." $Lnk $true }
        }
        $g1 = 'Tenant settings'
        $WarningPreference = 'SilentlyContinue'
        $au = $script:Results | Where-Object { $_.Step -eq 'AuditLog' } | Select-Object -Last 1
        $auLink = 'https://purview.microsoft.com/audit/auditsearch'
        $auWhy = 'Purview and Defender rely on the audit log for investigations, DLP reports and Copilot logging. It is checked and turned on by the "Unified audit log" step, which reads it from Exchange Online.'
        if ($au) {
            $auOn = $au.Status -in 'Compliant', 'Fixed'
            & $addRow $g1 'Unified audit log' $(if ($auOn) { 'On' } else { 'Off' }) 'On' $(if ($auOn) { 'Compliant' } else { 'Drift' }) $auWhy $auLink $false
        }
        else { & $addRow $g1 'Unified audit log' 'Checked by the Unified audit log step' 'On' Info 'Add the AuditLog step to read and enable it.' $auLink $false }        $spoT = $null
        if ($script:SpoOk) { try { $spoT = Get-SpoTenantCsom } catch { $spoT = $null; Write-Host "  SharePoint label settings could not be read: $($_.Exception.Message)" -ForegroundColor DarkGray } }
        if ($spoT) {
            & $addRow $g1 'Sensitivity labels in SharePoint and OneDrive' (& $yn ($spoT.EnableAIPIntegration -eq $true)) 'On' $(if ($spoT.EnableAIPIntegration -eq $true) { 'Compliant' } else { 'Drift' }) 'Lets SharePoint and OneDrive read and apply sensitivity labels (and encrypt labelled files). Without it, labels do not work on files in the cloud.' $spoLink $false
            if ($spoT.PSObject.Properties['EnableSensitivityLabelforPDF']) {
                & $addRow $g1 'Sensitivity labels for PDF files' (& $yn ($spoT.EnableSensitivityLabelforPDF -eq $true)) 'On' $(if ($spoT.EnableSensitivityLabelforPDF -eq $true) { 'Compliant' } else { 'Drift' }) 'Lets labels be applied to, and read from, PDF files in SharePoint and OneDrive.' $spoLink $false
            }
            else { & $addRow $g1 'Sensitivity labels for PDF files' 'Built in' 'On' Compliant 'Microsoft now supports labels on PDF files by default, so there is no setting to change.' $spoLink $false }
        }
        else { & $addRow $g1 'Sensitivity labels in SharePoint, OneDrive and for PDF files' 'Cannot be read automatically' 'On' Manual 'Open the SharePoint admin center > Settings > Sensitivity labels and confirm that label support (and PDF support) is on. New tenants have it on already.' $spoLink $false }
        try {
            $gu = @(Get-AllPages 'https://graph.microsoft.com/v1.0/groupSettings') | Where-Object { $_.displayName -eq 'Group.Unified' } | Select-Object -First 1
            $mip = if ($gu) { "$((@($gu.values) | Where-Object { $_.name -eq 'EnableMIPLabels' }).value)" } else { '' }
            $mipOn = $mip -match '^true$'
            & $addRow $g1 'Sensitivity labels for Microsoft 365 groups, Teams and sites' $(if ($mipOn) { 'On' } else { 'Off' }) 'On' $(if ($mipOn) { 'Compliant' } else { 'Drift' }) 'Lets you protect whole Teams, groups and SharePoint sites with a label (privacy, external sharing, unmanaged device access). Without this setting those container labels are not offered to users.' 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/General' $false
        }
        catch { & $addRow $g1 'Sensitivity labels for Microsoft 365 groups, Teams and sites' "Could not be read: $($_.Exception.Message)" 'On' Manual 'Check in the Entra admin center under Groups > General that sensitivity labels for groups are enabled.' 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/General' $false }

        $g2 = 'ALSO baseline (suggested): Sensitivity labels'; $g2x = 'Your existing tenant: Sensitivity labels'
        $labels = @()
        Write-Host '   ...reading sensitivity labels' -ForegroundColor DarkGray; try { $labels = @(Invoke-Timed 'Get-Label -ErrorAction Stop') } catch { & $addRow $g2 'Sensitivity labels' "Could not be read: $($_.Exception.Message)" 'Readable' Error 'Make sure the signed-in account is Global Administrator or Compliance Administrator.' $lbl $false }
        $find = { param($c, $parent)
            $labels | Where-Object { ($_.Name -eq $c.Name -or $_.DisplayName -eq $c.DisplayName) -and $(if ($parent) { "$($_.ParentId)" -eq "$($parent.Guid)" } else { -not $_.ParentId }) } | Select-Object -First 1 }
        $resolved = @{}
        $baseNames = @()
        if ($labels.Count -or $true) {
            foreach ($c in $config.Labels) {
                $p = & $find $c $null; $resolved[$c.Name] = $p; $baseNames += $c.DisplayName
                $d = @(); if ($p -and $null -ne $p.EncryptionEnabled -and [bool]$p.EncryptionEnabled -ne [bool]$c.Encrypt) { $d += "encryption is $(& $yn $p.EncryptionEnabled), baseline expects $(& $yn $c.Encrypt)" }
                & $emit $g2 "Label: $($c.DisplayName)" ([bool]$p) $d 'Sensitivity labels classify documents and e-mail so protection follows the data.' $lbl $null
                foreach ($s in @($c.SubLabels | Where-Object { $_ })) {
                    $sl = & $find $s $p; $resolved[$s.Name] = $sl
                    $d = @(); if ($sl -and $null -ne $sl.EncryptionEnabled -and [bool]$sl.EncryptionEnabled -ne [bool]$s.Encrypt) { $d += "encryption is $(& $yn $sl.EncryptionEnabled), baseline expects $(& $yn $s.Encrypt)" }
                    & $emit $g2 "Sub-label: $($c.DisplayName) > $($s.DisplayName)" ([bool]$sl) $d 'Sub-labels give the same classification different protection, for example encryption for specific people.' $lbl $null
                }
            }
            foreach ($x in @($labels | Where-Object { -not $_.ParentId -and $_.DisplayName -notin $baseNames })) {
                $sim = @($config.Labels | Where-Object { $x.DisplayName -like "*$($_.DisplayName)*" -or $_.DisplayName -like "*$($x.DisplayName)*" } | ForEach-Object { $_.DisplayName })
                $subN = @($labels | Where-Object { "$($_.ParentId)" -eq "$($x.Guid)" }).Count
                $wasEnc = if ($null -ne $x.EncryptionEnabled) { "Encryption: $(& $yn $x.EncryptionEnabled)." } else { '' }
                if ($sim.Count) { & $addRow $g2x "Label: $($x.DisplayName)" "Possible duplicate of the ALSO label:`n$(($sim | ForEach-Object { '- ' + $_ }) -join "`n")" 'Reviewed by you' Manual "This label exists in your tenant but is not the ALSO label. $wasEnc It has $subN sub-label(s). Two label sets with similar names confuse users: decide whether to keep yours, rename it or retire it before deploying the ALSO labels." $lbl $false }
                else { & $addRow $g2x "Label: $($x.DisplayName)" 'Exists, not part of the ALSO baseline' 'Reviewed by you' Info "Your own label. $wasEnc It has $subN sub-label(s). It is never changed by this script." $lbl $false }
            }
        }

        $g3 = 'ALSO baseline (suggested): Label policy'; $g3x = 'Your existing tenant: Label policies'
        try {
            Write-Host '   ...reading label policies' -ForegroundColor DarkGray; $lps = @(Invoke-Timed 'Get-LabelPolicy -ErrorAction Stop')
            $c = $config.LabelPolicy
            $lp = $lps | Where-Object { $_.Name -eq $c.Name } | Select-Object -First 1
            $d = @()
            if ($lp) {
                $want = @($c.PublishedLabels | ForEach-Object { $resolved[$_] })
                $have = @($lp.Labels | ForEach-Object { "$_" })
                $notPub = @($want | Where-Object { $_ -and -not ($have -contains "$($_.Guid)" -or $have -contains "$($_.Name)" -or $have -contains "$($_.DisplayName)") })
                if ($notPub.Count) { $d += "labels not published: $(($notPub | ForEach-Object { $_.DisplayName }) -join ', ')" }
                $m = Get-PvSetting $lp 'mandatory'; if ($null -ne $m -and (& $isTrue $m) -ne [bool]$c.MandatoryLabelling) { $d += "required labeling is $(& $yn (& $isTrue $m)), baseline expects $(& $yn $c.MandatoryLabelling)" }
                $dj = Get-PvSetting $lp 'requiredowngradejustification'; if ($null -ne $dj -and (& $isTrue $dj) -ne [bool]$c.DowngradeJustification) { $d += "downgrade justification is $(& $yn (& $isTrue $dj)), baseline expects $(& $yn $c.DowngradeJustification)" }
                $dl = $resolved[$c.DefaultLabel]; $cur = Get-PvSetting $lp 'defaultlabelid'
                if ($dl -and $cur -and "$cur" -ne "$($dl.Guid)" -and "$cur" -ne "$($dl.Name)") { $d += "default label for documents is not '$($dl.DisplayName)'" }
                if ($lp.Enabled -eq $false) { $d += 'the policy is switched off' }
            }
            & $emit $g3 "Label policy: $($c.Name)" ([bool]$lp) $d 'Publishes the four baseline labels, requires a label on documents and sets the default labels.' $lpL $null
            foreach ($o in @($lps | Where-Object { $_.Name -ne $c.Name })) {
                $have = @($o.Labels | ForEach-Object { "$_" })
                $shared = @($c.PublishedLabels | ForEach-Object { $resolved[$_] } | Where-Object { $_ -and ($have -contains "$($_.Guid)" -or $have -contains "$($_.Name)" -or $have -contains "$($_.DisplayName)") } | ForEach-Object { $_.DisplayName })
                if ($shared.Count) { & $addRow $g3x "Label policy: $($o.Name)" "Possible overlap, also publishes:`n$(($shared | ForEach-Object { '- ' + $_ }) -join "`n")" 'Reviewed by you' Manual "This policy publishes $($have.Count) label(s), including ALSO baseline labels. Users can get conflicting defaults or required-labeling rules when two policies target the same labels. Check which one should apply." $lpL $false }
                else { & $addRow $g3x "Label policy: $($o.Name)" "Publishes $($have.Count) label(s)" 'Reviewed by you' Info 'Your own label policy. It does not publish ALSO baseline labels. It is never changed by this script.' $lpL $false }
            }
        }
        catch { & $addRow $g3 'Label policy' "Could not be read: $($_.Exception.Message)" 'Readable' Error $null '' $lpL $false }

        $dlp = @(); $rules = @()
        Write-Host '   ...reading DLP policies and rules (can take a few minutes)' -ForegroundColor DarkGray; try { $dlp = @(Invoke-Timed 'Get-DlpCompliancePolicy -ErrorAction Stop' 180); $rules = @(Invoke-Timed 'Get-DlpComplianceRule -ErrorAction Stop' 180) }
        catch { & $addRow $g7 'Data loss prevention policies' "Could not be read: $($_.Exception.Message)" 'Readable' Error $null '' $dlpL $false }
        $rulesOf = { param($n) $rules | Where-Object { "$($_.ParentPolicyName)" -eq $n -or "$($_.Policy)" -eq $n } }
        $sitJson = { param($r) if ($r) { ($r | ForEach-Object { $_.ContentContainsSensitiveInformation } | ConvertTo-Json -Depth 12 -Compress) } else { '' } }
        $e5skip = { param($g, $n, $why) & $addRow $g $n 'Not licensed' 'Requires Microsoft 365 E5, E7 or the Purview suite' Skipped $why $dlpL $false }

        $g4 = 'ALSO baseline (suggested): DLP - protect labelled content'
        foreach ($c in $config.DlpPolicies) {
            if ($c.Name -like 'E5-PS*' -and $tier -ne 'Full') { & $e5skip $g4 $c.Name 'Endpoint DLP needs Microsoft 365 E5, E7 or the Purview suite.'; continue }
            $p = $dlp | Where-Object { $_.Name -eq $c.Name } | Select-Object -First 1
            $d = @()
            if ($p) {
                if ("$($p.Mode)" -eq 'Disable') { $d += 'the policy is switched off' }
                $loc = switch -Regex ("$($c.Workload)") { 'Exchange' { @($p.ExchangeLocation).Count } 'SharePoint' { @($p.SharePointLocation).Count } 'Endpoint' { @($p.EndpointDlpLocation).Count } default { 1 } }
                if (-not $loc) { $d += "it does not apply to $($c.Workload)" }
                $r = & $rulesOf $c.Name | Select-Object -First 1
                if (-not $r) { $d += 'the policy rule is missing' }
                elseif ($null -ne $c.BlockAccess -and "$($c.BlockAccess)" -ne '') {
                    if ($null -ne $r.BlockAccess -and [bool]$r.BlockAccess -ne [bool]$c.BlockAccess) { $d += "blocking is $(& $yn $r.BlockAccess), baseline expects $(& $yn $c.BlockAccess)" }
                    if ($c.BlockAccessScope -and $r.BlockAccessScope -and "$($r.BlockAccessScope)" -ne "$($c.BlockAccessScope)") { $d += "block scope is $($r.BlockAccessScope), baseline expects $($c.BlockAccessScope)" }
                }
            }
            $cur = if ($p) { " Mode today: $(& $modeTxt $p)." } else { '' }
            & $emit $g4 $c.Name ([bool]$p) $d "$($c.Comment)$cur" $dlpL $null
        }

        $g5 = 'ALSO baseline (suggested): DLP - detect sensitive data types'
        $sitNames = @{}
        foreach ($c in $config.SitDlpPolicies) {
            $p = $dlp | Where-Object { $_.Name -eq $c.Name } | Select-Object -First 1
            $need = @($c.SensitiveInformationTypes | Where-Object { -not $_.Optional } | ForEach-Object { $_.Name })
            $sitNames[$c.Name] = $need
            $d = @(); $equiv = $null
            if ($p) {
                if ("$($p.Mode)" -eq 'Disable') { $d += 'the policy is switched off' }
                $r = & $rulesOf $c.Name | Select-Object -First 1
                if (-not $r) { $d += 'the policy rule is missing' }
                else {
                    $j = & $sitJson $r
                    $lost = @($need | Where-Object { $j -notmatch [regex]::Escape($_) }); if ($lost.Count) { $d += "it does not look for: $($lost -join ', ')" }
                    if ($c.BlockAccess -and $null -ne $r.BlockAccess -and [bool]$r.BlockAccess -ne [bool]$c.BlockAccess) { $d += "blocking is $(& $yn $r.BlockAccess), baseline expects $(& $yn $c.BlockAccess)" }
                    if ($c.AccessScope -and $r.AccessScope -and "$($r.AccessScope)" -ne "$($c.AccessScope)") { $d += "it applies to '$($r.AccessScope)', baseline expects '$($c.AccessScope)'" }
                }
            }
            else {
                foreach ($o in @($dlp | Where-Object { $_.Name -notlike 'BP-ALSO*' -and $_.Name -notlike 'E5-PS-ALSO*' })) {
                    $j = & $sitJson (& $rulesOf $o.Name)
                    if ($j -and $need.Count -and -not @($need | Where-Object { $j -notmatch [regex]::Escape($_) }).Count) { $equiv = $o.Name; break }
                }
            }
            $cur = if ($p) { " Mode today: $(& $modeTxt $p)." } else { '' }
            & $emit $g5 $c.Name ([bool]$p) $d "$($c.Comment -replace ' Created by .*$', '')$cur" $dlpL $equiv
        }

        $g6 = 'ALSO baseline (suggested): AI protection'
        foreach ($c in $config.AIGovernance.DlpPolicies) {
            if ($tier -ne 'Full') { & $e5skip $g6 $c.Name 'Blocking Copilot from labelled content needs Microsoft 365 E5, E7 or the Purview suite.'; continue }
            $p = $dlp | Where-Object { $_.Name -eq $c.Name } | Select-Object -First 1
            $d = @(); if ($p -and "$($p.Mode)" -eq 'Disable') { $d += 'the policy is switched off' }
            if ($p -and -not (& $rulesOf $c.Name)) { $d += 'the policy rule is missing' }
            & $emit $g6 $c.Name ([bool]$p) $d $c.Comment $dlpL $null
        }

        $g7 = 'Your existing tenant: DLP policies'
        foreach ($o in @($dlp | Where-Object { $_.Name -notlike 'BP-ALSO*' -and $_.Name -notlike 'E5-PS-ALSO*' })) {
            $j = & $sitJson (& $rulesOf $o.Name)
            $where = @(if (@($o.ExchangeLocation).Count) { 'Exchange' }; if (@($o.SharePointLocation).Count) { 'SharePoint' }; if (@($o.OneDriveLocation).Count) { 'OneDrive' }; if (@($o.EndpointDlpLocation).Count) { 'Endpoint devices' }; if (@($o.TeamsLocation).Count) { 'Teams' }) -join ', '
            $facts = "Mode: $(& $modeTxt $o)." + $(if ($where) { " Applies to: $where." } else { '' })
            & $addRow $g7 "DLP policy: $($o.Name)" 'Existing policy' 'Reviewed by you' Info "$facts This policy already exists in your tenant and is not changed by this script. Review it and check that it does not overlap with the ALSO baseline DLP policies, otherwise users may be warned or blocked twice." $dlpL $false
        }

        $g8 = 'ALSO baseline (suggested): Retention (optional)'; $g8x = 'Your existing tenant: Retention policies'
        try {
            Write-Host '   ...reading retention policies' -ForegroundColor DarkGray; $ret = @(Invoke-Timed 'Get-RetentionCompliancePolicy -ErrorAction Stop')
            $c = $config.Retention
            $p = $ret | Where-Object { $_.Name -eq $c.Name } | Select-Object -First 1
            if ($p) {
                $d = @()
                Write-Host '   ...reading retention rule' -ForegroundColor DarkGray; $r = $null; try { $r = @(Invoke-Timed "Get-RetentionComplianceRule -Policy '$($p.Name -replace "'","''")' -ErrorAction Stop" 45) | Select-Object -First 1 } catch {}
                if ($r -and $null -ne $r.RetentionDuration -and "$($r.RetentionDuration)" -ne "$($c.DurationDays)") { $d += "keeps data $($r.RetentionDuration) days, baseline expects $($c.DurationDays)" }
                if ($r -and $r.RetentionComplianceAction -and "$($r.RetentionComplianceAction)" -ne "$($c.Action)") { $d += "action is $($r.RetentionComplianceAction), baseline expects $($c.Action)" }
                & $emit $g8 "Optional: $($c.Name)" $true $d 'Keeps Exchange mail for seven years and then deletes it. Optional, only after legal review.' $retL $null
            }
            else { & $addRow $g8 "Optional: $($c.Name)" 'Not deployed' 'Only after legal review' Info 'Keeps Exchange mail for seven years and then deletes it. It is optional and must be approved by legal and compliance first. Enforce mode asks separately.' $retL $false }
            foreach ($o in @($ret | Where-Object { $_.Name -ne $c.Name })) { & $addRow $g8x "Your retention policy: $($o.Name)" "$(if ($o.Enabled -eq $false) { 'Off' } else { 'On' })" 'Reviewed' Info 'Retention decides how long data is kept or deleted. Make sure it matches your legal requirements.' $retL $false }
        }
        catch { & $addRow $g8 'Retention policies' "Could not be read: $($_.Exception.Message)" 'Readable' Error $null '' $retL $false }

        $g9 = 'Your existing tenant: Other Purview protections'
        $extras = @(
            @{ N = 'Auto-labeling policies'; C = 'Get-AutoSensitivityLabelPolicy -ErrorAction Stop'; D = 'Auto-labeling applies labels to content that contains sensitive information, without relying on users.'; L = 'https://purview.microsoft.com/informationprotection/autolabeling' }
            @{ N = 'Insider risk management policies'; C = 'Get-InsiderRiskPolicy -ErrorAction Stop'; D = 'Detects risky activity such as data leaks by departing employees. Needs Microsoft 365 E5 or the Purview suite.'; L = 'https://purview.microsoft.com/insiderriskmanagement' }
            @{ N = 'Communication compliance policies'; C = 'Get-SupervisoryReviewPolicyV2 -ErrorAction Stop'; D = 'Reviews messages for policy violations. Needs Microsoft 365 E5 or the Purview suite.'; L = 'https://purview.microsoft.com/communicationcompliance' }
        )
        foreach ($x in $extras) {
            Write-Host "   ...reading $($x.N)" -ForegroundColor DarkGray
            try { $cc = @(Invoke-Timed $x.C 40); & $addRow $g9 $x.N $(if ($cc.Count) { "$($cc.Count): $(($cc | ForEach-Object { $_.Name }) -join '; ')" } else { 'None' }) 'Considered for your organization' Info $x.D $x.L $false }
            catch { & $addRow $g9 $x.N 'Not available in this tenant or not readable' 'Considered for your organization' Info $x.D $x.L $false }
        }
        $i = 0
        @($rows | ForEach-Object { $k = if ($_.Group -like 'Your existing*') { 2 } else { 1 }; [pscustomobject]@{ K = $k; I = $i++; R = $_ } } | Sort-Object K, I | ForEach-Object { $_.R })
    }

    $first = @(& $check 3>$null)
    $mipRow = @($first | Where-Object { $_.Setting -like 'Sensitivity labels for Microsoft 365 groups*' -and $_.Status -eq 'Drift' })
    if ($Mode -eq 'Enforce' -and $mipRow.Count -and (Confirm-Change "Turn on sensitivity labels for Microsoft 365 groups, Teams and sites (Group.Unified EnableMIPLabels: from Off to On)")) {
        try {
            $guUri = 'https://graph.microsoft.com/v1.0/groupSettings'
            $gu = @(Get-AllPages $guUri) | Where-Object { $_.displayName -eq 'Group.Unified' } | Select-Object -First 1
            if ($gu) {
                $vals = @(@($gu.values) | ForEach-Object { @{ name = $_.name; value = $(if ($_.name -eq 'EnableMIPLabels') { 'true' } else { "$($_.value)" }) } })
                if (-not ($vals | Where-Object { $_.name -eq 'EnableMIPLabels' })) { $vals += @{ name = 'EnableMIPLabels'; value = 'true' } }
                Graph PATCH "$guUri/$($gu.id)" @{ values = $vals } | Out-Null
            }
            else {
                $tpl = @((Graph GET 'https://graph.microsoft.com/v1.0/groupSettingTemplates').value) | Where-Object { $_.displayName -eq 'Group.Unified' } | Select-Object -First 1
                $vals = @(@($tpl.values) | ForEach-Object { @{ name = $_.name; value = $(if ($_.name -eq 'EnableMIPLabels') { 'true' } else { "$($_.defaultValue)" }) } })
                Graph POST $guUri @{ templateId = $tpl.id; values = $vals } | Out-Null
            }
            $re = @(& $check 3>$null)
            foreach ($f in $re) { if ($f.Setting -like 'Sensitivity labels for Microsoft 365 groups*' -and $f.Status -eq 'Compliant') { $f.Status = 'Fixed'; $f.Current = 'Off' } }
            $first = $re
        }
        catch { Add-Result 'Purview' 'Turning on: sensitivity labels for groups, Teams and sites' 'Off' 'On' Error 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/General' $_.Exception.Message $doc $docText }
    }
    if ($Mode -eq 'Enforce' -and $script:SpoOk) {
        $spoDrift = @($first | Where-Object { $_.Group -eq 'Tenant settings' -and $_.Status -eq 'Drift' -and $_.Setting -like 'Sensitivity labels*' })
        if ($spoDrift.Count -and (Confirm-Change "Turn on SharePoint/OneDrive sensitivity label support: $(($spoDrift | ForEach-Object { $_.Setting }) -join '; ')")) {
            foreach ($s in $spoDrift) {
                try {
                    if ($s.Setting -like '*PDF*') { Set-SpoTenantCsom 'EnableSensitivityLabelforPDF' }
                    else { Set-SpoTenantCsom 'EnableAIPIntegration' }
                }
                catch { Add-Result 'Purview' "Turning on: $($s.Setting)" $_.Exception.Message 'On' Error $spoLink 'SharePoint rejected the change. Turn it on in the SharePoint admin center.' $doc $docText }
            }
            $first = @(& $check 3>$null)
            foreach ($f in $first) { $o = $spoDrift | Where-Object { $_.Setting -eq $f.Setting }; if ($o -and $f.Status -eq 'Compliant') { $f.Status = 'Fixed'; $f.Current = $o.Current } }
        }
    }    $todo = @($first | Where-Object { $_.Status -eq 'Drift' -and $_.Deployable })
    $final = $first
    $deployed = $false
    $retRow = @($first | Where-Object { $_.Setting -like 'Optional: BP-ALSO*' -and $_.Status -eq 'Info' })

    if ($Mode -eq 'Enforce' -and ($todo.Count -or $retRow.Count)) {
        if ($PSVersionTable.PSVersion.Major -lt 7) {
            Add-Result 'Purview' 'Deploy the Purview baseline' 'PowerShell 7 is required' 'Deployed' Manual $repo 'ALSO''s Purview toolkit needs PowerShell 7 or later. Run this script again from PowerShell 7 (pwsh) to deploy automatically.' $doc $docText
        }
        else {
            $existing = @($todo | Where-Object { $_.Current -like 'Exists*' })
            $go = $false; $adopt = $false; $doRet = $false; $partKeys = @()
            if ($todo.Count) {
                $partOf = { param($g) if ($g -match 'Sensitivity labels|Label policy') { 'labels' } elseif ($g -match 'protect labelled') { 'dlp' } elseif ($g -match 'sensitive data types') { 'sit' } elseif ($g -match 'AI protection') { 'ai' } else { 'other' } }
                $partNames = @{ labels = 'Sensitivity labels and label policy'; dlp = 'DLP policies for labelled content'; sit = 'DLP policies for sensitive data types'; ai = 'AI protection (block Copilot on Highly Confidential content)' }
                $parts = @()
                foreach ($k in 'labels', 'dlp', 'sit', 'ai') {
                    $inPart = @($todo | Where-Object { (& $partOf $_.Group) -eq $k })
                    if ($inPart.Count) { $parts += [pscustomobject]@{ Key = $k; Name = $partNames[$k]; Items = $inPart } }
                }
                Write-Host '   Purview parts with missing or different items. New DLP policies start in simulation mode, so nothing is blocked by surprise.' -ForegroundColor DarkGray
                $selParts = @(Select-Deployment $parts 'Purview baseline parts' { "$($_.Name) ($($_.Items.Count) item(s): $(($_.Items | ForEach-Object { $_.Setting -replace '^(Label|Sub-label|Label policy|DLP policy): ', '' }) -join '; '))" })
                $partKeys = @($selParts | ForEach-Object { $_.Key })
                $go = $partKeys.Count -gt 0
                if ($go -and $existing.Count) { $adopt = Confirm-Change "Update $($existing.Count) existing Purview item(s) so they match the baseline" }
            }
            if ($retRow.Count -and -not $Force) { $doRet = Confirm-Change 'Also deploy the optional 7-year Exchange retention policy (mail is DELETED after 7 years - get legal approval first)' -Always }
            if ($go -or $doRet) {
                $mods = Join-Path $tk 'Purview\Modules'
                . (Join-Path $mods 'PurviewRunLog.ps1'); Initialize-PurviewRunLog
                $ti = [pscustomobject]@{ DisplayName = $org.displayName; TenantId = $org.id; DefaultDomain = [string]($org.verifiedDomains | Where-Object { $_.isDefault } | Select-Object -First 1).name; InitialDomain = $initialDomain; AllDomains = @($org.verifiedDomains | ForEach-Object { $_.name }); Source = 'Microsoft Graph organization' }
                $run = {
                    param($Name, $Body)
                    $sw = [Diagnostics.Stopwatch]::StartNew()
                    $ErrorActionPreference = 'Continue'
                    try {
                        $err = @()
                        & $Body 2>&1 3>$null | ForEach-Object { if ($_ -is [Management.Automation.ErrorRecord]) { $err += $_.Exception.Message; Write-Host "      ! $($_.Exception.Message)" -ForegroundColor Yellow } else { $_ } }
                        Write-Host ("   Finished {0} in {1:n0} seconds." -f $Name, $sw.Elapsed.TotalSeconds) -ForegroundColor DarkGray
                        if ($err.Count) { $errText = (($err | Select-Object -First 3 | ForEach-Object { "- $_" }) -join "`n"); Add-Result 'Purview' "Deploying: $Name" "$($err.Count) problem(s)" 'Deployed without problems' Error $repo $errText $doc $docText }
                        $true
                    }
                    catch { Add-Result 'Purview' "Deploying: $Name" $_.Exception.Message 'Deployed' Error $repo 'The ALSO Purview toolkit stopped with this error. The script continues with the next part. Run the script again after fixing the cause; completed parts are not repeated.' $doc $docText; $false }
                }
                if ($go) {
                    if ($partKeys -contains 'labels') {
                        $a = @{ Config = $config; TenantIdentity = $ti }; if ($adopt) { $a.AdoptExisting = $true }
                        Write-Host '   Deploying sensitivity labels and label policy. Microsoft processes label changes slowly: this part can take 5 to 15 minutes. The script is not stuck, please wait.' -ForegroundColor Cyan
                        $null = & $run 'sensitivity labels and label policy' { & (Join-Path $mods 'Setup-SensitivityLabels.ps1') @a }
                    }
                    if ($partKeys -contains 'dlp') {
                        $a = @{ Config = $config }; if ($adopt) { $a.AdoptExisting = $true }; if ($tier -ne 'Full') { $a.BPOnly = $true }
                        Write-Host '   Deploying label-based DLP policies...' -ForegroundColor Cyan
                        $null = & $run 'label-based DLP' { & (Join-Path $mods 'Setup-DLP.ps1') @a }
                    }
                    if ($partKeys -contains 'sit') {
                        Write-Host '   Deploying sensitive-data DLP policies...' -ForegroundColor Cyan
                        $null = & $run 'sensitive-data DLP' {
                            $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $tk 'Purview\Deploy-PurviewBestPractice.ps1'), [ref]$null, [ref]$null)
                            $fn = $ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-AlsoSitDlp' }, $true)
                            . ([scriptblock]::Create($fn.Extent.Text))
                            Invoke-AlsoSitDlp -Config $config
                        }
                    }
                    if ($partKeys -contains 'ai' -and $tier -eq 'Full') {
                        $a = @{ Config = $config }; if ($adopt) { $a.AdoptExisting = $true }
                        Write-Host '   Deploying AI protection...' -ForegroundColor Cyan
                        $null = & $run 'AI protection' { & (Join-Path $mods 'Setup-AIGovernance.ps1') @a }
                    }
                }
                if ($doRet) {
                    $a = @{ Config = $config }; if ($adopt) { $a.AdoptExisting = $true }
                    $null = & $run 'retention' { & (Join-Path $mods 'Setup-Retention.ps1') @a }
                }
                $deployed = $true
                Write-Host '   Reading the tenant again to verify the result...' -ForegroundColor Cyan
                $final = @(& $check 3>$null)
            }
        }
    }

    $start = $script:Results.Count
    $lastG = $null
    foreach ($r in $final) {
        if ($r.Group -ne $lastG) { Set-Group $r.Group; $lastG = $r.Group }
        $status = $r.Status; $cur = $r.Current; $detail = $r.Detail
        if ($deployed -and $r.Deployable -and $status -eq 'Drift') { $detail += ' It still does not match after the deployment. See the console output for the reason.' }
        $before = $first | Where-Object { $_.Setting -eq $r.Setting } | Select-Object -First 1
        if ($deployed -and $before -and $before.Deployable -and $before.Status -eq 'Drift' -and $status -eq 'Compliant') { $status = 'Fixed'; $cur = $before.Current }
        Add-Result 'Purview' $r.Setting $cur $r.Expected $status $r.Link $detail $doc $docText
    }

    $mine = @($script:Results | Select-Object -Skip $start)
    $base = @($mine | Where-Object { $_.Status -in 'Compliant', 'Fixed', 'Drift' })
    $okN = @($base | Where-Object { $_.Status -in 'Compliant', 'Fixed' }).Count
    $badN = @($base | Where-Object { $_.Status -eq 'Drift' }).Count
    $sim = @($final | Where-Object { $_.Current -match '^Matches' -and $_.Detail -match 'Mode today: Simulation' } | ForEach-Object { $_.Setting })
    Set-Group 'Summary'
    $verdict = if ($badN -eq 0) { 'Everything in the ALSO baseline that applies to your licenses is in place.' } elseif ($Mode -eq 'Enforce') { "$badN item(s) are still missing or different." } else { "$badN item(s) are missing or different. Run the script in Enforce mode to deploy them." }
    Add-Result 'Purview' 'Purview baseline overview' "$okN of $($base.Count) baseline items match" 'All items match' $(if ($badN) { 'Info' } else { 'Compliant' }) 'https://purview.microsoft.com' "$verdict Each policy below is compared setting by setting with ALSO's baseline file. 'Matches' means your policy has the baseline settings. 'Differs' lists exactly what is different. Your own policies are listed for review only and are never changed." $doc $docText
    $sum = $script:Results[$script:Results.Count - 1]; $script:Results.RemoveAt($script:Results.Count - 1); $sum.Group = '0. Summary'; $script:Results.Insert($start, $sum)

    Set-Group 'To do by a person'
    if ($sim.Count) { Add-Result 'Purview' 'DLP policies are in simulation mode' ($sim -join '; ') 'Switched on after reviewing the simulation results' Manual $dlpL 'The baseline starts DLP policies in simulation mode so nothing is blocked by surprise. Review the matches in Activity explorer for a few weeks, then switch each policy to On.' $doc $docText }
    if ($badN -gt 0 -and $Mode -ne 'Enforce') { Add-Result 'Purview' 'Deploy the missing items' "$badN item(s) missing or different" 'Deployed' Manual $repo 'Run this script in Enforce mode from PowerShell 7 to deploy them with ALSO''s Purview toolkit, or run Deploy-PurviewBestPractice.ps1 from the toolkit yourself (start with -WhatIf).' $doc $docText }
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

function Select-Removal($Items, [string]$Noun, [scriptblock]$Name) {
    $Items = @($Items)
    if (-not $Items.Count) { return @() }
    if (-not $PSCmdlet.ShouldProcess("Remove $($Items.Count) $Noun")) { return @() }
    if ($Force) { return $Items }
    Write-Host ''
    Write-Host "   $($Items.Count) $Noun found that this script can remove:" -ForegroundColor Yellow
    foreach ($i in $Items) { Write-Host "     - $(& $Name $i)" }
    $a = Read-Host '   [a] remove all  [o] choose one by one  [n] remove none (default: none)'
    if ($a -match '^(a|all)$') { return $Items }
    if ($a -match '^(o|one)$') {
        $sel = @()
        foreach ($i in $Items) { if ((Read-Host "   Remove '$(& $Name $i)'? [y/N]") -match '^(y|yes)$') { $sel += $i } }
        return $sel
    }
    return @()
}

function Remove-Items([string]$Step, [string]$Noun, $Items, [scriptblock]$Name, [scriptblock]$Delete, [string]$Link, [string]$Why) {
    $Items = @($Items)
    if (-not $Items.Count) { Add-Result $Step $Noun 'None found' 'Removed' Info $Link 'Nothing of this kind that the script deploys was found in the tenant, so there is nothing to remove.'; return }
    $sel = @(Select-Removal $Items $Noun $Name)
    foreach ($i in $Items) {
        $n = & $Name $i
        if ($sel -notcontains $i) { Add-Result $Step $n 'Left in place' 'Removed' Skipped $Link $Why; continue }
        try { & $Delete $i; Add-Result $Step $n 'Present' 'Removed' Fixed $Link $Why }
        catch { Add-Result $Step $n 'Present' 'Removed' Error $Link "$($_.Exception.Message)" }
    }
}

function Grant-AuAdmin([string]$AuId) {
    $added = 0
    foreach ($role in @{ 'Groups Administrator' = 'fdd7a751-b60b-444a-984c-02652fe8fa1c'; 'User Administrator' = 'fe930be7-5e62-47db-91af-98c3a49a38b1' }.GetEnumerator()) {
        $have = @((Graph GET "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$AuId/scopedRoleMembers").value | Where-Object { $_.roleId -eq $role.Value -and $_.roleMemberInfo.id -eq $script:MeId })
        if (-not $have.Count) {
            Graph POST "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$AuId/scopedRoleMembers" @{ roleId = $role.Value; roleMemberInfo = @{ id = $script:MeId } } | Out-Null
            $added++
        }
    }
    $added
}

function Remove-FromRestrictedUnit([string]$ObjectId) {
    try {
        $q = [uri]::EscapeDataString("displayName eq '$BreakGlassAuName'")
        foreach ($au in @((Graph GET ('https://graph.microsoft.com/v1.0/directory/administrativeUnits?$filter=' + $q)).value)) {
            try { Graph DELETE "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$($au.id)/members/$ObjectId/`$ref" | Out-Null } catch { }
        }
    }
    catch { }
}

function Step-WipeConditionalAccess {
    Write-Step 'Remove Conditional Access baseline' 'Removes the ALSO Conditional Access policies, authentication contexts and groups that this script imported.'
    $link = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'
    $caBase = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
    $stateTxt = @{ enabled = 'On'; disabled = 'Off'; enabledForReportingButNotEnforced = 'Report-only' }
    $dir = Get-GuidePackage 'conditional-access'
    $names = @(Get-PackageJson $dir 'ConditionalAccess' | ForEach-Object { $_.Json.displayName })
    Set-Group 'ALSO Conditional Access policies'
    $pol = @(Get-AllPages $caBase | Where-Object { $_.displayName -in $names } | ForEach-Object { [pscustomobject]@{ Name = "$($_.displayName) (currently $($stateTxt["$($_.state)"]))"; Uri = "$caBase/$($_.id)" } })
    Remove-Items 'ConditionalAccess' 'ALSO Conditional Access policies' $pol { param($x) $x.Name } { param($x) Graph DELETE $x.Uri | Out-Null } $link 'Policies that are switched on stop protecting users as soon as they are removed. Only policies with the exact ALSO names are listed; your own policies are never touched.'

    Set-Group 'Authentication contexts'
    $ctxUri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences'
    $ctx = @()
    foreach ($c in @(Get-PackageJson $dir 'AuthenticationContext')) {
        try { $have = Graph GET "$ctxUri/$($c.Json.id)"; if ($have.id) { $ctx += [pscustomobject]@{ Name = "Authentication context: $($have.displayName)"; Uri = "$ctxUri/$($have.id)" } } } catch { }
    }
    Remove-Items 'ConditionalAccess' 'ALSO authentication contexts' $ctx { param($x) $x.Name } { param($x) Graph DELETE $x.Uri | Out-Null } $link 'An authentication context cannot be removed while a Conditional Access policy still uses it. Remove the policies first.'

    Set-Group 'Groups created for the ALSO policies'
    $grp = @()
    foreach ($g in @(Get-PackageJson $dir 'Groups')) {
        $gn = $g.Json.displayName
        if ($gn -like '*BSAccounts*') { continue }
        $q = [uri]::EscapeDataString("displayName eq '$($gn.Replace("'", "''"))'")
        foreach ($f in @((Graph GET ('https://graph.microsoft.com/v1.0/groups?$filter=' + $q + '&$select=id,displayName,description')).value)) {
            if ("$($f.description)" -eq 'ALSO Conditional Access baseline group') { $grp += [pscustomobject]@{ Name = "Group: $($f.displayName)"; Id = $f.id } }
        }
    }
    Remove-Items 'ConditionalAccess' 'groups created for the ALSO policies' $grp { param($x) $x.Name } { param($x) Remove-FromRestrictedUnit $x.Id; Graph DELETE "https://graph.microsoft.com/v1.0/groups/$($x.Id)" | Out-Null } 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/AllGroups' 'Only groups with the description "ALSO Conditional Access baseline group" are listed, so groups you made yourself are never removed.'
}

function Step-WipeIntunePolicies {
    Write-Step 'Remove Intune policy baseline' 'Removes the Intune policies that this script imported (matched by the exact ALSO policy names).'
    $link = 'https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/overview'
    $norm = { param($s) ("$s" -replace '[^\p{L}\p{N}]', '').ToLower() }
    $cache = @{}; $seen = @{}; $items = @()
    Set-Group 'ALSO Intune policies'
    foreach ($pkg in 'device-compliance', 'app-protection', 'device-security', 'defender-onboarding', 'defender-security', 'browser-protection') {
        try { $dir = Get-GuidePackage $pkg } catch { continue }
        foreach ($x in (Get-PackageJson $dir $null)) {
            if ($x.File.Name -eq 'MigrationTable.json') { continue }
            $target = Get-IntuneTarget $x.Json
            if (-not $target) { continue }
            $nm = if ($x.Json.displayName) { $x.Json.displayName } else { $x.Json.name }
            if (-not $cache.ContainsKey($target)) { $cache[$target] = @(Get-AllPages $target) }
            $m = $cache[$target] | Where-Object { (& $norm $(if ($_.displayName) { $_.displayName } else { $_.name })) -eq (& $norm $nm) } | Select-Object -First 1
            if (-not $m -or $seen.ContainsKey("$($m.id)")) { continue }
            $seen["$($m.id)"] = $true
            $assigned = 0; try { $assigned = @((Graph GET "$target/$($m.id)/assignments").value).Count } catch { }
            $items += [pscustomobject]@{ Name = "$nm$(if ($assigned) { " (assigned to $assigned group(s): devices lose it when removed)" })"; Uri = "$target/$($m.id)" }
        }
    }
    Remove-Items 'IntunePolicies' 'ALSO Intune policies' $items { param($x) $x.Name } { param($x) Graph DELETE $x.Uri | Out-Null } $link 'Removing a policy that is assigned removes its settings from devices at the next check-in. Policies with different names, such as your own, are never touched.'
}

function Step-WipePurview {
    Write-Step 'Remove Purview baseline' 'Removes the ALSO Purview DLP policies, label policy, retention policy and sensitivity labels that the baseline deployed.'
    $repo = 'https://github.com/CoC-MS/ALSO-Microsoft-Security-Purview'
    try { $tk = Get-PurviewToolkit 3>$null; $config = Import-PowerShellDataFile (Join-Path $tk 'Purview\Config\PurviewConfig.psd1') }
    catch { Add-Result 'Purview' 'ALSO Purview baseline configuration' "Could not be downloaded: $($_.Exception.Message)" 'Downloaded from GitHub' Error $repo 'The wipe needs the list of baseline names from ALSO''s Purview repository.'; return }
    if (-not (Get-Command Get-Label -ErrorAction SilentlyContinue)) { Add-Result 'Purview' 'Purview connection' 'Purview commands are not available' 'Available' Error 'https://purview.microsoft.com' 'Close PowerShell, open a new PowerShell 7 window as administrator and run the wipe again.'; return }
    $tag = "$($config.ManagedByTag)"
    $dlpL = 'https://purview.microsoft.com/datalossprevention/policies'

    Set-Group 'DLP policies'
    $dlpNames = @($config.DlpPolicies.Name) + @($config.SitDlpPolicies.Name) + @($config.AIGovernance.DlpPolicies.Name) | Where-Object { $_ }
    $dlp = @()
    try { $dlp = @(Get-DlpCompliancePolicy -ErrorAction Stop | Where-Object { $_.Name -in $dlpNames } | ForEach-Object { [pscustomobject]@{ Name = "DLP policy: $($_.Name)"; Id = $_.Name } }) }
    catch { Add-Result 'Purview' 'DLP policies' "Could not be read: $($_.Exception.Message)" 'Readable' Error $dlpL '' }
    Remove-Items 'Purview' 'ALSO DLP policies' $dlp { param($x) $x.Name } {
        param($x)
        foreach ($r in @(Get-DlpComplianceRule -Policy $x.Id -ErrorAction SilentlyContinue)) { Remove-DlpComplianceRule -Identity $r.Name -Confirm:$false -ErrorAction Stop }
        Remove-DlpCompliancePolicy -Identity $x.Id -Confirm:$false -ErrorAction Stop
    } $dlpL 'Removing a DLP policy stops protection for the data it covered. Microsoft can take up to an hour to finish removing it.'

    Set-Group 'Label policy and sensitivity labels'
    $lp = @()
    try { $lp = @(Get-LabelPolicy -ErrorAction Stop | Where-Object { $_.Name -eq $config.LabelPolicy.Name } | ForEach-Object { [pscustomobject]@{ Name = "Label policy: $($_.Name)"; Id = $_.Name } }) }
    catch { Add-Result 'Purview' 'Label policy' "Could not be read: $($_.Exception.Message)" 'Readable' Error 'https://purview.microsoft.com/informationprotection/labelpolicies' '' }
    Remove-Items 'Purview' 'ALSO label policy' $lp { param($x) $x.Name } { param($x) Remove-LabelPolicy -Identity $x.Id -Confirm:$false -ErrorAction Stop } 'https://purview.microsoft.com/informationprotection/labelpolicies' 'Users no longer see the ALSO labels in Office apps after the policy is removed.'

    $labelNames = @($config.Labels | ForEach-Object { $_.Name; @($_.SubLabels | Where-Object { $_ } | ForEach-Object { $_.Name }) })
    $lab = @()
    try {
        $all = @(Get-Label -ErrorAction Stop | Where-Object { $_.Name -in $labelNames -and "$($_.Comment)" -like "*$tag*" })
        $lab = @(@($all | Where-Object { $_.ParentId }) + @($all | Where-Object { -not $_.ParentId }) | ForEach-Object { [pscustomobject]@{ Name = "Sensitivity label: $($_.DisplayName)"; Id = "$($_.Guid)" } })
    }
    catch { Add-Result 'Purview' 'Sensitivity labels' "Could not be read: $($_.Exception.Message)" 'Readable' Error 'https://purview.microsoft.com/informationprotection/labels' '' }
    Remove-Items 'Purview' 'ALSO sensitivity labels' $lab { param($x) $x.Name } { param($x) Remove-Label -Identity $x.Id -Confirm:$false -ErrorAction Stop } 'https://purview.microsoft.com/informationprotection/labels' 'Only labels marked as deployed by the ALSO toolkit are listed. Files already labelled keep their label text but lose label based protection. Sub-labels are listed before their parent labels.'

    Set-Group 'Retention policy'
    $ret = @()
    try { $ret = @(Get-RetentionCompliancePolicy -ErrorAction Stop | Where-Object { $_.Name -eq $config.Retention.Name } | ForEach-Object { [pscustomobject]@{ Name = "Retention policy: $($_.Name)"; Id = $_.Name } }) }
    catch { Add-Result 'Purview' 'Retention policy' "Could not be read: $($_.Exception.Message)" 'Readable' Error 'https://purview.microsoft.com/datalifecyclemanagement/policies' '' }
    Remove-Items 'Purview' 'ALSO retention policy' $ret { param($x) $x.Name } {
        param($x)
        foreach ($r in @(Get-RetentionComplianceRule -Policy $x.Id -ErrorAction SilentlyContinue)) { Remove-RetentionComplianceRule -Identity $r.Name -Confirm:$false -ErrorAction Stop }
        Remove-RetentionCompliancePolicy -Identity $x.Id -Confirm:$false -ErrorAction Stop
    } 'https://purview.microsoft.com/datalifecyclemanagement/policies' 'A retention policy with preservation lock cannot be removed by anyone.'
}

function Step-WipeRmau {
    Write-Step 'Remove the restricted management unit' 'Removed first, because groups inside it cannot be deleted by anyone who is not an administrator of the unit.'
    Set-Group 'Restricted management administrative unit'
    $link = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AdministrativeUnitsMenuBlade/~/AdminUnits'
    $q = [uri]::EscapeDataString("displayName eq '$BreakGlassAuName'")
    $items = @(foreach ($a in @((Graph GET ('https://graph.microsoft.com/v1.0/directory/administrativeUnits?$filter=' + $q)).value)) { [pscustomobject]@{ Name = "Restricted management unit: $($a.displayName)"; Uri = "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$($a.id)" } })
    Remove-Items 'BreakGlass' 'restricted management unit' $items { param($x) $x.Name } { param($x) Graph DELETE $x.Uri | Out-Null } $link 'Removing the unit first frees the Conditional Access groups and the emergency access group, so they can be deleted in the next steps.'
}

function Step-WipeBreakGlass {    Write-Step 'Remove emergency access accounts' 'Removes the two emergency access accounts, their security group and the restricted management unit that this script created.'
    Set-Group 'Emergency access accounts, group and restricted management unit'
    $link = 'https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers'
    Write-Host '   WARNING: make sure another Global Administrator can sign in before you remove the emergency access accounts.' -ForegroundColor Yellow
    $items = @()
    $q = [uri]::EscapeDataString("displayName eq '$BreakGlassAuName'")
    $g = $null
    $gf = Find-GroupByName $BreakGlassGroupName
    if ($gf) {
        $gd = Graph GET "https://graph.microsoft.com/v1.0/groups/$($gf.id)?`$select=id,displayName,description"
        if ($gd.description -eq 'Protected service accounts') { $g = $gd; $items += [pscustomobject]@{ Name = "Security group: $($g.displayName)"; Uri = "https://graph.microsoft.com/v1.0/groups/$($g.id)"; Id = $g.id; User = $false } }
        else { Write-Host "   Group '$($gd.displayName)' was not created by this script (different description), so it is left alone." -ForegroundColor DarkGray }
    }
    $gMembers = @()
    if ($g) { try { $gMembers = @(Get-AllPages "https://graph.microsoft.com/v1.0/groups/$($g.id)/members/microsoft.graph.user?`$select=id" | ForEach-Object { $_.id }) } catch { } }
    foreach ($n in $script:Reference.breakGlass.accountNames) {
        try {
            $u = Graph GET "https://graph.microsoft.com/v1.0/users/$("$n@$initialDomain")?`$select=id,userPrincipalName,department"
            if ($u.id -and ($u.department -eq 'ALSO Secure by Default' -or $u.id -in $gMembers -or $u.displayName -eq $n)) { $items += [pscustomobject]@{ Name = "Account: $($u.userPrincipalName)"; Uri = "https://graph.microsoft.com/v1.0/users/$($u.id)"; Id = $u.id; User = $true } }
            elseif ($u.id) { Write-Host "   Account $($u.userPrincipalName) was not created by this script, so it is left alone." -ForegroundColor DarkGray }
        } catch { }
    }
    Remove-Items 'BreakGlass' 'emergency access accounts, group and restricted management unit' $items { param($x) $x.Name } {
        param($x)
        if ($x.User) {
            foreach ($ra in @((Graph GET "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($x.Id)'").value)) { try { Graph DELETE "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/$($ra.id)" | Out-Null } catch { } }
        }
        Graph DELETE $x.Uri | Out-Null
        if ($x.User) { try { Graph DELETE "https://graph.microsoft.com/v1.0/directory/deletedItems/$($x.Id)" | Out-Null } catch { } }
    } $link 'Accounts are deleted permanently so the same names can be created again. The group is removed first, then the accounts. Only the accounts and group that this script created are removed (matched by the exact names, the marker or the group).'
}

function Step-WipeTenantSettings {
    Write-Step 'Set tenant-wide settings back to Microsoft defaults' 'Only settings that currently differ from the Microsoft default are listed. Nothing is changed until you choose.'
    Set-Group 'Tenant-wide settings'
    $items = New-Object System.Collections.ArrayList
    $add = {
        param($Step, $Text, $Do)
        if ($Step -in $Steps) { [void]$items.Add([pscustomobject]@{ Name = $Text; Do = $Do }) }
    }
    $authUri = 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
    try {
        $p = Graph GET $authUri; $d = $p.defaultUserRolePermissions
        if ($d.allowedToCreateApps -eq $false) { & $add 'UserSettings' 'Users can register applications: from No to Yes' { Graph PATCH $authUri @{ defaultUserRolePermissions = @{ allowedToCreateApps = $true } } | Out-Null } }
        if ($d.allowedToCreateTenants -eq $false) { & $add 'UserSettings' 'Non-admin users can create tenants: from No to Yes' { Graph PATCH $authUri @{ defaultUserRolePermissions = @{ allowedToCreateTenants = $true } } | Out-Null } }
        if ($d.allowedToCreateSecurityGroups -eq $false) { & $add 'UserSettings' 'Users can create security groups: from No to Yes' { Graph PATCH $authUri @{ defaultUserRolePermissions = @{ allowedToCreateSecurityGroups = $true } } | Out-Null } }
        if ("$($p.guestUserRoleId)" -ne 'a0b1b346-4d3e-4e8b-98f8-753987be4970' -and "$($p.guestUserRoleId)" -ne '10dae51f-b6af-4016-8d66-8c2a99b929b3') { & $add 'UserSettings' 'Guest user access: back to Limited access (Microsoft default)' { Graph PATCH $authUri @{ guestUserRoleId = '10dae51f-b6af-4016-8d66-8c2a99b929b3' } | Out-Null } }
        $assigned = @($d.permissionGrantPoliciesAssigned)
        if ($assigned | Where-Object { $_ -match 'default-low' }) {
            & $add 'Consent' 'User consent for apps: from verified publishers and low-impact permissions to the Microsoft-managed default' {
                $keep = @($assigned | Where-Object { $_ -notmatch '^ManagePermissionGrantsForSelf\.' })
                Graph PATCH $authUri @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-recommended') + $keep } } | Out-Null }
        }
    }
    catch { Add-Result 'UserSettings' 'Reading the user settings' $_.Exception.Message 'Readable' Error 'https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/UserSettings' }
    try {
        $ux = 'https://graph.microsoft.com/beta/admin/entra/uxSetting'
        if ("$((Graph GET $ux).restrictNonAdminAccess)" -eq 'true') { & $add 'UserSettings' 'Restrict access to Microsoft Entra admin center: from Yes to No' { Graph PATCH $ux @{ restrictNonAdminAccess = 'false' } | Out-Null } }
    }
    catch { }
    try {
        $wUri = 'https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy'
        if ((Graph GET $wUri).isEnabled -eq $true) { & $add 'Consent' 'Admin consent request workflow: from enabled to disabled' { Graph PUT $wUri @{ isEnabled = $false; notifyReviewers = $false; remindersEnabled = $false; requestDurationInDays = 30; reviewers = @() } | Out-Null } }
    }
    catch { }
    try {
        $sp = 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings'; $t = Graph GET $sp
        if ("$($t.sharingCapability)" -in 'disabled', 'existingExternalUserSharingOnly', 'externalUserSharingOnly') { & $add 'Sharepoint' "SharePoint and OneDrive external sharing: from $($t.sharingCapability) to externalUserAndGuestSharing (Anyone, Microsoft default)" { Graph PATCH $sp @{ sharingCapability = 'externalUserAndGuestSharing' } | Out-Null } }
        if ($t.isResharingByExternalUsersEnabled -eq $false) { & $add 'Sharepoint' 'Guests can share items they do not own: from No to Yes' { Graph PATCH $sp @{ isResharingByExternalUsersEnabled = $true } | Out-Null } }
    }
    catch { }
    try {
        $mdm = 'https://graph.microsoft.com/beta/policies/mobileDeviceManagementPolicies'
        $pol = (Graph GET $mdm).value | Where-Object { $_.displayName -match 'Intune' } | Select-Object -First 1
        if ($pol -and "$($pol.appliesTo)" -ne 'none') { & $add 'IntuneEnrollment' 'Automatic Intune enrollment (MDM user scope): back to None' { Graph PATCH "$mdm/$($pol.id)" @{ appliesTo = 'none' } | Out-Null } }
    }
    catch { }
    try {
        $dr = Graph GET 'https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy'
        if ($dr.localAdminPassword.isEnabled -eq $true) { & $add 'Laps' 'Entra LAPS: from enabled to disabled' { Set-DeviceRegPolicy { param($x) $x.localAdminPassword.isEnabled = $false } } }
        if ($dr.azureADJoin.localAdmins.enableGlobalAdmins -eq $false) { & $add 'Laps' 'Global administrators become local admin on joined devices: from No to Yes (Microsoft default)' { Set-DeviceRegPolicy { param($x) $x.azureADJoin.localAdmins.enableGlobalAdmins = $true } } }
    }
    catch { }
    Remove-Items 'TenantSettings' 'tenant-wide settings' $items { param($x) $x.Name } { param($x) & $x.Do } 'https://entra.microsoft.com' 'These settings were changed by Enforce mode. Setting them back returns the Microsoft default, which is usually less strict. Choose one by one if you only want to undo some of them.'
}
function Invoke-Wipe {
    Write-Host ''
    Write-Host 'WIPE mode: removes what this script deployed (matched by the exact ALSO names and markers). Your own policies, groups and labels are never touched.' -ForegroundColor Yellow
    Write-Host 'Tenant-wide settings (user settings, consent, SharePoint sharing, device and Intune enrollment settings) can be set back to Microsoft defaults; you choose which ones.' -ForegroundColor DarkGray
    if (-not $Force -and -not $WhatIfPreference) {
        if ((Read-Host 'Type WIPE to continue, anything else cancels') -ne 'WIPE') { Write-Host 'Cancelled. Nothing was removed.' -ForegroundColor Green; exit 0 }
    }
    try {
        $q0 = [uri]::EscapeDataString("displayName eq '$BreakGlassAuName'")
        $au0 = (Graph GET ('https://graph.microsoft.com/v1.0/directory/administrativeUnits?$filter=' + $q0)).value | Select-Object -First 1
        if ($au0 -and -not $WhatIfPreference -and (Grant-AuAdmin $au0.id) -gt 0) {
            Write-Host "  Added you as Groups Administrator and User Administrator of '$BreakGlassAuName' (needed to delete protected objects). Waiting 45 seconds for it to take effect..." -ForegroundColor DarkGray
            Start-Sleep -Seconds 45
        }
    }
    catch { Write-Host "  Could not assign you to the restricted management unit: $($_.Exception.Message)" -ForegroundColor Yellow }
    if ('BreakGlass' -in $Steps) { Invoke-Safe 'BreakGlass' { Step-WipeRmau } }
    foreach ($s in 'ConditionalAccess', 'IntunePolicies', 'Purview', 'BreakGlass', 'TenantSettings') {
        if ($s -eq 'TenantSettings' -or $s -in $Steps) { Invoke-Safe $s { & "Step-Wipe$s" } }
    }
    Write-Step 'Settings that are left as they are' 'Wipe never switches these off.'
    Add-Result 'GuideManual' 'Settings Wipe leaves unchanged' 'Not reverted' 'Left on purpose' Manual 'https://entra.microsoft.com' 'The unified audit log, passkey (FIDO2) sign-in, security defaults and the other authentication methods stay as they are, because turning them off weakens the tenant and Microsoft keeps them available by default. Change them in the portal if you really want them off.'
}

$basicSkip = 'IntuneEnrollment', 'IntunePolicies', 'ConditionalAccess', 'MdoPresets', 'DefenderEndpoint', 'DefenderGuidance'
if ($Mode -eq 'Wipe') { Invoke-Wipe; $Steps = @() }
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
    IntunePolicies = 'Devices: Intune policy baseline'; TenantSettings = 'Tenant-wide settings (Wipe)'; Purview = 'Data: Microsoft Purview'; GuideManual = 'Other guide steps'
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
        if ($r.Group -and $r.Group -ne $lastGrp) { "<tr class='grp' data-f='grp'><td colspan='5'>$(& $enc $r.Group)</td></tr>" }
        $lastGrp = $r.Group
        $l = if ($r.Link) { "<a href='$(& $enc $r.Link)' target='_blank'>Open in portal &rarr;</a>" } else { '' }
        $d = if ($r.Detail) { "<div class='why'>$(& $enc $r.Detail)$(if ($r.Doc) { " <a href='$(& $enc $r.Doc)' target='_blank'>$(& $enc $r.DocText) &rarr;</a>" })</div>" } else { '' }
        $chg = if ($r.Status -eq 'Drift' -and $r.Current -and $r.Expected) { "<div class='chg'>What will change: from <b>$(& $enc $r.Current)</b> to <b>$(& $enc $r.Expected)</b></div>" } else { '' }
        $grpOf = switch ($r.Status) { 'Drift' { 'todo' } 'Error' { 'todo' } 'Manual' { 'todo' } 'Compliant' { 'ok' } 'Fixed' { 'ok' } default { 'info' } }
        "<tr data-f='$grpOf'><td class='st'><span class='pill $($r.Status)'>$($label[$r.Status])</span></td><td><b>$(& $enc $r.Setting)</b>$chg$d</td><td>$(& $enc $r.Current)</td><td>$(& $enc $r.Expected)</td><td>$l</td></tr>"
    }
    "<section><h2>$(& $enc $cat) $badge</h2><table><tr><th>State</th><th>Setting</th><th>Current value</th><th>Expected</th><th></th></tr>$($rows -join '')</table></section>"
    }
}
$autoSections = & $buildSections $false
$needs = @($reportResults | Where-Object { $_.Status -in 'Drift', 'Error' })
$verdict = if ($needs.Count) { "<div class='verdict bad'><h2>$($needs.Count) setting(s) need your attention</h2><p>Everything else is in good shape or listed for information. Start with the list below, then work through the manual checks tab.</p>" } else { "<div class='verdict good'><h2>All automated checks are in good shape</h2><p>No automated setting needs a change. Review the manual checks tab for the items that need a person.</p>" }
if ($needs.Count) {
    $fi = foreach ($n in ($needs | Select-Object -First 10)) { "<li><b>$(& $enc $n.Setting)</b> &ndash; from <i>$(& $enc ($n.Current -replace '\s+', ' '))</i> to <i>$(& $enc ($n.Expected -replace '\s+', ' '))</i>$(if ($n.Link) { " <a href='$(& $enc $n.Link)' target='_blank'>open &rarr;</a>" })</li>" }
    $verdict += "<h3>Fix first</h3><ol>$($fi -join '')</ol>$(if ($needs.Count -gt 10) { "<p>...and $($needs.Count - 10) more in the sections below.</p>" })"
}
$verdict += '</div>'
$filters = "<div class='filters'>Show: <button class='fl on' data-f='all' onclick=""fl('all')"">Everything</button><button class='fl' data-f='todo' onclick=""fl('todo')"">Needs action</button><button class='fl' data-f='ok' onclick=""fl('ok')"">OK</button><button class='fl' data-f='info' onclick=""fl('info')"">Info</button><button class='fl' onclick='window.print()'>Print / save as PDF</button></div>"
$manualSections = & $buildSections $true
$manualCount = @($reportResults | Where-Object Status -eq 'Manual').Count
$autoCount = $total - $manualCount
$tabs = "<div class='tabs'><button class='tab on' data-t='auto' onclick=""sw('auto')"">Automated checks and actions ($autoCount)</button><button class='tab' data-t='manual' onclick=""sw('manual')"">Manual checks and actions ($manualCount)</button></div>"
$manualIntro = "<p class='intro'>These items cannot be read or changed automatically because Microsoft offers no API for them, or they need a person to decide. Work through them in the portal using the links and guides.</p>"
$js = "function fl(f){document.querySelectorAll('.fl[data-f]').forEach(function(b){b.classList.toggle('on',b.dataset.f===f)});document.querySelectorAll('tr[data-f]').forEach(function(r){r.style.display=(f==='all'||r.dataset.f===f||r.dataset.f==='grp')?'':'none'})}function sw(t){document.querySelectorAll('.pane').forEach(function(e){e.style.display=e.id===t?'block':'none'});document.querySelectorAll('.tab').forEach(function(b){b.classList.toggle('on',b.dataset.t===t)})}"
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
td{white-space:pre-line;padding:9px 8px;border-bottom:1px solid #eef2f6;vertical-align:top;font-size:.9rem;word-break:break-word}td.st{white-space:nowrap}
.why{margin-top:6px;font-size:.82rem;font-weight:400;color:#4a5a6a;line-height:1.45}a{color:#0b5cab;text-decoration:none}a:hover{text-decoration:underline}
.next{background:#fff;border:1px solid #dde3ea;border-left:5px solid #00757d;border-radius:10px;padding:8px 24px 22px;margin:28px 0}.next p{color:#5b6b7c;max-width:760px}.btn{display:inline-block;background:#0b5cab;color:#fff!important;padding:10px 20px;border-radius:8px;font-weight:600}.btn:hover{text-decoration:none;background:#094a8c}
.grp td{background:#eef6f6;font-weight:600;color:#00575d;padding:8px;border-bottom:1px solid #d3e6e7}
.verdict{background:#fff;border:1px solid #dde3ea;border-left:6px solid #2e8b57;border-radius:10px;padding:4px 24px 14px;margin-bottom:22px}.verdict.bad{border-left-color:#d98e04}.verdict h3{margin:14px 0 4px}.verdict ol{margin:4px 0;padding-left:22px;line-height:1.6}.chg{margin-top:4px;font-size:.82rem;color:#7a5200}.filters{margin-bottom:14px;color:#5b6b7c}.fl{border:1px solid #c9d3dd;background:#fff;border-radius:16px;padding:4px 14px;margin-left:6px;cursor:pointer;font-size:.85rem}.fl.on{background:#00757d;color:#fff;border-color:#00757d}@media print{.tabs,.filters,.btn,.next{display:none}.pane{display:block!important}body{background:#fff}}
.pill{display:inline-block;padding:2px 10px;border-radius:12px;font-size:.78rem;font-weight:600;color:#fff;background:#9aa7b4}
.pill.Compliant,.pill.Fixed{background:#2e8b57}.pill.Drift{background:#d98e04}.pill.Manual{background:#00757d}.pill.Error{background:#c0392b}
section.run{border-left:6px solid #00757d}.rbs{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:14px}.rb{border:1px solid #e6ebf0;border-radius:8px;padding:2px 14px 10px;border-top:4px solid #9aa7b4}.rb.Fixed{border-top-color:#2e8b57}.rb.Error{border-top-color:#c0392b}.rb.Drift{border-top-color:#d98e04}.rb.Manual{border-top-color:#00757d}.rb h3{font-size:1rem;margin:10px 0 4px}.rb ul{margin:4px 0;padding-left:20px;font-size:.88rem;line-height:1.5}.rb .none{color:#5b6b7c;font-size:.88rem}
'@
$nextBox = if ($Mode -eq 'Enforce') { "<div class='next'><h2>Done reviewing these settings? Continue with deeper configuration.</h2><p>Secure by Default sets the tenant-wide prerequisites. Next, use the ALSO Microsoft Security Policy Templates Navigator to choose the policy templates and configuration that fit your licenses and platforms.</p><a class='btn' href='https://coc-ms.github.io/ALSO-security-policy-templates-navigator/' target='_blank'>Open the Navigator &rarr;</a></div>" } else { '' }
$runBox = ''
if ($Mode -in 'Enforce', 'Wipe') {
    $verbDone = if ($Mode -eq 'Wipe') { 'Removed' } else { 'Deployed or changed' }
    $fxR = @($reportResults | Where-Object Status -eq 'Fixed'); $erR = @($reportResults | Where-Object Status -eq 'Error')
    $dfR = @($reportResults | Where-Object Status -eq 'Drift'); $skR = @($reportResults | Where-Object Status -eq 'Skipped'); $mnR = @($reportResults | Where-Object Status -eq 'Manual')
    $liBox = {
        param($title, $cls, $rows, $text, $empty)
        $li = foreach ($r in ($rows | Select-Object -First 40)) { "<li><b>$(& $enc $r.Setting)</b>$(& $text $r)</li>" }
        $more = if ($rows.Count -gt 40) { "<p>...and $($rows.Count - 40) more in the tabs below.</p>" } else { '' }
        "<div class='rb $cls'><h3>$title <span class='pill $cls'>$($rows.Count)</span></h3>$(if ($rows.Count) { "<ul>$($li -join '')</ul>$more" } else { "<p class='none'>$empty</p>" })</div>"
    }
    $b1 = & $liBox $verbDone 'Fixed' $fxR { param($r) " &ndash; from <i>$(& $enc ($r.Current -replace '\s+', ' '))</i> to <i>$(& $enc ($r.Expected -replace '\s+', ' '))</i>" } 'Nothing was changed in this run.'
    $b2 = & $liBox 'Failed' 'Error' $erR { param($r) "<div class='why'>Reason: $(& $enc $r.Detail)</div>" } 'No failures.'
    $b3 = & $liBox 'Not applied (you declined, or it was skipped)' 'Drift' @($dfR + $skR) { param($r) " &ndash; $(& $enc ($r.Current -replace '\s+', ' '))" } 'Everything was applied.'
    $b4 = & $liBox 'Still to do by a person' 'Manual' $mnR { param($r) $(if ($r.Link) { " <a href='$(& $enc $r.Link)' target='_blank'>open &rarr;</a>" }) } 'No manual steps remain.'
    $runBox = "<section class='run'><h2>What happened in this run</h2><p class='intro'>This is the result of your $Mode run: what was done, what failed and why, what you left out and what still needs a person. The full details per setting are in the tabs below.</p><div class='rbs'>$b1$b2$b3$b4</div></section>"
}
$page = "<!DOCTYPE html><html><head><meta charset='utf-8'><title>ALSO Secure by Default report</title><style>$css</style></head><body><header><h1>ALSO Secure by Default &ndash; $Mode report</h1><p>$(& $enc $org.displayName) &middot; $(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; $total settings checked</p></header><main>$runBox<div class='cards'>$($cards -join '')</div>$tabs<div class='pane' id='auto'>$filters$($autoSections -join '')</div><div class='pane' id='manual' style='display:none'>$manualIntro$($manualSections -join '')</div>$nextBox</main><script>$js</script></body></html>"
[IO.File]::WriteAllText($html, $page, (New-Object Text.UTF8Encoding($false)))

Write-Host "`nSummary:" -ForegroundColor Cyan
$script:Results | Group-Object Status | ForEach-Object { Write-Host ("  {0,-10} {1}" -f $_.Name, $_.Count) }
Write-Host "Reports: $json`n         $html"
if ($Mode -in 'Enforce', 'Wipe') {
    $fx = @($script:Results | Where-Object Status -eq 'Fixed'); $er = @($script:Results | Where-Object Status -eq 'Error'); $left = @($script:Results | Where-Object { $_.Status -in 'Drift', 'Skipped' }); $mn = @($script:Results | Where-Object Status -eq 'Manual')
    Write-Host "`nWhat happened in this run:" -ForegroundColor Cyan
    Write-Host "  $(if ($Mode -eq 'Wipe') { 'Removed' } else { 'Changed' }) : $($fx.Count)" -ForegroundColor Green; $fx | ForEach-Object { Write-Host "     - $($_.Setting)" -ForegroundColor Green }
    Write-Host "  Failed  : $($er.Count)" -ForegroundColor $(if ($er.Count) { 'Red' } else { 'Gray' }); $er | ForEach-Object { Write-Host "     - $($_.Setting)" -ForegroundColor Red; if ($_.Detail) { Write-Host "         Reason: $($_.Detail)" -ForegroundColor Red } }
    Write-Host "  Not applied (declined or skipped): $($left.Count)" -ForegroundColor $(if ($left.Count) { 'Yellow' } else { 'Gray' }); $left | ForEach-Object { Write-Host "     - $($_.Setting)" -ForegroundColor Yellow }
    Write-Host "  Still to do by a person: $($mn.Count) (see the Manual checks tab in the report)" -ForegroundColor Cyan
}
if ($Mode -eq 'Enforce') {
    Write-Host "`nDone? Continue with deeper configuration in the ALSO Policy Templates Navigator:" -ForegroundColor Cyan
    Write-Host '  https://coc-ms.github.io/ALSO-security-policy-templates-navigator/' -ForegroundColor Cyan
}
try { Invoke-Item $html } catch { Write-Host "Open the HTML report manually: $html" -ForegroundColor Yellow }
if ($Mode -eq 'Discover') {
    $driftSteps = @($script:Results | Where-Object Status -eq 'Drift' | Select-Object -ExpandProperty Step -Unique)
    if ($driftSteps) {
        Write-Host "`nPlanned changes if you continue (nothing has been changed yet):" -ForegroundColor Yellow
        $pn = 0
        foreach ($d in ($script:Results | Where-Object Status -eq 'Drift')) { $pn++; Write-Host ("  {0,2}. {1}: from '{2}' to '{3}'" -f $pn, $d.Setting, (($d.Current -replace '\s+', ' ').Trim()), (($d.Expected -replace '\s+', ' ').Trim())) }
        Write-Host "`nDrift found in: $($driftSteps -join ', ')" -ForegroundColor Yellow
        Write-Host 'Enforce mode asks you to confirm each change (answer 'a' to apply all remaining, or 's' to skip them). It needs a new Global Administrator sign-in with write permissions.'
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

