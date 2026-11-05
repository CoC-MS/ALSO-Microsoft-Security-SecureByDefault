# ALSO Secure by Default (Public Preview)

An automation script that sets the tenant-wide Microsoft 365 settings **not covered by ALSO's JSON configuration files**, so new and existing tenants start from a secure state on day 1. It runs in read-only discovery mode first and guides you step by step before changing anything.

Site: https://coc-ms.github.io/ALSO-Microsoft-Security-SecureByDefault/

## How to run

**A Global Administrator account is required** for all steps (discovery warns if you are not one; enforcement stops). Everything the script needs is installed for the current user on demand.

On first run the sign-in uses Microsoft's "Microsoft Graph Command Line Tools" enterprise application. Approve the permission request as Global Administrator ("Consent on behalf of your organization"); it then appears under Entra > Enterprise applications. Each sign-in is an interactive browser sign-in (no device code); before every one the script states which service it is for and what access it needs.

If scripts are blocked on your machine, allow them for this session only: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`. Do not run from `C:\Windows\System32`; clone to a normal folder.

```powershell
git clone https://github.com/CoC-MS/ALSO-Microsoft-Security-SecureByDefault
cd ALSO-Microsoft-Security-SecureByDefault

./scripts/Invoke-SecureByDefault.ps1                        # 1. discovery (read-only)
./scripts/Invoke-SecureByDefault.ps1 -Mode Enforce          # 2. guided enforcement (all, one by one or per Purview part)
./scripts/Invoke-SecureByDefault.ps1 -Mode Wipe             # 3. optional: remove what the script deployed
```

Run it from PowerShell 7 as administrator. The report has two tabs: Automated checks and actions, and Manual checks and actions. In Enforce mode you can apply changes one by one, apply all remaining, and deploy policies all at once or one by one. Existing Conditional Access, Intune and Purview policies are listed and never changed.

Run a subset of steps with `-Steps AuditLog,Fido2`. Reports are written to `sbd-reports` as HTML and JSON.

## What it covers

Unified audit log, Entra user and external collaboration settings, user consent, emergency access accounts (security group and restricted management administrative unit), FIDO2 and authentication methods, SharePoint sharing, Conditional Access baseline import (switched off), administrator role and access review checks, Intune enrollment, the Intune policy baseline (compliance, app protection, BitLocker, LAPS, Defender, Edge), Defender for Office 365 preset policies, Microsoft Purview (existing labels, label policies, DLP and retention compared with the ALSO baseline, SharePoint label settings, and deployment of what is missing), the other steps of the ALSO Copilot readiness guide, and Defender for Business / Endpoint provisioning checks with Intune connection guidance.

Expected values live in `config/reference-state.json`. Review them against your organization's requirements before enforcing.

## Safety

- Default mode is read-only and changes nothing.
- Passwords are shown once on the console and never written to reports.
- Settings that can only be changed in the portal are reported with a direct link.

## Next step

Continue with deeper configuration in the [ALSO Microsoft Security Policy Templates Navigator](https://coc-ms.github.io/ALSO-security-policy-templates-navigator/).

The logo is copied from the Navigator repository.

Sign-ins: up to three browser sign-ins (Microsoft Graph, Exchange, Purview), each explained before it opens. Enforce ends with a *What happened in this run* summary (changed, failed with reason, not applied, manual steps left). Wipe removes Conditional Access policies, Intune policies, Purview items and the break-glass accounts the script deployed; you choose all, one by one or none per category, and must type WIPE. Tenant-wide settings are not reverted.
