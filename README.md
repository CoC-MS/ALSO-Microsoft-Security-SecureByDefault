# ALSO Secure by Default (Public Preview)

An automation script that sets the tenant-wide Microsoft 365 settings **not covered by ALSO's JSON configuration files**, so new and existing tenants start from a secure state on day 1. It runs in read-only discovery mode first and guides you step by step before changing anything.

Site: https://coc-ms.github.io/ALSO-Microsoft-Security-SecureByDefault/

## How to run

You need a Global Administrator (or equivalent) account. Everything the script needs is installed for the current user on demand.

```powershell
git clone https://github.com/CoC-MS/ALSO-Microsoft-Security-SecureByDefault
cd ALSO-Microsoft-Security-SecureByDefault

./scripts/Invoke-SecureByDefault.ps1                        # 1. discovery (read-only)
./scripts/Invoke-SecureByDefault.ps1 -Mode Enforce -WhatIf  # 2. dry run
./scripts/Invoke-SecureByDefault.ps1 -Mode Enforce          # 3. guided enforcement
```

Run a subset of steps with `-Steps AuditLog,Fido2`. Reports are written to `sbd-reports` as HTML and JSON.

## What it covers

Unified audit log, Entra user and external collaboration settings, user consent, emergency access accounts (security group and restricted management administrative unit), FIDO2 and authentication methods, SharePoint sharing, Intune enrollment, Windows LAPS, Defender for Office 365 preset policies, and Defender for Business / Endpoint provisioning checks with Intune connection guidance.

Expected values live in `config/reference-state.json`. Review them against your organization's requirements before enforcing.

## Safety

- Default mode is read-only and changes nothing.
- Passwords are shown once on the console and never written to reports.
- Settings that can only be changed in the portal are reported with a direct link.

## Next step

Continue with deeper configuration in the [ALSO Microsoft Security Policy Templates Navigator](https://coc-ms.github.io/ALSO-security-policy-templates-navigator/).

The logo is copied from the Navigator repository.
