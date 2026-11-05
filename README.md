# ALSO Secure by Default

Automation script that sets tenant-wide Microsoft 365 settings **not covered by ALSO's JSON configuration files**, so new and existing tenants start from a secure state on day 1. Run discovery (read-only) before enforcing; the script guides you step by step.

```powershell
./scripts/Invoke-SecureByDefault.ps1                       # Discover (read-only)
./scripts/Invoke-SecureByDefault.ps1 -Mode Enforce -WhatIf # dry run
./scripts/Invoke-SecureByDefault.ps1 -Mode Enforce         # guided enforcement
```

## Technology choice
PowerShell 7+: Microsoft Graph, Exchange Online and SharePoint Online are only fully covered by PowerShell modules; Python has no equivalent for Exchange/SPO. Microsoft365DSC is recommended afterwards for drift control; its resources (`AADAuthorizationPolicy`, `AADAuthenticationMethodPolicyFido2`, `EXOAdminAuditLogConfig`, `SPOTenantSettings`, ...) mirror these settings.

## Steps
`AuditLog`, `UserSettings`, `Consent`, `BreakGlass`, `Fido2`, `AuthMethods`, `SharePoint`, `IntuneEnrollment`, `Laps`, `MdoPresets`, `DefenderEndpoint`, `DefenderGuidance` (select with `-Steps`).
Settings without an API (Entra admin center restriction, LinkedIn, keep-signed-in, Defender Intune toggle) are reported as **Manual** with a direct portal link.

Reference values live in `config/reference-state.json`; review them for your organization. Reports (JSON + HTML) go to `./sbd-reports`.

## Safety
- Discover mode requests read-only Graph scopes and changes nothing.
- Break-glass passwords are shown once on the console, never logged. Manual follow-ups: FIDO2 keys/TAP, Conditional Access exclusions and emergency-access policy (report-only first), SSPR exclusion, sign-in alerting.
- Windows LAPS policy must still be deployed via Intune.

## GitHub Pages
Site in `docs/`, deployed by `.github/workflows/pages.yml` (Settings > Pages > Source: GitHub Actions). `docs/also-logo.svg` is a placeholder wordmark; replace it with the official ALSO logo.
