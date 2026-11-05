# ALSO Secure by Default

Automation script that sets tenant-wide Microsoft 365 settings **not covered by ALSO's JSON configuration files**, so new and existing tenants start from a secure state on day 1. Run discovery (read-only) before enforcing; the script guides you step by step.

```powershell
./scripts/Invoke-SecureByDefault.ps1                       # Discover (read-only)
./scripts/Invoke-SecureByDefault.ps1 -Mode Enforce -WhatIf # dry run
./scripts/Invoke-SecureByDefault.ps1 -Mode Enforce         # guided enforcement
./scripts/Invoke-SecureByDefault.ps1 -Engine Dsc -TenantId <id> -ApplicationId <id> -CertificateThumbprint <thumb>   # native Microsoft365DSC
./scripts/Invoke-SecureByDefault.ps1 -Engine Python        # Graph-only, cross-platform
```

**Prerequisites:** PowerShell 7+ (5.1 for `-Engine Dsc`), a Global Administrator account, modules install to the current user on demand. Always run Discover first and review `sbd-reports\*.html`. Site: https://coc-ms.github.io/ALSO-Microsoft-Security-SecureByDefault/ (Settings > Pages > Source: GitHub Actions).
```

## Engines (one shared reference state: `config/reference-state.json`)
| Engine | File | Best for |
| --- | --- | --- |
| PowerShell orchestrator | `scripts/Invoke-SecureByDefault.ps1` | Full coverage: Graph + Exchange Online + SharePoint, guided, HTML/JSON report |
| Native Microsoft365DSC | `scripts/Invoke-SecureByDefaultDsc.ps1` + `dsc/SecureByDefault.dsc.ps1` | Declarative baseline and drift control. Discover = `Test-DscConfiguration`, Enforce = `Start-DscConfiguration`. Needs Windows PowerShell 5.1, an Entra app + certificate. Covers audit log, user settings/consent, admin consent workflow, FIDO2, SharePoint sharing, Entra LAPS |
| Python (Graph-only) | `python/sbd_graph.py` | Cross-platform/CI checks of Entra, consent, FIDO2, LAPS, Intune enrollment. Exchange/SharePoint have no Python SDK |

PowerShell is the primary engine because only it reaches every workload. DSC resources used: `O365AdminAuditLogConfig`, `AADAuthorizationPolicy`, `AADAdminConsentRequestPolicy`, `AADAuthenticationMethodPolicyFido2`, `SPOSharingSettings`, `AADDeviceRegistrationPolicy`. Microsoft365DSC also ships Defender resources (`DefenderDeviceAuthenticatedScanDefinition`, `DefenderRoleDefinition`, `DefenderSubscriptionPlan`) and `IntuneMobileThreatDefenseConnector` for further extension.

> The DSC and Python engines have only been syntax-checked, not run against a tenant. Run Discover first.
## Steps
`AuditLog`, `UserSettings`, `Consent`, `BreakGlass`, `Fido2`, `AuthMethods`, `SharePoint`, `IntuneEnrollment`, `Laps`, `MdoPresets`, `DefenderEndpoint`, `DefenderGuidance` (select with `-Steps`).
Settings without an API (Entra admin center restriction, LinkedIn, keep-signed-in, Defender Intune toggle) are reported as **Manual** with a direct portal link.

Reference values live in `config/reference-state.json`; review them for your organization. Reports (JSON + HTML) go to `./sbd-reports`.

## Safety
- Discover mode requests read-only Graph scopes and changes nothing.
- Break-glass passwords are shown once on the console, never logged. Manual follow-ups: FIDO2 keys/TAP, Conditional Access exclusions and emergency-access policy (report-only first), SSPR exclusion, sign-in alerting.
- Windows LAPS policy must still be deployed via Intune.

## GitHub Pages
Site in `docs/`, deployed by `.github/workflows/pages.yml` (Settings > Pages > Source: GitHub Actions). `docs/also-logo.png` is the ALSO logo, copied from CoC-MS/ALSO-security-policy-templates-navigator.



