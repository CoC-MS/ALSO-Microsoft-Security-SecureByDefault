<#
.SYNOPSIS
  Microsoft365DSC configuration for the Secure by Default settings that can be expressed declaratively.
  Values come from config/reference-state.json. Compile and run with scripts/Invoke-SecureByDefaultDsc.ps1.
#>
Configuration SecureByDefault {
    param(
        [Parameter(Mandatory)][string]$ApplicationId,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$CertificateThumbprint,
        [Parameter(Mandatory)]$Reference,
        [string[]]$Steps = @('AuditLog', 'UserSettings', 'Consent', 'Fido2', 'SharePoint', 'Laps')
    )
    Import-DscResource -ModuleName Microsoft365DSC

    Node localhost {
        if ('AuditLog' -in $Steps) {
            O365AdminAuditLogConfig AuditLog {
                IsSingleInstance                = 'Yes'
                UnifiedAuditLogIngestionEnabled = 'Enabled'
                ApplicationId                   = $ApplicationId
                TenantId                        = $TenantId
                CertificateThumbprint           = $CertificateThumbprint
            }
        }

        # One authorizationPolicy instance covers user settings, guest access and user consent.
        if ('UserSettings' -in $Steps -or 'Consent' -in $Steps) {
            $u = $Reference.userSettings
            AADAuthorizationPolicy AuthorizationPolicy {
                IsSingleInstance                                  = 'Yes'
                DefaultUserRolePermissions                        = MSFT_DefaultUserRolePermissions {
                    AllowedToCreateApps                    = $u.usersCanRegisterApps
                    AllowedToCreateAgentIdentityBlueprints = $u.usersCanRegisterAgentBlueprints
                    AllowedToCreateSecurityGroups          = $u.usersCanCreateSecurityGroups
                    AllowedToCreateTenants                 = (-not $u.restrictTenantCreation)
                }
                GuestUserRole                                     = 'Guest' # limited access to directory objects
                PermissionGrantPolicyIdsAssignedToDefaultUserRole = @($Reference.consent.userConsentPolicy)
                Ensure                                            = 'Present'
                ApplicationId                                     = $ApplicationId
                TenantId                                          = $TenantId
                CertificateThumbprint                             = $CertificateThumbprint
            }
        }

        if ('Consent' -in $Steps) {
            AADAdminConsentRequestPolicy AdminConsent {
                IsSingleInstance      = 'Yes'
                IsEnabled             = $true
                NotifyReviewers       = $true
                RemindersEnabled      = $true
                RequestDurationInDays = $Reference.consent.requestDurationInDays
                Reviewers             = @(MSFT_AADAdminConsentRequestPolicyReviewer {
                        ReviewerType = 'Role'
                        ReviewerId   = 'Global Administrator'
                    })
                ApplicationId         = $ApplicationId
                TenantId              = $TenantId
                CertificateThumbprint = $CertificateThumbprint
            }
        }

        if ('Fido2' -in $Steps) {
            AADAuthenticationMethodPolicyFido2 Fido2 {
                Id                               = 'Fido2'
                State                            = 'enabled'
                IsSelfServiceRegistrationAllowed = $true
                IsAttestationEnforced            = $false
                IncludeTargets                   = @(MSFT_AADAuthenticationMethodPolicyFido2IncludeTarget {
                        Id         = 'all_users'
                        TargetType = 'group'
                    })
                Ensure                           = 'Present'
                ApplicationId                    = $ApplicationId
                TenantId                         = $TenantId
                CertificateThumbprint            = $CertificateThumbprint
            }
        }

        if ('SharePoint' -in $Steps) {
            SPOSharingSettings Sharing {
                IsSingleInstance       = 'Yes'
                SharingCapability      = $Reference.sharePoint.sharingCapability
                DefaultSharingLinkType = $Reference.sharePoint.defaultSharingLinkType
                ApplicationId          = $ApplicationId
                TenantId               = $TenantId
                CertificateThumbprint  = $CertificateThumbprint
            }
        }

        if ('Laps' -in $Steps) {
            AADDeviceRegistrationPolicy DeviceRegistration {
                IsSingleInstance                      = 'Yes'
                LocalAdminPasswordIsEnabled           = $true
                LocalAdminsEnableGlobalAdmins         = $false
                AzureAdJoinLocalAdminsRegisteringMode = 'None'
                ApplicationId                         = $ApplicationId
                TenantId                              = $TenantId
                CertificateThumbprint                 = $CertificateThumbprint
            }
        }
    }
}

