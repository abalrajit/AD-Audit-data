#Requires -Version 5.1
<#
.SYNOPSIS
    Multi-domain security audit: Active Directory, Entra ID, Microsoft 365, Endpoint, and Endpoint DLP.

.DESCRIPTION
    Modular audit script that checks common security misconfigurations across on-prem AD,
    Entra ID (Azure AD), M365 (Exchange Online / SharePoint Online), endpoint (Defender /
    local hardening), and Purview Endpoint DLP. Produces a single self-contained HTML report
    with severity-ranked findings.

    Run each domain independently with -Skip switches, or run the whole thing.
    Designed to be run by a domain/tenant admin with appropriate read permissions.

.PARAMETER OutputPath
    Path for the generated HTML report. Defaults to a timestamped file in the current folder.

.PARAMETER SkipAD / SkipEntra / SkipM365 / SkipEndpoint / SkipDLP
    Skip a given audit domain (e.g. if you don't have RSAT / relevant module access on this box).

.PARAMETER StaleDays
    Days of inactivity before an AD/Entra account is flagged as stale. Default 90.

.NOTES
    Required modules (only for the domains you run):
      AD          : RSAT ActiveDirectory module
      Entra ID    : Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement,
                    Microsoft.Graph.Users, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Applications
      M365        : ExchangeOnlineManagement, Microsoft.Online.SharePoint.PowerShell
      Endpoint DLP: ExchangeOnlineManagement (for Connect-IPPSSession / Security & Compliance cmdlets)

    Auth: Entra ID / M365 / DLP checks use interactive delegated sign-in (Connect-MgGraph,
    Connect-ExchangeOnline, Connect-SPOService, Connect-IPPSSession). For unattended/scheduled
    runs, swap these for certificate-based app-only auth (see comments near each Connect- call).

    Run with an account that has, at minimum: Global Reader (Entra), View-Only Audit Logs /
    Compliance Administrator (M365/DLP), and Domain Admins or delegated read rights (AD).
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\SecurityAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    [switch]$SkipAD,
    [switch]$SkipEntra,
    [switch]$SkipM365,
    [switch]$SkipEndpoint,
    [switch]$SkipDLP,
    [int]$StaleDays = 90
)

# ============================================================================
# GLOBAL STATE
# ============================================================================

$Global:Findings = [System.Collections.Generic.List[PSObject]]::new()

function Add-Finding {
    <#
        Central logging function. Every check funnels through here so the report
        stays consistent. Severity: Info | Low | Medium | High | Critical
    #>
    param(
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('Info','Low','Medium','High','Critical')][string]$Severity,
        [Parameter(Mandatory)][ValidateSet('Pass','Finding','Error','Skipped')][string]$Status,
        [string]$Details = '',
        [string]$Recommendation = '',
        [int]$Count = -1
    )
    $Global:Findings.Add([PSCustomObject]@{
        Domain         = $Domain
        Check          = $Check
        Severity       = $Severity
        Status         = $Status
        Count          = $Count
        Details        = $Details
        Recommendation = $Recommendation
        Timestamp      = Get-Date
    })
}

function Test-ModuleAvailable {
    param([Parameter(Mandatory)][string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Warning "Module '$Name' not found. Install with: Install-Module $Name -Scope CurrentUser"
        return $false
    }
    return $true
}

# ============================================================================
# 1. ACTIVE DIRECTORY AUDIT
# ============================================================================

function Invoke-ADAudit {
    Write-Host "`n[AD] Starting Active Directory audit..." -ForegroundColor Cyan

    if (-not (Test-ModuleAvailable -Name ActiveDirectory)) {
        Add-Finding -Domain 'Active Directory' -Check 'Module availability' -Severity Info -Status Error `
            -Details 'ActiveDirectory RSAT module not installed on this host.' `
            -Recommendation 'Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
        return
    }
    Import-Module ActiveDirectory -ErrorAction Stop

    # --- Domain / forest posture ---
    try {
        $domain = Get-ADDomain
        $forest = Get-ADForest
        Add-Finding -Domain 'Active Directory' -Check 'Domain/Forest functional level' -Severity Info -Status Pass `
            -Details "Domain: $($domain.DomainMode); Forest: $($forest.ForestMode)"
    } catch {
        Add-Finding -Domain 'Active Directory' -Check 'Domain/Forest functional level' -Severity Info -Status Error -Details $_.Exception.Message
    }

    # --- Password policy ---
    try {
        $pp = Get-ADDefaultDomainPasswordPolicy
        $sev = if ($pp.MinPasswordLength -lt 14) { 'Medium' } else { 'Info' }
        $status = if ($pp.MinPasswordLength -lt 14) { 'Finding' } else { 'Pass' }
        Add-Finding -Domain 'Active Directory' -Check 'Default password policy' -Severity $sev -Status $status `
            -Details "MinLength=$($pp.MinPasswordLength), Complexity=$($pp.ComplexityEnabled), LockoutThreshold=$($pp.LockoutThreshold), MaxAge=$($pp.MaxPasswordAge)" `
            -Recommendation 'NIST/CIS guidance: 14+ char minimum, account lockout after 5-10 attempts, consider passphrase-based policy over frequent rotation.'
    } catch { Add-Finding -Domain 'Active Directory' -Check 'Default password policy' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- Privileged group membership ---
    $privGroups = 'Domain Admins','Enterprise Admins','Schema Admins','Administrators'
    foreach ($g in $privGroups) {
        try {
            $members = Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | Where-Object objectClass -eq 'user'
            $sev = if ($members.Count -gt 5) { 'High' } elseif ($members.Count -gt 0) { 'Medium' } else { 'Info' }
            Add-Finding -Domain 'Active Directory' -Check "Privileged group: $g" -Severity $sev -Status Finding `
                -Count $members.Count -Details ($members.SamAccountName -join ', ') `
                -Recommendation "Review membership of '$g' regularly; enforce least privilege and use PAM/JIT elevation (e.g. LAPS, Just Enough Administration, or a PAW model) instead of standing membership."
        } catch { Add-Finding -Domain 'Active Directory' -Check "Privileged group: $g" -Severity Info -Status Error -Details $_.Exception.Message }
    }

    # --- Stale user accounts ---
    try {
        $cutoff = (Get-Date).AddDays(-$StaleDays)
        $stale = Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonTimestamp |
            Where-Object { $_.LastLogonTimestamp -and [DateTime]::FromFileTime($_.LastLogonTimestamp) -lt $cutoff }
        $sev = if ($stale.Count -gt 0) { 'Medium' } else { 'Info' }
        Add-Finding -Domain 'Active Directory' -Check "Stale enabled accounts (no logon $StaleDays+ days)" -Severity $sev `
            -Status $(if ($stale.Count -gt 0) {'Finding'} else {'Pass'}) -Count $stale.Count `
            -Details ($stale.SamAccountName -join ', ') `
            -Recommendation 'Disable or remove stale accounts to shrink attack surface. Automate via a periodic access review.'
    } catch { Add-Finding -Domain 'Active Directory' -Check 'Stale accounts' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- Password never expires ---
    try {
        $pne = Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } -Properties PasswordNeverExpires
        $sev = if ($pne.Count -gt 0) { 'Medium' } else { 'Info' }
        Add-Finding -Domain 'Active Directory' -Check 'Accounts with PasswordNeverExpires' -Severity $sev `
            -Status $(if ($pne.Count -gt 0) {'Finding'} else {'Pass'}) -Count $pne.Count -Details ($pne.SamAccountName -join ', ') `
            -Recommendation 'Reserve for true service accounts (and prefer gMSA instead). Flag any human accounts with this set.'
    } catch { Add-Finding -Domain 'Active Directory' -Check 'PasswordNeverExpires' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- Kerberoastable accounts (SPN on user objects) ---
    try {
        $spnUsers = Get-ADUser -Filter { ServicePrincipalName -like '*' } -Properties ServicePrincipalName
        $sev = if ($spnUsers.Count -gt 0) { 'High' } else { 'Info' }
        Add-Finding -Domain 'Active Directory' -Check 'Kerberoastable accounts (user SPNs)' -Severity $sev `
            -Status $(if ($spnUsers.Count -gt 0) {'Finding'} else {'Pass'}) -Count $spnUsers.Count -Details ($spnUsers.SamAccountName -join ', ') `
            -Recommendation 'User accounts with SPNs are Kerberoastable offline. Move service accounts to gMSA, or ensure passwords are 25+ random characters and rotated.'
    } catch { Add-Finding -Domain 'Active Directory' -Check 'Kerberoastable accounts' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- AS-REP roastable accounts ---
    try {
        $asrep = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } -Properties DoesNotRequirePreAuth
        $sev = if ($asrep.Count -gt 0) { 'High' } else { 'Info' }
        Add-Finding -Domain 'Active Directory' -Check 'AS-REP roastable accounts (Kerberos pre-auth disabled)' -Severity $sev `
            -Status $(if ($asrep.Count -gt 0) {'Finding'} else {'Pass'}) -Count $asrep.Count -Details ($asrep.SamAccountName -join ', ') `
            -Recommendation 'Re-enable Kerberos pre-authentication unless there is a specific, documented reason not to.'
    } catch { Add-Finding -Domain 'Active Directory' -Check 'AS-REP roastable' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- Reversible encryption / empty password allowed ---
    try {
        $bad = Get-ADUser -Filter { AllowReversiblePasswordEncryption -eq $true -or PasswordNotRequired -eq $true } -Properties AllowReversiblePasswordEncryption,PasswordNotRequired
        $sev = if ($bad.Count -gt 0) { 'Critical' } else { 'Info' }
        Add-Finding -Domain 'Active Directory' -Check 'Reversible encryption / password not required' -Severity $sev `
            -Status $(if ($bad.Count -gt 0) {'Finding'} else {'Pass'}) -Count $bad.Count -Details ($bad.SamAccountName -join ', ') `
            -Recommendation 'These flags should almost never be set. Remove immediately unless a documented legacy app requirement exists.'
    } catch { Add-Finding -Domain 'Active Directory' -Check 'Reversible encryption' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- Domain Controller OS currency + SMBv1 ---
    try {
        $dcs = Get-ADDomainController -Filter *
        $oldOS = $dcs | Where-Object { $_.OperatingSystem -match '2008|2012(?! R2)' }
        $sev = if ($oldOS.Count -gt 0) { 'High' } else { 'Info' }
        Add-Finding -Domain 'Active Directory' -Check 'Domain Controller OS currency' -Severity $sev `
            -Status $(if ($oldOS.Count -gt 0) {'Finding'} else {'Pass'}) -Count $oldOS.Count `
            -Details (($dcs | Select-Object HostName,OperatingSystem | ForEach-Object { "$($_.HostName): $($_.OperatingSystem)" }) -join '; ') `
            -Recommendation 'Upgrade or decommission out-of-support DC operating systems.'
    } catch { Add-Finding -Domain 'Active Directory' -Check 'DC OS currency' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- LAPS deployment check ---
    try {
        $lapsSchema = Get-ADObject -Filter { name -eq 'ms-Mcs-AdmPwd' } -ErrorAction SilentlyContinue
        $windowsLaps = Get-ADObject -Filter { name -eq 'ms-LAPS-Password' } -ErrorAction SilentlyContinue
        if ($lapsSchema -or $windowsLaps) {
            Add-Finding -Domain 'Active Directory' -Check 'LAPS schema present' -Severity Info -Status Pass -Details 'Legacy or Windows LAPS schema extension detected.'
        } else {
            Add-Finding -Domain 'Active Directory' -Check 'LAPS schema present' -Severity High -Status Finding `
                -Details 'No LAPS schema extension found.' `
                -Recommendation 'Deploy Windows LAPS (built into Windows 11/Server 2022+) to randomize and rotate local admin passwords.'
        }
    } catch { Add-Finding -Domain 'Active Directory' -Check 'LAPS' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- Domain/forest trusts ---
    try {
        $trusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue
        if ($trusts) {
            $trustDetails = ($trusts | ForEach-Object { "$($_.Name) ($($_.Direction))" }) -join '; '
            Add-Finding -Domain 'Active Directory' -Check 'Domain/forest trusts' -Severity Medium -Status Finding `
                -Count $trusts.Count -Details $trustDetails `
                -Recommendation 'Confirm each trust is still required, and check SID filtering / selective authentication is enabled where appropriate.'
        } else {
            Add-Finding -Domain 'Active Directory' -Check 'Domain/forest trusts' -Severity Info -Status Pass -Details 'No trusts configured.'
        }
    } catch { Add-Finding -Domain 'Active Directory' -Check 'Trusts' -Severity Info -Status Error -Details $_.Exception.Message }
}

# ============================================================================
# 2. ENTRA ID AUDIT
# ============================================================================

function Invoke-EntraIDAudit {
    Write-Host "`n[Entra ID] Starting Entra ID audit..." -ForegroundColor Cyan

    $requiredModules = 'Microsoft.Graph.Authentication','Microsoft.Graph.Identity.DirectoryManagement',
                        'Microsoft.Graph.Users','Microsoft.Graph.Identity.SignIns','Microsoft.Graph.Applications'
    $missing = $requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }
    if ($missing) {
        Add-Finding -Domain 'Entra ID' -Check 'Module availability' -Severity Info -Status Error `
            -Details "Missing modules: $($missing -join ', ')" `
            -Recommendation "Install-Module $($missing -join ',') -Scope CurrentUser"
        return
    }

    try {
        # Delegated interactive sign-in. For scheduled/unattended runs, replace with:
        # Connect-MgGraph -ClientId <appId> -TenantId <tenantId> -CertificateThumbprint <thumbprint>
        Connect-MgGraph -Scopes 'User.Read.All','Directory.Read.All','Policy.Read.All','UserAuthenticationMethod.Read.All','Application.Read.All','AuditLog.Read.All' -NoWelcome -ErrorAction Stop
    } catch {
        Add-Finding -Domain 'Entra ID' -Check 'Connect-MgGraph' -Severity Info -Status Error -Details $_.Exception.Message
        return
    }

    # --- Security defaults ---
    try {
        $secDefaults = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
        $enabled = $secDefaults.isEnabled
        Add-Finding -Domain 'Entra ID' -Check 'Security Defaults' -Severity Info -Status Pass `
            -Details "Security Defaults enabled: $enabled. Note: if Conditional Access is in use, Security Defaults is typically off by design — that's expected, not a finding on its own."
    } catch { Add-Finding -Domain 'Entra ID' -Check 'Security Defaults' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- Conditional Access policy coverage ---
    try {
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All
        $enabledCA = $caPolicies | Where-Object { $_.State -eq 'enabled' }
        $mfaPolicies = $enabledCA | Where-Object { $_.GrantControls.BuiltInControls -contains 'mfa' }
        if ($enabledCA.Count -eq 0) {
            Add-Finding -Domain 'Entra ID' -Check 'Conditional Access policies' -Severity High -Status Finding `
                -Details 'No enabled Conditional Access policies found.' `
                -Recommendation 'Deploy baseline CA policies: require MFA for admins, require MFA for all users, block legacy auth, require compliant/hybrid-joined device or MFA for high-risk sign-ins.'
        } else {
            Add-Finding -Domain 'Entra ID' -Check 'Conditional Access policies' -Severity Info -Status Pass `
                -Count $enabledCA.Count -Details "$($enabledCA.Count) enabled policies, $($mfaPolicies.Count) enforce MFA."
        }
    } catch { Add-Finding -Domain 'Entra ID' -Check 'Conditional Access' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- Legacy authentication blocking ---
    try {
        $legacyBlock = $caPolicies | Where-Object {
            $_.State -eq 'enabled' -and $_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -and $_.GrantControls.BuiltInControls -contains 'block'
        }
        if (-not $legacyBlock) {
            Add-Finding -Domain 'Entra ID' -Check 'Legacy authentication blocked' -Severity High -Status Finding `
                -Details 'No CA policy found that explicitly blocks legacy authentication protocols.' `
                -Recommendation 'Legacy auth (POP/IMAP/SMTP AUTH/older Office clients) bypasses MFA. Block it via Conditional Access, then disable at the tenant/mailbox level.'
        } else {
            Add-Finding -Domain 'Entra ID' -Check 'Legacy authentication blocked' -Severity Info -Status Pass -Details 'Legacy auth block policy present.'
        }
    } catch { Add-Finding -Domain 'Entra ID' -Check 'Legacy auth block' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- MFA registration status ---
    try {
        $regDetails = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999'
        $users = $regDetails.value
        $noMfa = $users | Where-Object { -not $_.isMfaRegistered -and -not $_.isAdmin -eq $false }
        $noMfaCount = ($users | Where-Object { -not $_.isMfaRegistered }).Count
        $adminNoMfa = ($users | Where-Object { $_.isAdmin -and -not $_.isMfaRegistered }).Count
        $sev = if ($adminNoMfa -gt 0) { 'Critical' } elseif ($noMfaCount -gt 0) { 'High' } else { 'Info' }
        Add-Finding -Domain 'Entra ID' -Check 'MFA registration coverage' -Severity $sev `
            -Status $(if ($noMfaCount -gt 0) {'Finding'} else {'Pass'}) -Count $noMfaCount `
            -Details "$noMfaCount of $($users.Count) users not MFA-registered; $adminNoMfa of those are admins." `
            -Recommendation 'Every admin account must have MFA. Drive toward phishing-resistant MFA (FIDO2/Windows Hello/certificate) for privileged roles.'
    } catch { Add-Finding -Domain 'Entra ID' -Check 'MFA registration' -Severity Info -Status Error -Details "$($_.Exception.Message) (requires Entra ID P1/P2 reporting access)" }

    # --- Privileged role assignment counts ---
    try {
        $globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
        if ($globalAdminRole) {
            $gaMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id
            $sev = if ($gaMembers.Count -gt 5) { 'High' } elseif ($gaMembers.Count -gt 2) { 'Medium' } else { 'Info' }
            Add-Finding -Domain 'Entra ID' -Check 'Global Administrator count' -Severity $sev `
                -Status $(if ($gaMembers.Count -gt 2) {'Finding'} else {'Pass'}) -Count $gaMembers.Count `
                -Recommendation 'Microsoft recommends fewer than 5 Global Admins, ideally 2-4 with break-glass accounts excluded and PIM (Privileged Identity Management) used for JIT elevation instead of standing assignment.'
        }
    } catch { Add-Finding -Domain 'Entra ID' -Check 'Global Admin count' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- Guest users ---
    try {
        $guests = Get-MgUser -Filter "userType eq 'Guest'" -All -ConsistencyLevel eventual -CountVariable gc
        Add-Finding -Domain 'Entra ID' -Check 'Guest user count' -Severity Info -Status Finding -Count $guests.Count `
            -Details "$($guests.Count) guest accounts in tenant." `
            -Recommendation 'Ensure access reviews are configured for guests (Entra ID Governance) and that guest access to sensitive resources is time-bound.'
    } catch { Add-Finding -Domain 'Entra ID' -Check 'Guest users' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- App registrations with high-privilege API permissions ---
    try {
        $apps = Get-MgApplication -All
        $risky = $apps | Where-Object {
            $_.RequiredResourceAccess.ResourceAccess.Id -and ($_.RequiredResourceAccess | Where-Object { $_.ResourceAccess.Type -contains 'Role' })
        }
        Add-Finding -Domain 'Entra ID' -Check 'App registrations with application (role) permissions' -Severity Medium -Status Finding `
            -Count $risky.Count -Details ($risky.DisplayName -join ', ') `
            -Recommendation 'Application permissions (as opposed to delegated) run unattended with no user context. Review each for least-privilege scoping and owner accountability.'
    } catch { Add-Finding -Domain 'Entra ID' -Check 'App registrations' -Severity Info -Status Error -Details $_.Exception.Message }
}

# ============================================================================
# 3. M365 AUDIT (Exchange Online + SharePoint Online)
# ============================================================================

function Invoke-M365Audit {
    Write-Host "`n[M365] Starting Microsoft 365 audit..." -ForegroundColor Cyan

    if (-not (Test-ModuleAvailable -Name ExchangeOnlineManagement)) {
        Add-Finding -Domain 'M365' -Check 'Module availability' -Severity Info -Status Error `
            -Details 'ExchangeOnlineManagement module not installed.' -Recommendation 'Install-Module ExchangeOnlineManagement -Scope CurrentUser'
        return
    }

    try {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
    } catch {
        Add-Finding -Domain 'M365' -Check 'Connect-ExchangeOnline' -Severity Info -Status Error -Details $_.Exception.Message
        return
    }

    # --- Unified audit log ---
    try {
        $orgConfig = Get-OrganizationConfig
        if (-not $orgConfig.AuditDisabled) {
            Add-Finding -Domain 'M365' -Check 'Unified Audit Log' -Severity Info -Status Pass -Details 'Audit logging enabled.'
        } else {
            Add-Finding -Domain 'M365' -Check 'Unified Audit Log' -Severity High -Status Finding `
                -Details 'Unified Audit Log is disabled.' -Recommendation 'Enable via Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true. Without it, you lose forensic visibility across the tenant.'
        }
    } catch { Add-Finding -Domain 'M365' -Check 'Unified Audit Log' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- Mailbox forwarding to external domains ---
    try {
        $tenantDomains = (Get-AcceptedDomain).DomainName
        $mailboxes = Get-Mailbox -ResultSize Unlimited
        $extForward = $mailboxes | Where-Object {
            $_.ForwardingSmtpAddress -and ($tenantDomains | Where-Object { $_.ForwardingSmtpAddress -notmatch $_ }).Count -eq $tenantDomains.Count
        }
        $sev = if ($extForward.Count -gt 0) { 'Critical' } else { 'Info' }
        Add-Finding -Domain 'M365' -Check 'Mailboxes with external auto-forwarding' -Severity $sev `
            -Status $(if ($extForward.Count -gt 0) {'Finding'} else {'Pass'}) -Count $extForward.Count `
            -Details ($extForward.PrimarySmtpAddress -join ', ') `
            -Recommendation 'External auto-forwarding is a top data-exfiltration vector (often set by a compromised account or malicious inbox rule). Block tenant-wide via mail flow rule and review flagged mailboxes immediately.'
    } catch { Add-Finding -Domain 'M365' -Check 'External forwarding' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- Inbox rules with suspicious forwarding (per-mailbox rules, more expensive - sample or flag) ---
    try {
        $suspiciousRules = Get-Mailbox -ResultSize Unlimited | ForEach-Object {
            Get-InboxRule -Mailbox $_.PrimarySmtpAddress -ErrorAction SilentlyContinue |
                Where-Object { $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo }
        }
        $sev = if ($suspiciousRules.Count -gt 0) { 'High' } else { 'Info' }
        Add-Finding -Domain 'M365' -Check 'Inbox rules forwarding/redirecting mail' -Severity $sev `
            -Status $(if ($suspiciousRules.Count -gt 0) {'Finding'} else {'Pass'}) -Count $suspiciousRules.Count `
            -Recommendation 'Individually review each rule — a common post-compromise persistence technique is a hidden inbox rule forwarding finance/HR mail externally.'
    } catch { Add-Finding -Domain 'M365' -Check 'Inbox rules' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- Transport rules (mail flow rules) that bypass filtering ---
    try {
        $transportRules = Get-TransportRule
        $bypass = $transportRules | Where-Object { $_.SetSCL -eq -1 -or $_.SenderAddressLocation -eq 'HeaderOrEnvelope' }
        Add-Finding -Domain 'M365' -Check 'Transport rules bypassing spam filtering' -Severity Medium -Status Finding `
            -Count $bypass.Count -Details ($bypass.Name -join ', ') `
            -Recommendation 'Rules that set SCL -1 skip spam/phishing filtering entirely. Confirm each is scoped narrowly (e.g. to a specific trusted sender/IP), not broadly.'
    } catch { Add-Finding -Domain 'M365' -Check 'Transport rules' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- SharePoint / OneDrive external sharing ---
    if (Test-ModuleAvailable -Name Microsoft.Online.SharePoint.PowerShell) {
        try {
            $tenantName = Read-Host "Enter SharePoint tenant admin URL (e.g. https://contoso-admin.sharepoint.com)"
            Connect-SPOService -Url $tenantName -ErrorAction Stop
            $spoTenant = Get-SPOTenant
            $sev = switch ($spoTenant.SharingCapability) {
                'ExternalUserAndGuestSharing' { 'High' }
                'ExternalUserSharingOnly'     { 'Medium' }
                default                        { 'Info' }
            }
            Add-Finding -Domain 'M365' -Check 'SharePoint/OneDrive external sharing level' -Severity $sev -Status Finding `
                -Details "SharingCapability = $($spoTenant.SharingCapability)" `
                -Recommendation 'If set to Anyone/Anonymous link sharing, restrict to "New and existing guests" at minimum, and set default link type to internal-only where business allows.'
        } catch { Add-Finding -Domain 'M365' -Check 'SharePoint external sharing' -Severity Info -Status Error -Details $_.Exception.Message }
    } else {
        Add-Finding -Domain 'M365' -Check 'SharePoint external sharing' -Severity Info -Status Skipped `
            -Details 'Microsoft.Online.SharePoint.PowerShell module not installed.' -Recommendation 'Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser'
    }
}

# ============================================================================
# 4. ENDPOINT AUDIT
# ============================================================================

function Invoke-EndpointAudit {
    Write-Host "`n[Endpoint] Starting endpoint audit (local machine: $env:COMPUTERNAME)..." -ForegroundColor Cyan

    # --- Defender status ---
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $sev = if (-not $mp.RealTimeProtectionEnabled) { 'Critical' } elseif ((Get-Date) - $mp.AntivirusSignatureLastUpdated -gt (New-TimeSpan -Days 3)) { 'High' } else { 'Info' }
        $status = if ($sev -ne 'Info') { 'Finding' } else { 'Pass' }
        Add-Finding -Domain 'Endpoint' -Check 'Microsoft Defender status' -Severity $sev -Status $status `
            -Details "RealTimeProtection=$($mp.RealTimeProtectionEnabled), SignatureAge=$((Get-Date) - $mp.AntivirusSignatureLastUpdated), LastFullScan=$($mp.FullScanEndTime)" `
            -Recommendation 'Real-time protection must be on; signatures should be under 24-48h old. Investigate any endpoint reporting stale signatures.'
    } catch { Add-Finding -Domain 'Endpoint' -Check 'Defender status' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- OS patch currency ---
    try {
        $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending
        $lastPatch = $hotfixes | Select-Object -First 1
        $daysSince = if ($lastPatch.InstalledOn) { ((Get-Date) - $lastPatch.InstalledOn).Days } else { -1 }
        $sev = if ($daysSince -gt 45 -or $daysSince -eq -1) { 'High' } else { 'Info' }
        Add-Finding -Domain 'Endpoint' -Check 'OS patch currency' -Severity $sev -Status $(if ($sev -eq 'High') {'Finding'} else {'Pass'}) `
            -Details "Most recent update: $($lastPatch.HotFixID) on $($lastPatch.InstalledOn)" `
            -Recommendation 'Ensure monthly cumulative updates land within your patch SLA (commonly 14-30 days for critical/security updates).'
    } catch { Add-Finding -Domain 'Endpoint' -Check 'Patch currency' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- Open ports (RDP flagged specially, matching prior audit pattern) ---
    try {
        $listening = Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object -ExpandProperty LocalPort -Unique
        $rdpOpen = $listening -contains 3389
        $sev = if ($rdpOpen) { 'High' } else { 'Info' }
        Add-Finding -Domain 'Endpoint' -Check 'RDP (3389) exposure' -Severity $sev -Status $(if ($rdpOpen) {'Finding'} else {'Pass'}) `
            -Details "RDP listening: $rdpOpen. All listening ports: $($listening -join ', ')" `
            -Recommendation 'RDP should never be directly internet-facing. Restrict to VPN/jump-box access, enforce NLA, and consider Azure Bastion / Windows Admin Center for remote admin instead.'
    } catch { Add-Finding -Domain 'Endpoint' -Check 'Open ports' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- Firewall profiles ---
    try {
        $fw = Get-NetFirewallProfile
        $off = $fw | Where-Object { -not $_.Enabled }
        $sev = if ($off.Count -gt 0) { 'High' } else { 'Info' }
        Add-Finding -Domain 'Endpoint' -Check 'Windows Firewall profiles' -Severity $sev -Status $(if ($off.Count -gt 0) {'Finding'} else {'Pass'}) `
            -Details ($fw | ForEach-Object { "$($_.Name): $($_.Enabled)" }) -join '; ' `
            -Recommendation 'All three firewall profiles (Domain/Private/Public) should be enabled unless explicitly compensated by another control.'
    } catch { Add-Finding -Domain 'Endpoint' -Check 'Firewall' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- BitLocker ---
    try {
        $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        $sev = if ($bl.ProtectionStatus -ne 'On') { 'Medium' } else { 'Info' }
        Add-Finding -Domain 'Endpoint' -Check 'BitLocker (OS drive)' -Severity $sev -Status $(if ($sev -eq 'Medium') {'Finding'} else {'Pass'}) `
            -Details "ProtectionStatus=$($bl.ProtectionStatus), EncryptionPercentage=$($bl.EncryptionPercentage)" `
            -Recommendation 'Enable BitLocker with TPM protector on all endpoints, especially laptops, to protect data at rest if a device is lost or stolen.'
    } catch { Add-Finding -Domain 'Endpoint' -Check 'BitLocker' -Severity Info -Status Error -Details "$($_.Exception.Message) (may require running as admin, or not applicable to this host type)" }

    # --- Local Administrators group membership ---
    try {
        $localAdmins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
        $sev = if ($localAdmins.Count -gt 3) { 'Medium' } else { 'Info' }
        Add-Finding -Domain 'Endpoint' -Check 'Local Administrators group membership' -Severity $sev -Status $(if ($sev -eq 'Medium') {'Finding'} else {'Pass'}) `
            -Count $localAdmins.Count -Details ($localAdmins.Name -join ', ') `
            -Recommendation 'Minimize standing local admin membership. Prefer LAPS-managed local admin + JIT elevation over persistent domain-account membership in local Administrators.'
    } catch { Add-Finding -Domain 'Endpoint' -Check 'Local admins' -Severity Info -Status Error -Details $_.Exception.Message }
}

# ============================================================================
# 5. ENDPOINT DLP AUDIT (Microsoft Purview)
# ============================================================================

function Invoke-EndpointDLPAudit {
    Write-Host "`n[DLP] Starting Endpoint DLP audit..." -ForegroundColor Cyan

    if (-not (Test-ModuleAvailable -Name ExchangeOnlineManagement)) {
        Add-Finding -Domain 'Endpoint DLP' -Check 'Module availability' -Severity Info -Status Error `
            -Details 'ExchangeOnlineManagement module (provides Connect-IPPSSession) not installed.' `
            -Recommendation 'Install-Module ExchangeOnlineManagement -Scope CurrentUser'
        return
    }

    try {
        Connect-IPPSSession -ErrorAction Stop | Out-Null
    } catch {
        Add-Finding -Domain 'Endpoint DLP' -Check 'Connect-IPPSSession' -Severity Info -Status Error -Details $_.Exception.Message
        return
    }

    # --- DLP policy inventory & endpoint coverage ---
    try {
        $policies = Get-DlpCompliancePolicy
        $endpointPolicies = $policies | Where-Object { $_.EndpointDlpLocation -or $_.Workload -match 'Endpoint' }
        $disabledPolicies = $policies | Where-Object { $_.Mode -eq 'Disable' }

        Add-Finding -Domain 'Endpoint DLP' -Check 'DLP policy inventory' -Severity Info -Status Pass `
            -Count $policies.Count -Details "$($policies.Count) total DLP policies; $($endpointPolicies.Count) include Endpoint locations."

        if ($endpointPolicies.Count -eq 0) {
            Add-Finding -Domain 'Endpoint DLP' -Check 'Endpoint DLP coverage' -Severity High -Status Finding `
                -Details 'No DLP policy currently targets the Endpoint (devices) location.' `
                -Recommendation 'If sensitive data can leave via USB, print, clipboard, or unallowed apps, create a policy with Endpoint DLP location enabled and onboard devices via Purview/Defender.'
        }

        if ($disabledPolicies.Count -gt 0) {
            Add-Finding -Domain 'Endpoint DLP' -Check 'Policies in Disabled/test mode' -Severity Medium -Status Finding `
                -Count $disabledPolicies.Count -Details ($disabledPolicies.Name -join ', ') `
                -Recommendation 'Policies stuck in "Test without notifications" or Disabled provide no protection. Confirm intentional and set a review date to move to enforce.'
        }
    } catch { Add-Finding -Domain 'Endpoint DLP' -Check 'DLP policies' -Severity Info -Status Error -Details $_.Exception.Message }

    # --- Endpoint DLP settings (onboarded devices, file path exclusions) ---
    try {
        $settings = Get-DlpEndpointOnboardingSetting -ErrorAction Stop
        Add-Finding -Domain 'Endpoint DLP' -Check 'Device onboarding status' -Severity Info -Status Finding `
            -Details ($settings | Out-String) `
            -Recommendation 'Cross-check onboarded device count against total managed endpoint count (Intune/SCCM) — gaps mean those devices have zero DLP visibility.'
    } catch { Add-Finding -Domain 'Endpoint DLP' -Check 'Device onboarding' -Severity Info -Status Error -Details "$($_.Exception.Message) (cmdlet availability varies by tenant/module version)" }

    # --- Sensitivity label / sensitive info type usage in rules ---
    try {
        $rules = Get-DlpComplianceRule
        $noAction = $rules | Where-Object { -not $_.BlockAccess -and -not $_.GenerateAlert -and -not $_.NotifyUser }
        Add-Finding -Domain 'Endpoint DLP' -Check 'DLP rules with no enforcement action' -Severity Medium -Status Finding `
            -Count $noAction.Count -Details ($noAction.Name -join ', ') `
            -Recommendation 'A rule that only logs (no block/alert/notify) provides audit trail but no active prevention. Confirm that is the intent for each such rule.'
    } catch { Add-Finding -Domain 'Endpoint DLP' -Check 'DLP rule actions' -Severity Info -Status Error -Details $_.Exception.Message }
}

# ============================================================================
# HTML REPORT GENERATION
# ============================================================================

function New-HTMLReport {
    param([string]$Path)

    $sevOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $sevColor = @{ Critical = '#7a1f1f'; High = '#c0392b'; Medium = '#d68910'; Low = '#2874a6'; Info = '#5f6a6a' }

    $findingsOnly = $Global:Findings | Where-Object { $_.Status -eq 'Finding' } | Sort-Object { $sevOrder[$_.Severity] }
    $summary = $Global:Findings | Where-Object { $_.Status -eq 'Finding' } | Group-Object Severity |
        ForEach-Object { [PSCustomObject]@{ Severity = $_.Name; Count = $_.Count } } | Sort-Object { $sevOrder[$_.Severity] }

    $domains = $Global:Findings | Select-Object -ExpandProperty Domain -Unique

    $summaryCardsHtml = ($summary | ForEach-Object {
        "<div class='card' style='border-left-color:$($sevColor[$_.Severity])'><div class='card-count'>$($_.Count)</div><div class='card-label'>$($_.Severity)</div></div>"
    }) -join "`n"

    $sectionsHtml = ($domains | ForEach-Object {
        $domainName = $_
        $rows = $Global:Findings | Where-Object { $_.Domain -eq $domainName } | Sort-Object { $sevOrder[$_.Severity] }, Check
        $rowsHtml = ($rows | ForEach-Object {
            $badgeColor = $sevColor[$_.Severity]
            $countStr = if ($_.Count -ge 0) { $_.Count } else { '' }
            $details = [System.Web.HttpUtility]::HtmlEncode($_.Details)
            $rec = [System.Web.HttpUtility]::HtmlEncode($_.Recommendation)
            @"
            <tr class="row-$($_.Status.ToLower())">
                <td><span class="badge" style="background:$badgeColor">$($_.Severity)</span></td>
                <td>$($_.Check)</td>
                <td>$($_.Status)</td>
                <td>$countStr</td>
                <td class="details-cell">$details</td>
                <td class="details-cell">$rec</td>
            </tr>
"@
        }) -join "`n"

        @"
        <div class="domain-section">
            <h2 onclick="this.parentElement.classList.toggle('collapsed')">$domainName <span class="count-pill">$($rows.Count) checks</span></h2>
            <div class="domain-body">
                <table>
                    <thead><tr><th>Severity</th><th>Check</th><th>Status</th><th>Count</th><th>Details</th><th>Recommendation</th></tr></thead>
                    <tbody>$rowsHtml</tbody>
                </table>
            </div>
        </div>
"@
    }) -join "`n"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Audit Report - $(Get-Date -Format 'yyyy-MM-dd')</title>
<style>
    body { font-family: 'Segoe UI', Arial, sans-serif; background:#f4f6f7; color:#1c2833; margin:0; padding:0 0 40px; }
    header { background:#1c2833; color:#fff; padding:24px 32px; }
    header h1 { margin:0; font-size:22px; }
    header p { margin:4px 0 0; color:#aab7b8; font-size:13px; }
    .container { max-width:1200px; margin:0 auto; padding:0 24px; }
    .summary { display:flex; gap:16px; margin:24px 0; flex-wrap:wrap; }
    .card { background:#fff; border-left:5px solid #999; border-radius:4px; padding:14px 20px; min-width:110px; box-shadow:0 1px 3px rgba(0,0,0,0.1); }
    .card-count { font-size:26px; font-weight:700; }
    .card-label { font-size:12px; text-transform:uppercase; color:#566573; letter-spacing:0.5px; }
    .domain-section { background:#fff; border-radius:6px; margin-bottom:18px; box-shadow:0 1px 3px rgba(0,0,0,0.08); overflow:hidden; }
    .domain-section h2 { margin:0; padding:14px 20px; background:#e8eef1; font-size:16px; cursor:pointer; user-select:none; display:flex; justify-content:space-between; align-items:center; }
    .count-pill { font-size:12px; font-weight:400; background:#d5dbdb; padding:3px 10px; border-radius:12px; color:#333; }
    .domain-section.collapsed .domain-body { display:none; }
    table { width:100%; border-collapse:collapse; font-size:13px; }
    th { text-align:left; padding:10px 14px; background:#f8f9f9; border-bottom:2px solid #d5dbdb; font-size:11px; text-transform:uppercase; color:#566573; }
    td { padding:10px 14px; border-bottom:1px solid #eef1f1; vertical-align:top; }
    .details-cell { max-width:280px; word-wrap:break-word; color:#444; }
    .badge { color:#fff; padding:3px 10px; border-radius:10px; font-size:11px; font-weight:600; white-space:nowrap; }
    .row-pass { opacity:0.6; }
    .row-error { background:#fdfefe; color:#999; }
    footer { text-align:center; color:#909497; font-size:12px; margin-top:30px; }
</style>
</head>
<body>
<header>
    <h1>Security Audit Report</h1>
    <p>Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME by $env:USERNAME</p>
</header>
<div class="container">
    <div class="summary">$summaryCardsHtml</div>
    $sectionsHtml
</div>
<footer>Findings requiring attention are expanded by default. Click a section header to collapse/expand. "Pass"/"Error" rows are dimmed.</footer>
</body>
</html>
"@

    Add-Type -AssemblyName System.Web
    $html | Out-File -FilePath $Path -Encoding UTF8
    Write-Host "`nReport written to: $Path" -ForegroundColor Green
}

# ============================================================================
# MAIN
# ============================================================================

Write-Host "=== Security Audit: AD / Entra ID / M365 / Endpoint / Endpoint DLP ===" -ForegroundColor Yellow

if (-not $SkipAD)       { Invoke-ADAudit }
if (-not $SkipEntra)    { Invoke-EntraIDAudit }
if (-not $SkipM365)     { Invoke-M365Audit }
if (-not $SkipEndpoint) { Invoke-EndpointAudit }
if (-not $SkipDLP)      { Invoke-EndpointDLPAudit }

New-HTMLReport -Path $OutputPath

$criticalCount = ($Global:Findings | Where-Object { $_.Status -eq 'Finding' -and $_.Severity -eq 'Critical' }).Count
$highCount     = ($Global:Findings | Where-Object { $_.Status -eq 'Finding' -and $_.Severity -eq 'High' }).Count
Write-Host "`nAudit complete. Critical: $criticalCount | High: $highCount. Full report: $OutputPath" -ForegroundColor Yellow

# Clean up sessions
Get-PSSession | Where-Object { $_.ConfigurationName -match 'Microsoft.Exchange' } | Remove-PSSession -ErrorAction SilentlyContinue
try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
