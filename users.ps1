#Requires -Version 5.1

<#
.SYNOPSIS
Creates Active Directory users from a reviewed CSV without modifying existing objects.

.DESCRIPTION
Reads a CSV, validates every row against the department configuration, checks for
duplicate identities in Active Directory and inside the CSV, prints the complete
effect plan, and asks for confirmation before writing anything.

New accounts are created disabled, populated, added to their groups, verified,
and only then enabled. A failure leaves the new account disabled. Existing users
and organizational units are never modified or deleted; existing groups are only
ever added to (the new user becomes a member). No membership is removed.

.PARAMETER CsvPath
Path to the user import CSV. Required columns: FirstName, LastName, Department.

.PARAMETER DepartmentConfigPath
Path to the department JSON file. Defaults to config\departments.json beside this
script. Copy config\departments.example.json and edit it for the target domain.

.PARAMETER UsersRootOU
Distinguished name of the OU that contains all target OUs. Defaults to the
configuration file, then OU=Users in the target domain.

.PARAMETER UpnSuffix
UPN suffix for generated user principal names. Defaults to the configuration
file, then the domain DNS name. The suffix must be registered in the forest.

.PARAMETER EmailDomain
Domain used to generate email addresses when the CSV does not provide one.

.PARAMETER Company
Value written to the Company attribute.

.PARAMETER Server
Domain controller to use for all reads and writes. Defaults to a discovered DC.

.PARAMETER Credential
Credential with delegated rights to create users and modify group membership.
Defaults to the current Windows identity.

.PARAMETER LogPath
Directory for the transcript and audit CSV. Defaults to
C:\ProgramData\ADUserProvisioning\Logs.

.PARAMETER CredentialMode
Generated creates a unique random temporary password for each user and writes it
to CredentialExportPath. Single prompts once for one shared temporary password.
None creates disabled accounts without a password.

.PARAMETER CredentialExportPath
Required with CredentialMode Generated. The file must not already exist and is
locked down to the current user, SYSTEM, and Administrators.

.PARAMETER AllowPrivilegedGroups
Allows membership in privileged groups such as Domain Admins. Without this
switch, any such group blocks the affected row.

.PARAMETER StopOnError
Stops after the first failed creation instead of continuing with remaining rows.

.PARAMETER Force
Skips the interactive confirmation prompt. Use only for reviewed, automated
runs. The full plan is still printed.

.PARAMETER SkipTranscript
Does not start a PowerShell transcript. The structured audit CSV is still written.

.INPUTS
None.

.OUTPUTS
None. The script writes a transcript and an audit CSV, and sets the process exit
code to 0 (success or clean abort), 1 (one or more failed rows), or 2 (preflight
failure).

.EXAMPLE
.\users.ps1 -CsvPath .\users.csv -CredentialMode Generated -CredentialExportPath C:\secure\new-users.csv -WhatIf

Shows every planned effect and makes no changes.

.EXAMPLE
.\users.ps1 -CsvPath .\users.csv -CredentialMode Generated -CredentialExportPath C:\secure\new-users.csv

Creates the users after the interactive confirmation.

.NOTES
Requires Windows PowerShell 5.1, the ActiveDirectory module (RSAT), and rights
delegated for user creation and group membership. Run -WhatIf first.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,

    [string]$DepartmentConfigPath,
    [string]$UsersRootOU,
    [string]$UpnSuffix,
    [string]$EmailDomain,
    [string]$Company,
    [string]$Server,
    [pscredential]$Credential,
    [string]$LogPath = 'C:\ProgramData\ADUserProvisioning\Logs',
    [Alias('PasswordMode')]
    [ValidateSet('Generated', 'Single', 'None')]
    [string]$CredentialMode = 'Generated',
    [string]$CredentialExportPath,
    [switch]$AllowPrivilegedGroups,
    [switch]$StopOnError,
    [switch]$Force,
    [switch]$SkipTranscript
)

$ErrorActionPreference = 'Stop'
$exitCode = 0
$transcriptStarted = $false
$sharedPassword = $null

try {
    $modulePath = Join-Path $PSScriptRoot 'src\ADUserProvisioning.psm1'
    if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
        throw "Module not found: $modulePath"
    }
    Import-Module $modulePath -Force -ErrorAction Stop

    if ([string]::IsNullOrWhiteSpace($DepartmentConfigPath)) {
        $DepartmentConfigPath = Join-Path $PSScriptRoot 'config\departments.json'
    }
    if (-not (Test-Path -LiteralPath $DepartmentConfigPath -PathType Leaf)) {
        throw "Department configuration not found: $DepartmentConfigPath. Copy config\departments.example.json to config\departments.json and edit it."
    }

    $settingsArguments = @{
        CsvPath              = $CsvPath
        DepartmentConfigPath = $DepartmentConfigPath
        LogPath              = $LogPath
        CredentialMode       = $CredentialMode
        AllowPrivilegedGroups = [bool]$AllowPrivilegedGroups
        StopOnError          = [bool]$StopOnError
    }
    if (-not [string]::IsNullOrWhiteSpace($UsersRootOU)) { $settingsArguments.UsersRootOU = $UsersRootOU }
    if (-not [string]::IsNullOrWhiteSpace($UpnSuffix)) { $settingsArguments.UpnSuffix = $UpnSuffix }
    if (-not [string]::IsNullOrWhiteSpace($EmailDomain)) { $settingsArguments.EmailDomain = $EmailDomain }
    if (-not [string]::IsNullOrWhiteSpace($Company)) { $settingsArguments.Company = $Company }
    if (-not [string]::IsNullOrWhiteSpace($Server)) { $settingsArguments.Server = $Server }
    if ($null -ne $Credential) { $settingsArguments.Credential = $Credential }
    if (-not [string]::IsNullOrWhiteSpace($CredentialExportPath)) { $settingsArguments.CredentialExportPath = $CredentialExportPath }
    if ($WhatIfPreference) { $settingsArguments.PlanOnly = $true }

    $settings = Get-ADProvisioningSetting @settingsArguments

    if (-not $SkipTranscript -and -not $WhatIfPreference) {
        try {
            Start-Transcript -Path $settings.TranscriptPath -Force -ErrorAction Stop | Out-Null
            $transcriptStarted = $true
        } catch {
            Write-Warning "Transcript could not be started: $($_.Exception.Message)"
        }
    }

    Write-Host ('Preflight passed. Domain {0} via {1}.' -f $settings.Domain.DNSRoot, $settings.Server) -ForegroundColor Cyan

    $plan = Get-ADProvisioningPlan -Settings $settings
    Show-ADProvisioningPlan -Plan $plan

    if ($WhatIfPreference) {
        Write-Host 'WhatIf: no changes were made.' -ForegroundColor Cyan
        $exitCode = 0
    } elseif ($plan.CreateCount -eq 0) {
        Write-Host 'No users can be created from this CSV. Nothing was changed.' -ForegroundColor Yellow
        $exitCode = 0
    } else {
        if ($CredentialMode -eq 'Single') {
            $sharedPassword = Read-Host -AsSecureString -Prompt 'Temporary password for all new users'
            $confirmationPassword = Read-Host -AsSecureString -Prompt 'Re-enter the temporary password'
            $bstr1 = [IntPtr]::Zero
            $bstr2 = [IntPtr]::Zero
            $plain1 = $null
            $plain2 = $null
            try {
                $bstr1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sharedPassword)
                $bstr2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmationPassword)
                $plain1 = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr1)
                $plain2 = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr2)
                if ($plain1 -cne $plain2) { throw 'Temporary passwords do not match.' }
                if ($plain1.Length -lt 12) { throw 'The temporary password must be at least 12 characters long.' }
                $classes = 0
                if ($plain1 -cmatch '[A-Z]') { $classes++ }
                if ($plain1 -cmatch '[a-z]') { $classes++ }
                if ($plain1 -cmatch '[0-9]') { $classes++ }
                if ($plain1 -cmatch '[^A-Za-z0-9]') { $classes++ }
                if ($classes -lt 3) { throw 'The temporary password must use at least three of: upper case, lower case, digits, symbols.' }
            } finally {
                if ($bstr1 -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr1) }
                if ($bstr2 -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2) }
                $plain1 = $null
                $plain2 = $null
            }
        }

        $proceed = [bool]$Force
        if (-not $proceed) {
            $answer = Read-Host 'Type Y to create these users, or anything else to abort'
            $proceed = Test-ADProvisioningConfirmation -Answer $answer
        }

        if (-not $proceed) {
            Write-Host 'Aborted. No changes were made.' -ForegroundColor Yellow
            $exitCode = 0
        } else {
            $result = Invoke-ADProvisioningPlan -Plan $plan -SharedPassword $sharedPassword
            Write-Host ''
            Write-Host ('Result: {0} created, {1} created disabled, {2} failed, {3} skipped.' -f $result.Created, $result.CreatedDisabled, $result.Failed, $result.Skipped) -ForegroundColor Cyan
            Write-Host ('Audit:      {0}' -f $result.AuditPath)
            if ($result.TranscriptPath -and $transcriptStarted) { Write-Host ('Transcript: {0}' -f $result.TranscriptPath) }
            $exitCode = $result.ExitCode
        }
    }
} catch {
    Write-Host ('ERROR: {0}' -f $_.Exception.Message) -ForegroundColor Red
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) { Write-Host $_.ErrorDetails.Message -ForegroundColor Red }
    $exitCode = 2
} finally {
    if ($transcriptStarted) {
        try { Stop-Transcript | Out-Null } catch { Write-Verbose "Transcript was not running." }
    }
}

exit $exitCode
