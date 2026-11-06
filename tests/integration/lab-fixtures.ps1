<#
.SYNOPSIS
Creates the organizational units, groups, managers, and duplicate fixtures used by the integration tests.

.DESCRIPTION
Designed for a disposable lab domain only. The script is idempotent: existing
objects are left untouched. It never deletes anything.

.PARAMETER FixturePassword
Password assigned to the fixture manager and duplicate accounts.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [Alias('FixturePassword')]
    [string]$FixtureSecret,

    [string]$UsersRootOU = 'OU=Users,OU=Company'
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop

$domain = Get-ADDomain
$domainDn = $domain.DistinguishedName
$secureFixturePassword = New-Object System.Security.SecureString
foreach ($character in $FixtureSecret.ToCharArray()) { $secureFixturePassword.AppendChar($character) }
$secureFixturePassword.MakeReadOnly()

function Ensure-OU {
    param([string]$Name, [string]$Path)
    $dn = "OU=$Name,$Path"
    try {
        Get-ADOrganizationalUnit -Identity $dn -ErrorAction Stop | Out-Null
    } catch {
        New-ADOrganizationalUnit -Name $Name -Path $Path | Out-Null
    }
}

function Ensure-Group {
    param([string]$Name, [string]$Path)
    try {
        Get-ADGroup -Identity $Name -ErrorAction Stop | Out-Null
    } catch {
        New-ADGroup -Name $Name -GroupScope Global -GroupCategory Security -Path $Path | Out-Null
    }
}

function Ensure-User {
    param(
        [string]$Sam,
        [string]$First,
        [string]$Last,
        [string]$OU,
        [hashtable]$Extra = @{}
    )
    try {
        Get-ADUser -Identity $Sam -ErrorAction Stop | Out-Null
        return
    } catch { }

    $parameters = @{
        Name                  = "$First $Last"
        GivenName             = $First
        Surname               = $Last
        DisplayName           = "$First $Last"
        SamAccountName        = $Sam
        UserPrincipalName     = "$Sam@$($domain.DNSRoot)"
        Path                  = $OU
        AccountPassword       = $secureFixturePassword
        Enabled               = $true
        ChangePasswordAtLogon = $false
        EmailAddress          = "$Sam@$($domain.DNSRoot)"
    }
    foreach ($key in $Extra.Keys) { $parameters[$key] = $Extra[$key] }
    New-ADUser @parameters
}

Ensure-OU 'Company' $domainDn
Ensure-OU 'Users' "OU=Company,$domainDn"
$usersDn = "$UsersRootOU,$domainDn"
Ensure-OU 'Departments' $usersDn
$departmentsDn = "OU=Departments,$usersDn"
Ensure-OU 'Administrative' $departmentsDn
Ensure-OU 'Operations' $departmentsDn
$administrativeDn = "OU=Administrative,$departmentsDn"
$operationsDn = "OU=Operations,$departmentsDn"

foreach ($name in 'Finance', 'Human Resources', 'Information Technology') {
    Ensure-OU $name $administrativeDn
}
foreach ($name in 'Document Control', 'Facilities', 'Manufacturing', 'Manufacturing Engineering', 'Materials', 'Quality Assurance') {
    Ensure-OU $name $operationsDn
}
foreach ($name in 'Business Development', 'Engineering') {
    Ensure-OU $name $departmentsDn
}

Ensure-OU 'Groups' $domainDn
$groupsDn = "OU=Groups,$domainDn"
foreach ($name in @(
    'Finance Team', 'HR Team', 'IT Team', 'Engineering Team', 'Document Control Team',
    'Facilities Team', 'Manufacturing Team', 'Manufacturing Engineering Team', 'Materials Team',
    'Quality Assurance Team', 'Quality Team', 'Standard Employee Access', 'Remote Access',
    'Knowledge Base Users', 'Source Control Users', 'Project Tracking Users',
    'Restricted Area Access', 'Shipping Team', 'Culture Committee', 'Lab Tier 0'
)) {
    Ensure-Group $name $groupsDn
}

Ensure-User 'mgr.finance' 'Morgan' 'Finance' "OU=Finance,$administrativeDn"
Ensure-User 'mgr.hr' 'Harper' 'Reed' "OU=Human Resources,$administrativeDn"
Ensure-User 'mgr.it' 'Ira' 'Chen' "OU=Information Technology,$administrativeDn"
Ensure-User 'mgr.engineering' 'Emerson' 'Gray' "OU=Engineering,$departmentsDn"
Ensure-User 'mgr.operations' 'Olivia' 'Stone' "OU=Manufacturing,$operationsDn"

Ensure-User 'existing.user' 'Existing' 'User' "OU=Finance,$administrativeDn" @{ EmployeeID = 'E-1000' }
Ensure-User 'dup.upn' 'Duplicate' 'Upn' "OU=Finance,$administrativeDn" @{ UserPrincipalName = "collision.upn@$($domain.DNSRoot)" }
Ensure-User 'dup.mail' 'Duplicate' 'Mail' "OU=Finance,$administrativeDn" @{ EmailAddress = "collision.mail@$($domain.DNSRoot)" }
Ensure-User 'dup.emp' 'Duplicate' 'Employee' "OU=Finance,$administrativeDn" @{ EmployeeID = 'E-2000' }
Ensure-User 'same.name' 'Same' 'Name' "OU=Finance,$administrativeDn"

Write-Output "Fixtures ready in $domainDn"
