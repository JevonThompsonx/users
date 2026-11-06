#Requires -Version 5.1
<#
.SYNOPSIS
Runs the real-AD integration suite for users.ps1 on a disposable lab domain.

.DESCRIPTION
Creates isolated test users, exercises dry-run, confirmation, duplicate,
validation, privileged-group, password-mode, and audit paths, and verifies every
effect with Get-ADUser and Get-ADGroupMember. It never deletes directory objects.

.PARAMETER RepoRoot
Directory containing users.ps1. Defaults to C:\adup.

.PARAMETER RunId
Short suffix used to keep test identities unique across runs.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = 'C:\adup',
    [string]$RunId = (Get-Date -Format 'HHmmss')
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop

$domain = Get-ADDomain
$domainDn = $domain.DistinguishedName
$usersRootDn = "OU=Users,OU=Company,$domainDn"
$artifacts = Join-Path $RepoRoot 'artifacts'
$logs = Join-Path $artifacts 'logs'
$configPath = Join-Path $RepoRoot 'config\departments.json'
$exampleConfigPath = Join-Path $RepoRoot 'config\departments.example.json'

New-Item -ItemType Directory -Path $artifacts -Force | Out-Null
New-Item -ItemType Directory -Path $logs -Force | Out-Null

$config = Get-Content -LiteralPath $exampleConfigPath -Raw | ConvertFrom-Json
$config.usersRootOU = 'OU=Users,OU=Company'
$config.upnSuffix = $domain.DNSRoot
$config.emailDomain = $domain.DNSRoot
$config.company = 'Lab Corp'
$config | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $configPath -Encoding UTF8

$privilegedConfigPath = Join-Path $artifacts 'departments-privileged.json'
$privilegedConfig = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$privilegedConfig.privilegedGroups = @('Lab Tier 0')
$privilegedConfig | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $privilegedConfigPath -Encoding UTF8

$script:Pass = 0
$script:Fail = 0
$script:Findings = New-Object System.Collections.Generic.List[string]

function Assert {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) {
        $script:Pass++
        Write-Host ("[PASS] {0}" -f $Name) -ForegroundColor Green
    } else {
        $script:Fail++
        $script:Findings.Add($Name)
        Write-Host ("[FAIL] {0} {1}" -f $Name, $Detail) -ForegroundColor Red
    }
}

function New-Row {
    param(
        [string]$First,
        [string]$Last,
        [string]$Department,
        [string]$Title = '',
        [string]$Manager = '',
        [string]$Sam = '',
        [string]$Upn = '',
        [string]$Email = '',
        [string]$Employee = '',
        [string]$Groups = '',
        [string]$Ou = '',
        [string]$Middle = ''
    )
    [pscustomobject]@{
        FirstName         = $First
        MiddleName        = $Middle
        LastName          = $Last
        Department        = $Department
        Title             = $Title
        Manager           = $Manager
        SamAccountName    = $Sam
        UserPrincipalName = $Upn
        EmailAddress      = $Email
        EmployeeID        = $Employee
        Groups            = $Groups
        OU                = $Ou
    }
}

function New-TestCsv {
    param([string]$Name, [object[]]$Rows)
    $path = Join-Path $artifacts $Name
    $Rows |
        Select-Object FirstName, MiddleName, LastName, Department, Title, Manager,
            SamAccountName, UserPrincipalName, EmailAddress, EmployeeID, Groups, OU |
        Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
    return $path
}

function Invoke-Users {
    param(
        [string]$Csv,
        [string[]]$Arguments = @(),
        [string]$Config = $configPath
    )

    $stdout = Join-Path $artifacts ("run-" + [guid]::NewGuid().ToString('N') + '.out')
    $stderr = Join-Path $artifacts ("run-" + [guid]::NewGuid().ToString('N') + '.err')
    $arguments = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $RepoRoot 'users.ps1'),
        '-CsvPath', $Csv,
        '-DepartmentConfigPath', $Config,
        '-LogPath', $logs,
        '-SkipTranscript'
    ) + $Arguments

    $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    return [pscustomobject]@{
        ExitCode = $process.ExitCode
        Output   = [string](Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue)
        Error    = [string](Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue)
    }
}

function Get-TestUser {
    param([string]$Sam)
    return Get-ADUser -Filter "sAMAccountName -eq '$Sam'" -Properties SamAccountName, UserPrincipalName, EmailAddress, GivenName, Surname,
        DisplayName, Department, Title, Company, Manager, Enabled, EmployeeID, pwdLastSet, DistinguishedName
}

function Get-LineCount {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    return (Get-Content -LiteralPath $Path | Measure-Object -Line).Lines
}

function Get-Count {
    return @(Get-ADUser -Filter *).Count
}

$fixtureNames = @('existing.user', 'dup.upn', 'dup.mail', 'dup.emp', 'same.name')
$fixtureBefore = @{}
foreach ($name in $fixtureNames) {
    $user = Get-ADUser -Identity $name -Properties SamAccountName, UserPrincipalName, EmailAddress, EmployeeID, Enabled, DistinguishedName
    $fixtureBefore[$name] = [pscustomobject]@{
        DistinguishedName = $user.DistinguishedName
        Upn               = $user.UserPrincipalName
        Email             = $user.EmailAddress
        EmployeeID        = $user.EmployeeID
        Enabled           = $user.Enabled
    }
}

$baselineCount = Get-Count
Write-Host ("Run {0} against {1}; baseline user count {2}" -f $RunId, $domain.DNSRoot, $baselineCount) -ForegroundColor Cyan

# A. WhatIf
$whatIfCsv = New-TestCsv -Name 'whatif.csv' -Rows @(
    (New-Row -First "WhatIf$RunId" -Last 'Alpha' -Department 'Finance' -Title 'Analyst' -Manager 'mgr.finance' -Sam "whatif.$RunId.alpha" -Employee "E-$RunId-1"),
    (New-Row -First "WhatIf$RunId" -Last 'Beta' -Department 'Engineering' -Title 'Engineer' -Manager 'mgr.engineering' -Sam "whatif.$RunId.beta" -Employee "E-$RunId-2")
)
$whatIfCreds = Join-Path $artifacts "whatif-$RunId.csv"
$result = Invoke-Users -Csv $whatIfCsv -Arguments @('-PasswordMode', 'Generated', '-CredentialExportPath', $whatIfCreds, '-WhatIf')
Assert 'A1 WhatIf exits 0' ($result.ExitCode -eq 0) ("exit=" + $result.ExitCode + " " + $result.Error)
Assert 'A2 WhatIf creates no user' ($null -eq (Get-TestUser "whatif.$RunId.alpha")) ''
Assert 'A3 WhatIf writes no credential file' (-not (Test-Path -LiteralPath $whatIfCreds)) ''
Assert 'A4 WhatIf leaves user count unchanged' ((Get-Count) -eq $baselineCount) ''
Assert 'A5 WhatIf output states no changes' ($result.Output -match 'WhatIf') $result.Output

# C. -Force confirmation path
$confirmCsv = New-TestCsv -Name 'confirm.csv' -Rows @(
    (New-Row -First "Confirm$RunId" -Last 'User' -Department 'Finance' -Title 'Analyst' -Manager 'mgr.finance' -Sam "confirm.$RunId.user" -Employee "E-$RunId-4")
)
$confirmCreds = Join-Path $artifacts "confirm-$RunId.csv"
$result = Invoke-Users -Csv $confirmCsv -Arguments @('-PasswordMode', 'Generated', '-CredentialExportPath', $confirmCreds, '-Force')
$confirmUser = Get-TestUser "confirm.$RunId.user"
Assert 'C1 forced run exits 0' ($result.ExitCode -eq 0) ("exit=" + $result.ExitCode + " " + $result.Error)
Assert 'C2 forced run creates the user' ($null -ne $confirmUser) ''
Assert 'C3 created user is enabled' ($null -ne $confirmUser -and $confirmUser.Enabled -eq $true) ''
Assert 'C4 forced run writes one credential row' ((Get-LineCount $confirmCreds) -eq 2) ''

# D. Happy-path batch
$batchCsv = New-TestCsv -Name 'batch.csv' -Rows @(
    (New-Row -First "Batch$RunId" -Last 'Finance' -Department 'Finance' -Title 'Analyst' -Manager 'mgr.finance' -Sam "batch.$RunId.finance" -Employee "E-$RunId-10"),
    (New-Row -First "Batch$RunId" -Last 'Engineer' -Department 'Engineering' -Title 'Engineer' -Manager 'mgr.engineering' -Sam "batch.$RunId.engineer" -Employee "E-$RunId-11"),
    (New-Row -First "Batch$RunId" -Last 'Support' -Department 'Information Technology' -Title 'Technician' -Manager 'mgr.it' -Sam "batch.$RunId.it" -Employee "E-$RunId-12"),
    (New-Row -First "Batch$RunId" -Last 'Materials' -Department 'Materials' -Title 'Coordinator' -Manager 'mgr.operations' -Sam "batch.$RunId.materials" -Employee "E-$RunId-13"),
    (New-Row -First "Batch$RunId" -Last 'Quality' -Department 'Quality Assurance' -Title 'Inspector' -Manager 'mgr.operations' -Sam "batch.$RunId.quality" -Employee "E-$RunId-14"),
    (New-Row -First "Batch$RunId" -Last 'Facilities' -Department 'Facilities' -Title 'Coordinator' -Manager 'mgr.operations' -Sam "batch.$RunId.facilities" -Employee "E-$RunId-15")
)
$batchCreds = Join-Path $artifacts "batch-$RunId.csv"
$result = Invoke-Users -Csv $batchCsv -Arguments @('-PasswordMode', 'Generated', '-CredentialExportPath', $batchCreds, '-Force')
Assert 'D1 batch exits 0' ($result.ExitCode -eq 0) ("exit=" + $result.ExitCode + " " + $result.Error)
Assert 'D2 batch creates six users' ((Get-Count) -eq ($baselineCount + 7)) ("count=" + (Get-Count))

$expected = @{
    "batch.$RunId.finance"    = @{ OU = 'OU=Finance,OU=Administrative,OU=Departments'; Groups = @('Finance Team', 'Standard Employee Access', 'Remote Access', 'Knowledge Base Users'); Manager = 'mgr.finance' }
    "batch.$RunId.engineer"   = @{ OU = 'OU=Engineering,OU=Departments'; Groups = @('Engineering Team', 'Standard Employee Access', 'Remote Access', 'Knowledge Base Users', 'Source Control Users'); Manager = 'mgr.engineering' }
    "batch.$RunId.it"         = @{ OU = 'OU=Information Technology,OU=Administrative,OU=Departments'; Groups = @('IT Team', 'Standard Employee Access', 'Remote Access', 'Knowledge Base Users'); Manager = 'mgr.it' }
    "batch.$RunId.materials"  = @{ OU = 'OU=Materials,OU=Operations,OU=Departments'; Groups = @('Materials Team', 'Standard Employee Access', 'Restricted Area Access', 'Remote Access', 'Shipping Team', 'Knowledge Base Users'); Manager = 'mgr.operations' }
    "batch.$RunId.quality"    = @{ OU = 'OU=Quality Assurance,OU=Operations,OU=Departments'; Groups = @('Quality Assurance Team', 'Quality Team', 'Standard Employee Access', 'Remote Access', 'Knowledge Base Users'); Manager = 'mgr.operations' }
    "batch.$RunId.facilities" = @{ OU = 'OU=Facilities,OU=Operations,OU=Departments'; Groups = @('Facilities Team', 'Standard Employee Access', 'Remote Access', 'Knowledge Base Users'); Manager = 'mgr.operations' }
}
foreach ($sam in $expected.Keys) {
    $user = Get-TestUser $sam
    $spec = $expected[$sam]
    Assert ("D3 {0} exists" -f $sam) ($null -ne $user) ''
    if (-not $user) { continue }
    Assert ("D4 {0} in correct OU" -f $sam) ($user.DistinguishedName.EndsWith((',' + $spec.OU + ',' + $usersRootDn), [System.StringComparison]::OrdinalIgnoreCase)) $user.DistinguishedName
    Assert ("D5 {0} enabled" -f $sam) ($user.Enabled -eq $true) ''
    Assert ("D6 {0} must change password" -f $sam) ([int64]$user.pwdLastSet -eq 0) ("pwdLastSet=" + $user.pwdLastSet)
    $managerDn = (Get-ADUser -Identity $spec.Manager).DistinguishedName
    Assert ("D7 {0} manager" -f $sam) ($user.Manager -eq $managerDn) ("manager=" + $user.Manager)
    foreach ($group in $spec.Groups) {
        $members = Get-ADGroupMember -Identity $group | ForEach-Object { $_.DistinguishedName }
        Assert ("D8 {0} in {1}" -f $sam, $group) ($members -contains $user.DistinguishedName) ''
    }
}
Assert 'D9 credential file has header plus six rows' ((Get-LineCount $batchCreds) -eq 7) ''
Assert 'D10 credential file ACL is protected' ((Test-Path -LiteralPath $batchCreds) -and (Get-Acl -LiteralPath $batchCreds).AreAccessRulesProtected -eq $true) ''
$firstPassword = if (Test-Path -LiteralPath $batchCreds) { (Import-Csv -LiteralPath $batchCreds | Select-Object -First 1).TemporaryPassword } else { '' }
$latestAudit = Get-ChildItem -LiteralPath $logs -Filter 'provisioning-*.csv' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$auditText = if ($latestAudit) { [string](Get-Content -LiteralPath $latestAudit.FullName -Raw) } else { '' }
Assert 'D11 audit CSV does not contain a password' (-not $auditText.Contains($firstPassword)) ''
Assert 'D12 console output does not contain a password' (-not $result.Output.Contains($firstPassword)) ''

# E. Idempotent rerun
$rerunCreds = Join-Path $artifacts "rerun-$RunId.csv"
$countBeforeRerun = Get-Count
$result = Invoke-Users -Csv $batchCsv -Arguments @('-PasswordMode', 'Generated', '-CredentialExportPath', $rerunCreds, '-Force')
Assert 'E1 rerun exits 0' ($result.ExitCode -eq 0) ("exit=" + $result.ExitCode)
Assert 'E2 rerun creates no users' ((Get-Count) -eq $countBeforeRerun) ''
Assert 'E3 rerun reports zero creates' ($result.Output -match 'Summary:\s+0 create') $result.Output

# F. Existing-object duplicates
$duplicateCsv = New-TestCsv -Name 'duplicates.csv' -Rows @(
    (New-Row -First 'Existing' -Last 'User' -Department 'Finance' -Title 'Analyst' -Manager 'mgr.finance' -Sam 'existing.user' -Employee "E-$RunId-20"),
    (New-Row -First 'Dup' -Last 'Upn' -Department 'Finance' -Title 'Analyst' -Manager 'mgr.finance' -Sam "newdup.$RunId.upn" -Upn "collision.upn@$($domain.DNSRoot)" -Employee "E-$RunId-21"),
    (New-Row -First 'Dup' -Last 'Mail' -Department 'Finance' -Title 'Analyst' -Manager 'mgr.finance' -Sam "newdup.$RunId.mail" -Email "collision.mail@$($domain.DNSRoot)" -Employee "E-$RunId-22"),
    (New-Row -First 'Dup' -Last 'Emp' -Department 'Finance' -Title 'Analyst' -Manager 'mgr.finance' -Sam "newdup.$RunId.emp" -Employee 'E-1000'),
    (New-Row -First 'Same' -Last 'Name' -Department 'Finance' -Title 'Analyst' -Manager 'mgr.finance' -Sam "newsame.$RunId" -Employee "E-$RunId-23")
)
$countBeforeDuplicates = Get-Count
$result = Invoke-Users -Csv $duplicateCsv -Arguments @('-PasswordMode', 'None', '-Force')
Assert 'F1 duplicate run exits 0' ($result.ExitCode -eq 0) ("exit=" + $result.ExitCode)
Assert 'F2 duplicate run creates no users' ((Get-Count) -eq $countBeforeDuplicates) ''
Assert 'F3 duplicate output reports skips' ($result.Output -match 'Summary:\s+0 create') $result.Output
foreach ($sam in @("newdup.$RunId.upn", "newdup.$RunId.mail", "newdup.$RunId.emp", "newsame.$RunId")) {
    Assert ("F4 no user {0}" -f $sam) ($null -eq (Get-TestUser $sam)) ''
}

# G. Duplicate rows inside the CSV
$csvDuplicateCsv = New-TestCsv -Name 'csvduplicate.csv' -Rows @(
    (New-Row -First "Csv$RunId" -Last 'Dup' -Department 'Finance' -Title 'Analyst' -Manager 'mgr.finance' -Sam "csvdup.$RunId" -Employee "E-$RunId-30"),
    (New-Row -First "Csv$RunId" -Last 'Dup' -Department 'Finance' -Title 'Analyst' -Manager 'mgr.finance' -Sam "csvdup.$RunId" -Employee "E-$RunId-30")
)
$countBeforeCsvDuplicate = Get-Count
$result = Invoke-Users -Csv $csvDuplicateCsv -Arguments @('-PasswordMode', 'None', '-Force')
Assert 'G1 CSV duplicate run creates no users' ((Get-Count) -eq $countBeforeCsvDuplicate) ''
Assert 'G2 CSV duplicate is reported' ($result.Output -match 'within the CSV') $result.Output

# H. Missing references
$invalidCsv = New-TestCsv -Name 'invalid.csv' -Rows @(
    (New-Row -First "Missing$RunId" -Last 'Group' -Department 'Finance' -Title 'Analyst' -Manager 'mgr.finance' -Sam "missing.$RunId.group" -Employee "E-$RunId-40" -Groups 'Missing Group'),
    (New-Row -First "Missing$RunId" -Last 'Ou' -Department 'Finance' -Title 'Analyst' -Manager 'mgr.finance' -Sam "missing.$RunId.ou" -Employee "E-$RunId-41" -Ou 'OU=Missing,OU=Departments'),
    (New-Row -First "Unknown$RunId" -Last 'Dept' -Department 'Legal' -Title 'Analyst' -Manager 'mgr.finance' -Sam "unknown.$RunId.dept" -Employee "E-$RunId-42")
)
$countBeforeInvalid = Get-Count
$result = Invoke-Users -Csv $invalidCsv -Arguments @('-PasswordMode', 'None', '-Force')
Assert 'H1 invalid-reference run creates no users' ((Get-Count) -eq $countBeforeInvalid) ''
Assert 'H2 missing group is reported' ($result.Output -match 'Missing Group') $result.Output
Assert 'H3 unknown department is reported' ($result.Output -match 'Unknown department') $result.Output

# I. Privileged group refusal
$privilegedCsv = New-TestCsv -Name 'privileged.csv' -Rows @(
    (New-Row -First "Priv$RunId" -Last 'User' -Department 'Finance' -Title 'Analyst' -Manager 'mgr.finance' -Sam "priv.$RunId.user" -Employee "E-$RunId-50" -Groups 'Domain Admins')
)
$countBeforePrivileged = Get-Count
$result = Invoke-Users -Csv $privilegedCsv -Arguments @('-PasswordMode', 'None', '-Force')
Assert 'I1 privileged-group run creates no users' ((Get-Count) -eq $countBeforePrivileged) ''
Assert 'I2 privileged group is refused' ($result.Output -match 'privileged') $result.Output

# J. Privileged override with a configured custom group
$overrideCsv = New-TestCsv -Name 'override.csv' -Rows @(
    (New-Row -First "Override$RunId" -Last 'User' -Department 'Finance' -Title 'Analyst' -Manager 'mgr.finance' -Sam "override.$RunId.user" -Employee "E-$RunId-51" -Groups 'Lab Tier 0')
)
$result = Invoke-Users -Csv $overrideCsv -Config $privilegedConfigPath -Arguments @('-PasswordMode', 'None', '-AllowPrivilegedGroups', '-Force')
$overrideUser = Get-TestUser "override.$RunId.user"
Assert 'J1 override run creates the user' ($null -ne $overrideUser) $result.Error
$tier0 = Get-ADGroupMember -Identity 'Lab Tier 0' | ForEach-Object { $_.DistinguishedName }
Assert 'J2 override adds the user to the configured group' ($null -ne $overrideUser -and $tier0 -contains $overrideUser.DistinguishedName) ''

# K. Password mode None
$noPasswordCsv = New-TestCsv -Name 'nopassword.csv' -Rows @(
    (New-Row -First "NoPassword$RunId" -Last 'User' -Department 'Finance' -Title 'Analyst' -Manager 'mgr.finance' -Sam "nopassword.$RunId.user" -Employee "E-$RunId-60")
)
$result = Invoke-Users -Csv $noPasswordCsv -Arguments @('-PasswordMode', 'None', '-Force')
$noPasswordUser = Get-TestUser "nopassword.$RunId.user"
Assert 'K1 password-none run creates a user' ($null -ne $noPasswordUser) $result.Error
Assert 'K2 password-none user stays disabled' ($null -ne $noPasswordUser -and $noPasswordUser.Enabled -eq $false) ''

# L. Invalid UPN suffix fails preflight
$badUpnCsv = New-TestCsv -Name 'badupn.csv' -Rows @(
    (New-Row -First "Bad$RunId" -Last 'Upn' -Department 'Finance' -Title 'Analyst' -Manager 'mgr.finance' -Sam "badupn.$RunId.user" -Employee "E-$RunId-70")
)
$countBeforeBadUpn = Get-Count
$result = Invoke-Users -Csv $badUpnCsv -Arguments @('-PasswordMode', 'None', '-UpnSuffix', 'invalid.test', '-Force')
Assert 'L1 invalid UPN suffix exits 2' ($result.ExitCode -eq 2) ("exit=" + $result.ExitCode)
Assert 'L2 invalid UPN suffix creates no user' ((Get-Count) -eq $countBeforeBadUpn) ''

# M. Missing root OU fails preflight
$badRootCsv = New-TestCsv -Name 'badroot.csv' -Rows @(
    (New-Row -First "Bad$RunId" -Last 'Root' -Department 'Finance' -Title 'Analyst' -Manager 'mgr.finance' -Sam "badroot.$RunId.user" -Employee "E-$RunId-71")
)
$countBeforeBadRoot = Get-Count
$result = Invoke-Users -Csv $badRootCsv -Arguments @('-PasswordMode', 'None', '-UsersRootOU', "OU=Missing,OU=Company,$domainDn", '-Force')
Assert 'M1 missing root OU exits 2' ($result.ExitCode -eq 2) ("exit=" + $result.ExitCode)
Assert 'M2 missing root OU creates no user' ((Get-Count) -eq $countBeforeBadRoot) ''

# N. Existing fixtures unchanged
foreach ($name in $fixtureNames) {
    $user = Get-ADUser -Identity $name -Properties SamAccountName, UserPrincipalName, EmailAddress, EmployeeID, Enabled, DistinguishedName
    $before = $fixtureBefore[$name]
    Assert ("N1 {0} DN unchanged" -f $name) ($user.DistinguishedName -eq $before.DistinguishedName) ''
    Assert ("N2 {0} UPN unchanged" -f $name) ($user.UserPrincipalName -eq $before.Upn) ''
    Assert ("N3 {0} email unchanged" -f $name) ($user.EmailAddress -eq $before.Email) ''
    Assert ("N4 {0} employeeID unchanged" -f $name) ($user.EmployeeID -eq $before.EmployeeID) ''
    Assert ("N5 {0} enabled state unchanged" -f $name) ($user.Enabled -eq $before.Enabled) ''
}

$finalCount = Get-Count
$expectedCreates = 1 + 6 + 1 + 1
Assert 'O1 total user delta matches the created accounts' ($finalCount -eq ($baselineCount + $expectedCreates)) ("baseline=$baselineCount final=$finalCount expected=" + ($baselineCount + $expectedCreates))

Write-Host ''
Write-Host ("Integration result: {0} passed, {1} failed." -f $script:Pass, $script:Fail) -ForegroundColor Cyan
if ($script:Fail -gt 0) {
    $script:Findings | ForEach-Object { Write-Host ("FAILED: " + $_) -ForegroundColor Red }
    exit 1
}
exit 0
