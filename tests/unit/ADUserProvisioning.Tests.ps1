$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Split-Path -Parent (Split-Path -Parent $here)
$global:TestRoot = Join-Path $env:TEMP ('adup-tests-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $global:TestRoot -Force | Out-Null
$env:PSModulePath = (Join-Path $here 'stubs') + ';' + $env:PSModulePath
Import-Module (Join-Path $repo 'src\ADUserProvisioning.psm1') -Force

InModuleScope ADUserProvisioning {

    function New-TestSecureString {
        param([string]$Value)
        $secure = New-Object System.Security.SecureString
        foreach ($character in $Value.ToCharArray()) { $secure.AppendChar($character) }
        $secure.MakeReadOnly()
        return $secure
    }

    function New-TestSettings {
        param(
            [string]$CsvPath,
            [string]$ConfigPath,
            [string]$ExportPath,
            [string]$Mode = 'Generated',
            [bool]$AllowPrivileged = $false
        )
        [pscustomobject]@{
            CsvPath               = $CsvPath
            CsvHash               = 'TESTHASH'
            DepartmentConfigPath  = $ConfigPath
            Server                = 'dc01.lab.test'
            Credential            = $null
            Domain                = [pscustomobject]@{ DNSRoot = 'lab.test'; DistinguishedName = 'DC=lab,DC=test' }
            Forest                = [pscustomobject]@{ Domains = @('lab.test'); UPNSuffixes = @('lab.test') }
            DomainDn              = 'DC=lab,DC=test'
            UsersRootOU           = 'OU=Users,OU=Company,DC=lab,DC=test'
            UsersRootDN           = 'OU=Users,OU=Company,DC=lab,DC=test'
            UpnSuffix             = 'lab.test'
            ValidUpnSuffixes      = @('lab.test')
            EmailDomain           = 'lab.test'
            Company               = 'Lab Corp'
            LogPath               = $global:TestRoot
            AuditPath             = (Join-Path $global:TestRoot ('audit-' + [guid]::NewGuid().ToString('N') + '.csv'))
            TranscriptPath        = (Join-Path $global:TestRoot 'transcript.log')
            PasswordMode          = $Mode
            CredentialExportPath  = $ExportPath
            AllowPrivilegedGroups = $AllowPrivileged
            StopOnError           = $false
            PlanOnly              = $false
            PrivilegedGroups      = @()
            Departments           = @{
                Finance     = [pscustomobject]@{ Name = 'Finance'; OU = 'OU=Finance,OU=Departments'; Groups = @('Finance Team') }
                Engineering = [pscustomobject]@{ Name = 'Engineering'; OU = 'OU=Engineering,OU=Departments'; Groups = @('Engineering Team') }
            }
            Operator              = 'LAB\tester'
            HostName              = 'testhost'
            StartedUtc            = (Get-Date)
            QueryCache            = @{}
        }
    }

    function New-TestCsv {
        param([string]$Path, [string[]]$Rows)
        $header = 'FirstName,MiddleName,LastName,Department,Title,Manager,SamAccountName,UserPrincipalName,EmailAddress,EmployeeID,Groups,OU'
        Set-Content -LiteralPath $Path -Value (@($header) + $Rows) -Encoding UTF8
    }

    function New-Manager {
        param([string]$Sam = 'mgr.finance')
        [pscustomobject]@{
            SamAccountName    = $Sam
            DistinguishedName = "CN=$Sam,OU=Users,OU=Company,DC=lab,DC=test"
            Enabled           = $true
        }
    }

    function New-SecurityGroup {
        param([string]$Name)
        if ($global:MockGroupNameOverride) { $Name = $global:MockGroupNameOverride }
        [pscustomobject]@{
            Name              = $Name
            DistinguishedName = "CN=$Name,OU=Groups,DC=lab,DC=test"
            GroupCategory     = 'Security'
            GroupScope        = 'Global'
            ObjectSid         = $null
            AdminCount        = 0
            MemberOf          = if ($global:MockGroupMemberOf) { $global:MockGroupMemberOf } else { @() }
        }
    }

    function Reset-TestState {
        $global:MockManager = $null
        $global:MockExistingSam = $null
        $global:MockExistingUpn = $null
        $global:MockExistingEmail = $null
        $global:MockExistingEmployee = $null
        $global:MockExistingCn = $null
        $global:MockExistingObject = $null
        $global:MockMissingGroup = $null
        $global:MockNewUserError = $null
        $global:MockGroupError = $null
        $global:MockCreatedSam = $null
        $global:MockCreatedDn = $null
        $global:MockVerifyDn = $null
        $global:MockVerifyUser = $null
        $global:MockVerifyGroupMember = $null
        $global:MockGroupNameOverride = $null
        $global:MockGroupMemberOf = $null
        $global:testEnabled = $false
        $global:newUserCalls = 0
        $global:setPasswordCalls = 0
        $global:enableCalls = 0
        $global:disableCalls = 0
        $global:removeCalls = 0
    }

    $script:DefaultMocks = {
        Mock Get-ADDomainController { [pscustomobject]@{ HostName = 'dc01.lab.test' } }
        Mock Get-ADDomain { [pscustomobject]@{ DNSRoot = 'lab.test'; DistinguishedName = 'DC=lab,DC=test' } }
        Mock Get-ADForest { [pscustomobject]@{ Domains = @('lab.test'); UPNSuffixes = @('lab.test') } }
        Mock Get-ADOrganizationalUnit { param($Identity) [pscustomobject]@{ DistinguishedName = $Identity } }
        Mock Get-ADUser {
            param($Identity, $LDAPFilter)
            if ($Identity) {
                if ($global:MockManager -and $Identity -eq $global:MockManager.SamAccountName) { return $global:MockManager }
                if ($global:MockCreatedSam -and $Identity -eq $global:MockCreatedSam) { return [pscustomobject]@{ DistinguishedName = $global:MockCreatedDn } }
                if ($global:MockVerifyDn -and $Identity -eq $global:MockVerifyDn -and $global:MockVerifyUser) { return (& $global:MockVerifyUser) }
                return @()
            }
            if ($LDAPFilter) {
                if ($global:MockExistingSam -and $LDAPFilter -eq ('(sAMAccountName={0})' -f $global:MockExistingSam)) { return @($global:MockExistingObject) }
                if ($global:MockExistingUpn -and $LDAPFilter -eq ('(userPrincipalName={0})' -f $global:MockExistingUpn)) { return @($global:MockExistingObject) }
                if ($global:MockExistingEmail -and $LDAPFilter -like ('*(mail={0})*' -f $global:MockExistingEmail)) { return @($global:MockExistingObject) }
                if ($global:MockExistingEmployee -and $LDAPFilter -eq ('(employeeID={0})' -f $global:MockExistingEmployee)) { return @($global:MockExistingObject) }
            }
            return @()
        }
        Mock Get-ADGroup {
            param($Identity)
            if ($global:MockMissingGroup -and $Identity -eq $global:MockMissingGroup) { throw 'not found' }
            New-SecurityGroup -Name $Identity
        }
        Mock Get-ADObject {
            param($LDAPFilter)
            if ($global:MockExistingCn -and $LDAPFilter -eq ('(cn={0})' -f $global:MockExistingCn)) { return @($global:MockExistingObject) }
            return @()
        }
        Mock Set-ADUser { $global:setPasswordCalls++ }
        Mock New-ADUser {
            $global:newUserCalls++
            if ($global:MockNewUserError) { throw $global:MockNewUserError }
            $global:testEnabled = $false
        }
        Mock Add-ADGroupMember {
            if ($global:MockGroupError) { throw $global:MockGroupError }
        }
        Mock Enable-ADAccount { $global:enableCalls++; $global:testEnabled = $true }
        Mock Disable-ADAccount { $global:disableCalls++; $global:testEnabled = $false }
        Mock Remove-ADUser { $global:removeCalls++; throw 'Remove-ADUser must never be called' }
        Mock Remove-ADGroupMember { throw 'Remove-ADGroupMember must never be called' }
        Mock Get-ADGroupMember {
            if ($global:MockVerifyGroupMember) { [pscustomobject]@{ DistinguishedName = $global:MockVerifyGroupMember } }
        }
    }

    Describe 'SamAccountName generation' {
        It 'removes diacritics, apostrophes, and spaces' {
            ConvertTo-ADSamAccountName -FirstName ('Jos' + [char]0x00E9) -LastName "O'Brien" | Should Be 'jose.obrien'
            ConvertTo-ADSamAccountName -FirstName 'Anne-Marie' -LastName 'Berg' | Should Be 'anne-marie.berg'
        }
        It 'truncates to 20 characters without a trailing separator' {
            $sam = ConvertTo-ADSamAccountName -FirstName 'Abcdefghijklmnop' -LastName 'Qrstuvwxyz'
            $sam.Length | Should BeLessThan 21
            $sam | Should Not Match '[.-]$'
        }
        It 'rejects invalid SamAccountName values' {
            Test-ADSamAccountName -Value 'user name' | Should Not BeNullOrEmpty
            Test-ADSamAccountName -Value ('a' * 21) | Should Not BeNullOrEmpty
            Test-ADSamAccountName -Value 'user.' | Should Not BeNullOrEmpty
            Test-ADSamAccountName -Value 'user.name' | Should BeNullOrEmpty
        }
    }

    Describe 'LDAP filter escaping' {
        It 'escapes the RFC 4515 special characters' {
            ConvertTo-ADLdapFilterValue -Value 'a*b(c)\d' | Should Be 'a\2ab\28c\29\5cd'
        }
        It 'leaves ordinary values unchanged' {
            ConvertTo-ADLdapFilterValue -Value 'jane.doe@lab.test' | Should Be 'jane.doe@lab.test'
        }
    }

    Describe 'Name validation' {
        It 'accepts names with apostrophes and accents' {
            Test-ADPersonName -Value "O'Brien" -Field 'LastName' | Should BeNullOrEmpty
            Test-ADPersonName -Value ('Jos' + [char]0x00E9) -Field 'FirstName' | Should BeNullOrEmpty
        }
        It 'rejects control characters and path characters' {
            Test-ADPersonName -Value "Bad`tName" -Field 'FirstName' | Should Match 'control'
            Test-ADPersonName -Value 'Bad/Name' -Field 'LastName' | Should Match 'unsupported'
            Test-ADPersonName -Value '   ' -Field 'FirstName' | Should Not BeNullOrEmpty
        }
    }

    Describe 'CSV import' {
        BeforeEach {
            Reset-TestState
            . $script:DefaultMocks
        }

        It 'rejects a CSV without required columns' {
            $path = Join-Path $global:TestRoot 'bad.csv'
            Set-Content -LiteralPath $path -Value 'FirstName,Department' -Encoding UTF8
            { Import-ADProvisioningCsv -Path $path } | Should Throw
        }

        It 'rejects an empty CSV' {
            $path = Join-Path $global:TestRoot 'empty.csv'
            Set-Content -LiteralPath $path -Value '' -Encoding UTF8
            { Import-ADProvisioningCsv -Path $path } | Should Throw
        }

        It 'trims values and collapses whitespace' {
            $path = Join-Path $global:TestRoot 'trim.csv'
            New-TestCsv -Path $path -Rows @('  Jane  ,,  Doe  ,Finance,  Analyst  ,mgr.finance,,,,E-1001,,')
            $rows = @(Import-ADProvisioningCsv -Path $path)
            $rows.Count | Should Be 1
            $rows[0].FirstName | Should Be 'Jane'
            $rows[0].Title | Should Be 'Analyst'
            $rows[0].RowNumber | Should Be 2
        }
    }

    Describe 'Plan construction' {
        BeforeEach {
            Reset-TestState
            . $script:DefaultMocks
            $script:csv = Join-Path $global:TestRoot 'users.csv'
            $script:settings = New-TestSettings -CsvPath $script:csv -ConfigPath (Join-Path $global:TestRoot 'departments.json') -ExportPath (Join-Path $global:TestRoot 'credentials.csv')
            $global:MockManager = New-Manager
        }

        It 'builds a complete create plan' {
            New-TestCsv -Path $script:csv -Rows @('Jane,,Doe,Finance,Analyst,mgr.finance,,,,E-1001,,')
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $plan.CreateCount | Should Be 1
            $row = $plan.Rows[0]
            $row.Action | Should Be 'Create'
            $row.Sam | Should Be 'jane.doe'
            $row.Upn | Should Be 'jane.doe@lab.test'
            $row.Email | Should Be 'jane.doe@lab.test'
            $row.TargetOU | Should Be 'OU=Finance,OU=Departments,OU=Users,OU=Company,DC=lab,DC=test'
            $row.ManagerUser.SamAccountName | Should Be 'mgr.finance'
            @($row.GroupObjects).Count | Should Be 1
            $row.GroupObjects[0].Name | Should Be 'Finance Team'
        }

        It 'skips an existing SamAccountName' {
            New-TestCsv -Path $script:csv -Rows @('Jane,,Doe,Finance,Analyst,mgr.finance,,,,E-1001,,')
            $global:MockExistingSam = 'jane.doe'
            $global:MockExistingObject = [pscustomobject]@{ SamAccountName = 'jane.doe'; DistinguishedName = 'CN=Existing,OU=Users,OU=Company,DC=lab,DC=test' }
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $plan.CreateCount | Should Be 0
            $plan.Rows[0].SkipReason | Should Match 'already exists'
        }

        It 'skips an existing UPN' {
            New-TestCsv -Path $script:csv -Rows @('Jane,,Doe,Finance,Analyst,mgr.finance,,,,E-1001,,')
            $global:MockExistingUpn = 'jane.doe@lab.test'
            $global:MockExistingObject = [pscustomobject]@{ SamAccountName = 'other'; DistinguishedName = 'CN=Other,OU=Users,OU=Company,DC=lab,DC=test' }
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $plan.CreateCount | Should Be 0
            $plan.Rows[0].SkipReason | Should Match 'UserPrincipalName'
        }

        It 'skips an existing email address' {
            New-TestCsv -Path $script:csv -Rows @('Jane,,Doe,Finance,Analyst,mgr.finance,,,,E-1001,,')
            $global:MockExistingEmail = 'jane.doe@lab.test'
            $global:MockExistingObject = [pscustomobject]@{ SamAccountName = 'other'; DistinguishedName = 'CN=Other,OU=Users,OU=Company,DC=lab,DC=test' }
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $plan.CreateCount | Should Be 0
            $plan.Rows[0].SkipReason | Should Match 'Email'
        }

        It 'skips an existing employeeID' {
            New-TestCsv -Path $script:csv -Rows @('Jane,,Doe,Finance,Analyst,mgr.finance,,,,E-1001,,')
            $global:MockExistingEmployee = 'E-1001'
            $global:MockExistingObject = [pscustomobject]@{ SamAccountName = 'other'; DistinguishedName = 'CN=Other,OU=Users,OU=Company,DC=lab,DC=test' }
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $plan.CreateCount | Should Be 0
            $plan.Rows[0].SkipReason | Should Match 'EmployeeID'
        }

        It 'skips a CN collision in the target OU' {
            New-TestCsv -Path $script:csv -Rows @('Jane,,Doe,Finance,Analyst,mgr.finance,,,,E-1001,,')
            $global:MockExistingCn = 'Jane Doe'
            $global:MockExistingObject = [pscustomobject]@{ DistinguishedName = 'CN=Jane Doe,OU=Finance,OU=Departments,OU=Users,OU=Company,DC=lab,DC=test' }
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $plan.CreateCount | Should Be 0
            $plan.Rows[0].SkipReason | Should Match 'already exists in the target OU'
        }

        It 'skips duplicate identities inside the CSV' {
            New-TestCsv -Path $script:csv -Rows @(
                'Jane,,Doe,Finance,Analyst,mgr.finance,,,,E-1001,,',
                'Jane,,Doe,Finance,Analyst,mgr.finance,,,,E-1001,,'
            )
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $plan.CreateCount | Should Be 0
            $plan.Rows[0].SkipReason | Should Match 'within the CSV'
            $plan.Rows[1].SkipReason | Should Match 'within the CSV'
        }

        It 'skips an unknown department' {
            New-TestCsv -Path $script:csv -Rows @('Jane,,Doe,Legal,Analyst,mgr.finance,,,,E-1001,,')
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $plan.CreateCount | Should Be 0
            $plan.Rows[0].SkipReason | Should Match 'Unknown department'
        }

        It 'skips a missing group' {
            New-TestCsv -Path $script:csv -Rows @('Jane,,Doe,Finance,Analyst,mgr.finance,,,,E-1001,Missing Group,')
            $global:MockMissingGroup = 'Missing Group'
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $plan.CreateCount | Should Be 0
            $plan.Rows[0].SkipReason | Should Match "Group 'Missing Group' was not found"
        }

        It 'skips a privileged group by default' {
            New-TestCsv -Path $script:csv -Rows @('Jane,,Doe,Finance,Analyst,mgr.finance,,,,E-1001,Domain Admins,')
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $plan.CreateCount | Should Be 0
            $plan.Rows[0].SkipReason | Should Match 'privileged'
        }

        It 'allows a privileged group with the override' {
            $script:settings.AllowPrivilegedGroups = $true
            New-TestCsv -Path $script:csv -Rows @('Jane,,Doe,Finance,Analyst,mgr.finance,,,,E-1001,Domain Admins,')
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $plan.CreateCount | Should Be 1
            $plan.Rows[0].Warnings -join ' ' | Should Match 'privileged'
        }

        It 'skips a duplicate display name and target OU inside the CSV' {
            New-TestCsv -Path $script:csv -Rows @(
                'Cn,,Dup,Finance,Analyst,mgr.finance,cn.dup.a,,,E-CN-A,,'
                'Cn,,Dup,Finance,Analyst,mgr.finance,cn.dup.b,,,E-CN-B,,'
            )
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $plan.CreateCount | Should Be 0
            $plan.Rows[0].SkipReason | Should Match 'Duplicate display name and target OU'
            $plan.Rows[1].SkipReason | Should Match 'Duplicate display name and target OU'
        }

        It 'matches configured privileged groups by resolved name even when the CSV uses a DN' {
            $script:settings.PrivilegedGroups = @('Lab Tier 0')
            $global:MockGroupNameOverride = 'Lab Tier 0'
            New-TestCsv -Path $script:csv -Rows @(
                'Dn,,Group,Finance,Analyst,mgr.finance,dn.group.a,,,E-DN-A,"CN=Lab Tier 0,OU=Groups,DC=lab,DC=test",'
            )
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $plan.CreateCount | Should Be 0
            $plan.Rows[0].SkipReason | Should Match 'privileged'
        }

        It 'fails closed when a nested parent group cannot be read' {
            $global:MockGroupMemberOf = @('CN=Unreadable,OU=Groups,DC=lab,DC=test')
            $global:MockMissingGroup = 'CN=Unreadable,OU=Groups,DC=lab,DC=test'
            New-TestCsv -Path $script:csv -Rows @(
                'Nested,,Group,Finance,Analyst,mgr.finance,nested.group.a,,,E-NEST-A,,'
            )
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $plan.CreateCount | Should Be 0
            $plan.Rows[0].SkipReason | Should Match 'privileged'
        }

        It 'skips an unresolved manager' {
            New-TestCsv -Path $script:csv -Rows @('Jane,,Doe,Finance,Analyst,nobody,,,,E-1001,,')
            $global:MockManager = $null
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $plan.CreateCount | Should Be 0
            $plan.Rows[0].SkipReason | Should Match 'not found'
        }

        It 'allows a missing manager with a warning' {
            New-TestCsv -Path $script:csv -Rows @('Jane,,Doe,Finance,Analyst,,,,,E-1001,,')
            $global:MockManager = $null
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $plan.CreateCount | Should Be 1
            $plan.Rows[0].Warnings -join ' ' | Should Match 'No manager'
        }

        It 'skips an unregistered UPN suffix' {
            New-TestCsv -Path $script:csv -Rows @('Jane,,Doe,Finance,Analyst,mgr.finance,,jane@other.test,,E-1001,,')
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $plan.CreateCount | Should Be 0
            $plan.Rows[0].SkipReason | Should Match 'not registered'
        }
    }

    Describe 'Confirmation gate' {
        It 'accepts only y or yes' {
            (Test-ADProvisioningConfirmation -Answer 'y') | Should Be $true
            (Test-ADProvisioningConfirmation -Answer 'Y') | Should Be $true
            (Test-ADProvisioningConfirmation -Answer 'yes') | Should Be $true
            (Test-ADProvisioningConfirmation -Answer 'YES') | Should Be $true
            (Test-ADProvisioningConfirmation -Answer 'n') | Should Be $false
            (Test-ADProvisioningConfirmation -Answer '') | Should Be $false
            (Test-ADProvisioningConfirmation -Answer 'yeah') | Should Be $false
        }
    }

    Describe 'Password generation' {
        It 'creates a unique complex password for each user' {
            $passwords = @()
            1..100 | ForEach-Object { $passwords += New-ADTemporaryPassword }
            @($passwords | Select-Object -Unique).Count | Should Be 100
            foreach ($password in $passwords) {
                $password.Length | Should Be 20
                $password | Should Match '[A-Z]'
                $password | Should Match '[a-z]'
                $password | Should Match '[0-9]'
                $password | Should Match '[!@#$%^&*\-_=+?]'
            }
        }
    }

    Describe 'Plan execution' {
        BeforeEach {
            Reset-TestState
            . $script:DefaultMocks
            $script:csv = Join-Path $global:TestRoot 'exec.csv'
            $script:export = Join-Path $global:TestRoot ('exec-' + [guid]::NewGuid().ToString('N') + '.csv')
            $script:settings = New-TestSettings -CsvPath $script:csv -ConfigPath (Join-Path $global:TestRoot 'departments.json') -ExportPath $script:export
            $script:dn = 'CN=Jane Doe,OU=Finance,OU=Departments,OU=Users,OU=Company,DC=lab,DC=test'
            New-TestCsv -Path $script:csv -Rows @('Jane,,Doe,Finance,Analyst,mgr.finance,,,,E-1001,,')
            $global:MockManager = New-Manager
            $global:MockCreatedSam = 'jane.doe'
            $global:MockCreatedDn = $script:dn
            $global:MockVerifyDn = $script:dn
            $global:MockVerifyGroupMember = $script:dn
            $global:MockVerifyUser = {
                [pscustomobject]@{
                    SamAccountName             = 'jane.doe'
                    UserPrincipalName          = 'jane.doe@lab.test'
                    EmailAddress               = 'jane.doe@lab.test'
                    GivenName                  = 'Jane'
                    Surname                    = 'Doe'
                    DisplayName                = 'Jane Doe'
                    Department                 = 'Finance'
                    Title                      = 'Analyst'
                    Company                    = 'Lab Corp'
                    Manager                    = 'CN=mgr.finance,OU=Users,OU=Company,DC=lab,DC=test'
                    Enabled                    = [bool]$global:testEnabled
                    EmployeeID                 = 'E-1001'
                    physicalDeliveryOfficeName = ''
                    telephoneNumber            = ''
                    mobile                     = ''
                    streetAddress              = ''
                    l                          = ''
                    st                         = ''
                    postalCode                 = ''
                    co                         = ''
                    pwdLastSet                 = 0
                }
            }
        }

        It 'creates, verifies, and enables the user' {
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $result = Invoke-ADProvisioningPlan -Plan $plan
            $result.Created | Should Be 1
            $result.Failed | Should Be 0
            $result.ExitCode | Should Be 0
            $global:newUserCalls | Should Be 1
            $global:setPasswordCalls | Should Be 1
            $global:enableCalls | Should Be 1
            $global:disableCalls | Should Be 0
            $global:removeCalls | Should Be 0
            (Get-Content -LiteralPath $script:export | Measure-Object -Line).Lines | Should Be 2
            (Get-Acl -LiteralPath $script:export).AreAccessRulesProtected | Should Be $true
            $audit = Get-Content -LiteralPath $script:settings.AuditPath -Raw
            $audit | Should Match 'Created'
            $audit | Should Not Match 'TemporaryPassword'
        }

        It 'makes no writes under -WhatIf' {
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $result = Invoke-ADProvisioningPlan -Plan $plan -WhatIf
            $global:newUserCalls | Should Be 0
            $global:setPasswordCalls | Should Be 0
            $global:enableCalls | Should Be 0
            $global:disableCalls | Should Be 0
            Test-Path -LiteralPath $script:export | Should Be $false
            Test-Path -LiteralPath $script:settings.AuditPath | Should Be $false
        }

        It 'leaves a failed creation disabled and never deletes it' {
            $global:MockNewUserError = 'simulated directory failure'
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $result = Invoke-ADProvisioningPlan -Plan $plan
            $result.Created | Should Be 0
            $result.Failed | Should Be 1
            $global:newUserCalls | Should Be 1
            $global:enableCalls | Should Be 0
            $global:removeCalls | Should Be 0
            (Get-Content -LiteralPath $script:settings.AuditPath -Raw) | Should Match 'simulated directory failure'
        }

        It 'disables a partially created account when group assignment fails' {
            $global:MockGroupError = 'simulated group failure'
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $result = Invoke-ADProvisioningPlan -Plan $plan
            $result.Created | Should Be 0
            $result.Failed | Should Be 1
            $global:disableCalls | Should Be 1
            $global:removeCalls | Should Be 0
            (Get-Content -LiteralPath $script:settings.AuditPath -Raw) | Should Match 'left disabled'
        }
    }

    Describe 'Single password mode execution' {
        BeforeEach {
            Reset-TestState
            . $script:DefaultMocks
            $script:csv = Join-Path $global:TestRoot 'single.csv'
            $script:settings = New-TestSettings -CsvPath $script:csv -ConfigPath (Join-Path $global:TestRoot 'departments.json') -ExportPath '' -Mode 'Single'
            $script:dn = 'CN=Single User,OU=Finance,OU=Departments,OU=Users,OU=Company,DC=lab,DC=test'
            New-TestCsv -Path $script:csv -Rows @('Single,,User,Finance,Analyst,mgr.finance,single.user.a,,,E-SINGLE-A,,')
            $global:MockManager = New-Manager
            $global:MockCreatedSam = 'single.user.a'
            $global:MockCreatedDn = $script:dn
            $global:MockVerifyDn = $script:dn
            $global:MockVerifyGroupMember = $script:dn
            $global:MockVerifyUser = {
                [pscustomobject]@{
                    SamAccountName = 'single.user.a'; UserPrincipalName = 'single.user.a@lab.test';
                    EmailAddress = 'single.user.a@lab.test'; GivenName = 'Single'; Surname = 'User';
                    DisplayName = 'Single User'; Department = 'Finance'; Title = 'Analyst';
                    Company = 'Lab Corp'; Manager = 'CN=mgr.finance,OU=Users,OU=Company,DC=lab,DC=test';
                    Enabled = [bool]$global:testEnabled; EmployeeID = 'E-SINGLE-A';
                    physicalDeliveryOfficeName = ''; telephoneNumber = ''; mobile = '';
                    streetAddress = ''; l = ''; st = ''; postalCode = ''; co = ''; pwdLastSet = 0
                }
            }
        }

        It 'creates and enables a user with a shared secure password' {
            $plan = Get-ADProvisioningPlan -Settings $script:settings
            $result = Invoke-ADProvisioningPlan -Plan $plan -SharedPassword (New-TestSecureString -Value 'Shared!Password123')
            $result.Created | Should Be 1
            $result.Failed | Should Be 0
            $global:setPasswordCalls | Should Be 1
            $global:enableCalls | Should Be 1
        }
    }

    Describe 'Settings validation' {
        BeforeEach {
            Reset-TestState
            . $script:DefaultMocks
            Mock Import-Module { }
            $script:csv = Join-Path $global:TestRoot 'settings.csv'
            $script:config = Join-Path $global:TestRoot 'settings.json'
            New-TestCsv -Path $script:csv -Rows @('Jane,,Doe,Finance,Analyst,,,,,E-1001,,')
            $configObject = [pscustomobject]@{
                usersRootOU = 'OU=Users,OU=Company'
                upnSuffix   = 'lab.test'
                emailDomain = 'lab.test'
                company     = 'Lab Corp'
                departments = [pscustomobject]@{
                    Finance = [pscustomobject]@{ ou = 'OU=Finance,OU=Departments'; groups = @('Finance Team') }
                }
            }
            $configObject | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:config -Encoding UTF8
            $script:log = Join-Path $global:TestRoot ('logs-' + [guid]::NewGuid().ToString('N'))
        }

        It 'builds settings from a valid configuration' {
            $settings = Get-ADProvisioningSetting -CsvPath $script:csv -DepartmentConfigPath $script:config -LogPath $script:log -PasswordMode None
            $settings.UsersRootDN | Should Be 'OU=Users,OU=Company,DC=lab,DC=test'
            $settings.UpnSuffix | Should Be 'lab.test'
            ($settings.ValidUpnSuffixes -contains 'lab.test') | Should Be $true
            $settings.AuditPath | Should Match 'provisioning-'
        }

        It 'rejects an unregistered UPN suffix' {
            { Get-ADProvisioningSetting -CsvPath $script:csv -DepartmentConfigPath $script:config -LogPath $script:log -PasswordMode None -UpnSuffix 'other.test' } | Should Throw
        }

        It 'requires a credential export path for generated passwords' {
            { Get-ADProvisioningSetting -CsvPath $script:csv -DepartmentConfigPath $script:config -LogPath $script:log -PasswordMode Generated } | Should Throw
        }
    }
}
