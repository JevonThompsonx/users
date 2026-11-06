Set-StrictMode -Version Latest

$script:AuditHeader = 'TimestampUtc,Operator,HostName,Domain,CsvPath,CsvSha256,RowNumber,SamAccountName,UserPrincipalName,Status,Action,TargetOU,Groups,Manager,Reason,Error'

function Get-ADPropertyValue {
    param($Object, [string]$Name)

    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if ($property) { return $property.Value }
    return $null
}

function ConvertTo-ADLdapFilterValue {
    param([string]$Value)

    if ($null -eq $Value) { return '' }
    $builder = New-Object System.Text.StringBuilder
    foreach ($character in $Value.ToCharArray()) {
        switch ([int][char]$character) {
            0x00 { [void]$builder.Append('\00') }
            0x28 { [void]$builder.Append('\28') }
            0x29 { [void]$builder.Append('\29') }
            0x2a { [void]$builder.Append('\2a') }
            0x5c { [void]$builder.Append('\5c') }
            default { [void]$builder.Append($character) }
        }
    }
    return $builder.ToString()
}

function ConvertTo-ADSamAccountName {
    param([string]$FirstName, [string]$LastName)

    $text = ('{0}.{1}' -f $FirstName, $LastName)
    try {
        $decomposed = $text.Normalize([System.Text.NormalizationForm]::FormD)
    } catch {
        $decomposed = $text
    }

    $builder = New-Object System.Text.StringBuilder
    foreach ($character in $decomposed.ToCharArray()) {
        $category = [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($character)
        if ($category -ne [System.Globalization.UnicodeCategory]::NonSpacingMark) {
            [void]$builder.Append($character)
        }
    }

    $value = $builder.ToString().Normalize([System.Text.NormalizationForm]::FormC).ToLowerInvariant()
    $value = [regex]::Replace($value, '[^a-z0-9.-]', '')
    $value = [regex]::Replace($value, '\.{2,}', '.')
    $value = $value.Trim('.', '-')
    if ($value.Length -gt 20) {
        $value = $value.Substring(0, 20).TrimEnd('.', '-')
    }
    return $value
}

function Test-ADPersonName {
    param([string]$Value, [string]$Field)

    if ([string]::IsNullOrWhiteSpace($Value)) { return "$Field is required." }
    if ($Value.Length -gt 64) { return "$Field must be 64 characters or fewer." }
    if ($Value -match '[\x00-\x1F\x7F]') { return "$Field contains control characters." }
    if ($Value -match '^[\s\.\,\-\x27]+$') { return "$Field is not a valid name." }
    if ($Value -match '[\\/\[\]\:\;\|\=\+\*\?<>"]') { return "$Field contains unsupported characters." }
    return $null
}

function Test-ADSamAccountName {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return 'SamAccountName is empty.' }
    if ($Value.Length -gt 20) { return 'SamAccountName exceeds 20 characters.' }
    if ($Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { return 'SamAccountName contains unsupported characters.' }
    if ($Value -match '[.-]$') { return 'SamAccountName cannot end with a period or hyphen.' }
    return $null
}

function Test-ADUpn {
    param([string]$Value, [string[]]$ValidSuffixes)

    if ([string]::IsNullOrWhiteSpace($Value)) { return 'UserPrincipalName is empty.' }
    if ($Value.Length -gt 256) { return 'UserPrincipalName exceeds 256 characters.' }
    if ($Value -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { return 'UserPrincipalName is not a valid address.' }
    $suffix = $Value.Split('@')[-1]
    if ($ValidSuffixes -notcontains $suffix) {
        return "UserPrincipalName suffix '$suffix' is not registered in the forest."
    }
    return $null
}

function Test-ADEmailAddress {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    if ($Value.Length -gt 256) { return 'EmailAddress exceeds 256 characters.' }
    if ($Value -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { return 'EmailAddress is not a valid address.' }
    return $null
}

function New-ADStringList {

    return New-Object System.Collections.Generic.List[string]
}

function Add-ADPlanError {
    param($Row, [string]$Message)

    if (-not $Row.Errors.Contains($Message)) { $Row.Errors.Add($Message) }
}

function Add-ADPlanWarning {
    param($Row, [string]$Message)

    if (-not $Row.Warnings.Contains($Message)) { $Row.Warnings.Add($Message) }
}

function Get-ADServerArgument {
    param($Settings)

    $arguments = @{ Server = $Settings.Server }
    if ($Settings.Credential) { $arguments.Credential = $Settings.Credential }
    return $arguments
}

function Get-ADUserProperty {
    return @(
        'SamAccountName', 'UserPrincipalName', 'EmailAddress', 'GivenName', 'Surname',
        'DisplayName', 'Department', 'Title', 'Company', 'Manager', 'Enabled',
        'EmployeeID', 'physicalDeliveryOfficeName', 'telephoneNumber', 'mobile',
        'streetAddress', 'l', 'st', 'postalCode', 'co', 'pwdLastSet', 'memberOf'
    )
}

function Get-ADForestUserByFilter {
    param($Settings, [string]$Filter)

    if ($Settings.QueryCache.ContainsKey($Filter)) { return $Settings.QueryCache[$Filter] }

    $users = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[string]

    foreach ($domainName in $Settings.Forest.Domains) {
        try {
            $discoveryArguments = @{
                DomainName    = $domainName
                Discover      = $true
                Service       = 'ADWS'
                ForceDiscover = $true
            }
            if ($Settings.Credential) { $discoveryArguments.Credential = $Settings.Credential }
            $discovery = Get-ADDomainController @discoveryArguments -ErrorAction Stop
            $arguments = @{
                Server     = [string]$discovery.HostName
                LDAPFilter = $Filter
                Properties = (Get-ADUserProperty)
            }
            if ($Settings.Credential) { $arguments.Credential = $Settings.Credential }
            foreach ($user in @(Get-ADUser @arguments -ErrorAction Stop)) { $users.Add($user) }
        } catch {
            $errors.Add(("{0}: {1}" -f $domainName, (Get-ADExceptionMessage $_)))
        }
    }

    $result = [pscustomobject]@{ Users = $users.ToArray(); Errors = $errors.ToArray() }
    $Settings.QueryCache[$Filter] = $result
    return $result
}

function Resolve-ADUserReference {
    param($Settings, [string]$Value)

    $value = $Value.Trim()
    if ([string]::IsNullOrWhiteSpace($value)) {
        return [pscustomobject]@{ User = $null; Error = 'Manager is empty.' }
    }

    $arguments = Get-ADServerArgument $Settings
    $arguments.Identity = $value
    $arguments.Properties = (Get-ADUserProperty)
    try {
        $user = Get-ADUser @arguments -ErrorAction Stop
        if ($user) {
            return [pscustomobject]@{ User = $user; Error = $null }
        }
    } catch {
        if ($value -match '=') {
            return [pscustomobject]@{ User = $null; Error = "Manager '$value' was not found." }
        }
    }

    foreach ($attribute in 'sAMAccountName', 'userPrincipalName', 'employeeID', 'displayName') {
        $filter = '({0}={1})' -f $attribute, (ConvertTo-ADLdapFilterValue $value)
        $result = Get-ADForestUserByFilter -Settings $Settings -Filter $filter
        if ($result.Errors.Count -gt 0) {
            return [pscustomobject]@{ User = $null; Error = ("Manager lookup failed: {0}" -f ($result.Errors -join '; ')) }
        }
        if ($result.Users.Count -eq 1) {
            return [pscustomobject]@{ User = $result.Users[0]; Error = $null }
        }
        if ($result.Users.Count -gt 1) {
            return [pscustomobject]@{ User = $null; Error = "Manager '$value' is ambiguous; use a distinguished name or SamAccountName." }
        }
    }

    return [pscustomobject]@{ User = $null; Error = "Manager '$value' was not found." }
}

function Test-ADPrivilegedGroup {
    param(
        $Settings,
        $Group,
        [System.Collections.Generic.HashSet[string]]$Visited
    )

    if ($null -eq $Visited) {
        $Visited = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    }

    $name = [string](Get-ADPropertyValue $Group 'Name')
    $sid = [string](Get-ADPropertyValue (Get-ADPropertyValue $Group 'ObjectSid') 'Value')
    $adminCount = Get-ADPropertyValue $Group 'AdminCount'

    $privilegedNames = @(
        'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
        'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators',
        'Group Policy Creator Owners', 'Protected Users', 'Key Admins',
        'Enterprise Key Admins', 'DnsAdmins', 'Cert Publishers', 'Domain Controllers',
        'Read-only Domain Controllers', 'Enterprise Read-only Domain Controllers',
        'Exchange Organization Administrators', 'Organization Management', 'Recipient Management'
    )
    if ($privilegedNames -contains $name) { return $true }

    $privilegedRids = @(498, 512, 516, 517, 518, 519, 520, 521, 525, 526, 527, 544, 548, 549, 550, 551, 552, 553, 557)
    foreach ($rid in $privilegedRids) {
        if ($sid -match ('-{0}$' -f $rid)) { return $true }
    }
    if ($adminCount -eq 1) { return $true }

    if (-not $Visited.Add($name)) { return $false }
    foreach ($parentDn in @(Get-ADPropertyValue $Group 'MemberOf')) {
        if ([string]::IsNullOrWhiteSpace($parentDn)) { continue }
        if (-not $Visited.Add($parentDn)) { continue }
        try {
            $arguments = Get-ADServerArgument $Settings
            $arguments.Identity = $parentDn
            $arguments.Properties = @('Name', 'ObjectSid', 'AdminCount', 'MemberOf')
            $parent = Get-ADGroup @arguments -ErrorAction Stop
        } catch {
            # Fail closed: an unreadable parent may be a privileged group.
            return $true
        }
        if (Test-ADPrivilegedGroup -Settings $Settings -Group $parent -Visited $Visited) { return $true }
    }
    return $false
}

function Get-ADDepartmentConfiguration {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Department configuration not found: $Path"
    }

    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        $config = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Department configuration is not valid JSON: $($_.Exception.Message)"
    }

    if (-not (Get-ADPropertyValue $config 'departments')) {
        throw "Department configuration must contain a 'departments' object."
    }

    $departments = @{}
    foreach ($property in $config.departments.PSObject.Properties) {
        $name = $property.Name.Trim()
        if ($departments.ContainsKey($name)) {
            throw "Department '$name' is defined more than once."
        }
        $entry = $property.Value
        $ou = [string](Get-ADPropertyValue $entry 'ou')
        if ([string]::IsNullOrWhiteSpace($ou)) {
            throw "Department '$name' is missing an 'ou' value."
        }
        $groups = @()
        $groupValue = Get-ADPropertyValue $entry 'groups'
        if ($groupValue) {
            $groups = @($groupValue | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
        }
        $departments[$name] = [pscustomobject]@{
            Name   = $name
            OU     = $ou
            Groups = $groups
        }
    }

    if ($departments.Count -eq 0) { throw 'Department configuration contains no departments.' }

    return [pscustomobject]@{
        UsersRootOU      = [string](Get-ADPropertyValue $config 'usersRootOU')
        UpnSuffix        = [string](Get-ADPropertyValue $config 'upnSuffix')
        EmailDomain      = [string](Get-ADPropertyValue $config 'emailDomain')
        Company          = [string](Get-ADPropertyValue $config 'company')
        PrivilegedGroups = @((Get-ADPropertyValue $config 'privilegedGroups') | Where-Object { $_ } | ForEach-Object { [string]$_ })
        Departments      = $departments
    }
}

function Resolve-ADTargetOu {
    param($Settings, [string]$Ou)

    $value = $Ou.Trim()
    if ([string]::IsNullOrWhiteSpace($value)) { throw 'Target OU is empty.' }

    if ($value -notmatch '=') {
        $value = 'OU={0},{1}' -f $value, $Settings.UsersRootDN
    } elseif ($value -notmatch 'DC=') {
        $value = '{0},{1}' -f $value, $Settings.UsersRootDN
    }

    $arguments = Get-ADServerArgument $Settings
    $arguments.Identity = $value
    $target = Get-ADOrganizationalUnit @arguments -ErrorAction Stop

    $targetDn = [string]$target.DistinguishedName
    $isUnderRoot = $targetDn.Equals($Settings.UsersRootDN, [System.StringComparison]::OrdinalIgnoreCase) -or
        $targetDn.EndsWith((',' + $Settings.UsersRootDN), [System.StringComparison]::OrdinalIgnoreCase)
    if (-not $isUnderRoot) {
        throw "Target OU '$targetDn' is outside the configured users root '$($Settings.UsersRootDN)'."
    }
    return $targetDn
}

function Get-ADExceptionMessage {
    param($ErrorRecord)

    $message = [string]$ErrorRecord.Exception.Message
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        $message = '{0} {1}' -f $message, $ErrorRecord.ErrorDetails.Message
    }
    return ([regex]::Replace($message, '\s+', ' ')).Trim()
}

function Get-ADProvisioningSetting {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CsvPath,
        [Parameter(Mandatory)][string]$DepartmentConfigPath,
        [string]$UsersRootOU,
        [string]$UpnSuffix,
        [string]$EmailDomain,
        [string]$Company,
        [string]$Server,
        [pscredential]$Credential,
        [string]$LogPath = 'C:\ProgramData\ADUserProvisioning\Logs',
        [Alias('PasswordMode')]
        [ValidateSet('Generated', 'Single', 'None')][string]$CredentialMode = 'Generated',
        [string]$CredentialExportPath,
        [switch]$AllowPrivilegedGroups,
        [switch]$StopOnError,
        [switch]$PlanOnly
    )

    if ($env:OS -ne 'Windows_NT') {
        throw 'This script must run on Windows with the ActiveDirectory PowerShell module.'
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        throw "The ActiveDirectory module is not available: $($_.Exception.Message)"
    }
    if (-not (Get-Command New-ADUser -ErrorAction SilentlyContinue)) {
        throw 'New-ADUser was not found. Install RSAT Active Directory tools or run on a domain controller.'
    }

    if (-not (Test-Path -LiteralPath $CsvPath -PathType Leaf)) {
        throw "CSV file not found: $CsvPath"
    }
    $csvItem = Get-Item -LiteralPath $CsvPath -ErrorAction Stop
    if ($csvItem.Length -eq 0) { throw "CSV file is empty: $CsvPath" }

    $configuration = Get-ADDepartmentConfiguration -Path $DepartmentConfigPath

    if (-not $Server) {
        try {
            $discovery = Get-ADDomainController -Discover -Service ADWS -ForceDiscover -ErrorAction Stop
            $Server = [string]$discovery.HostName
        } catch {
            throw "Unable to discover a domain controller: $($_.Exception.Message)"
        }
    }

    $arguments = @{ Server = $Server }
    if ($Credential) { $arguments.Credential = $Credential }
    try {
        $domain = Get-ADDomain @arguments -ErrorAction Stop
        $forest = Get-ADForest @arguments -ErrorAction Stop
    } catch {
        throw "Unable to contact Active Directory at '$Server': $($_.Exception.Message)"
    }

    $domainDn = [string]$domain.DistinguishedName
    if ([string]::IsNullOrWhiteSpace($UsersRootOU)) { $UsersRootOU = $configuration.UsersRootOU }
    if ([string]::IsNullOrWhiteSpace($UsersRootOU)) {
        throw 'UsersRootOU is required. Set it in the department configuration or pass -UsersRootOU.'
    }
    if ($UsersRootOU -notmatch '=') { $UsersRootOU = "OU=$UsersRootOU,$domainDn" }
    elseif ($UsersRootOU -notmatch 'DC=') { $UsersRootOU = "$UsersRootOU,$domainDn" }

    $rootArguments = @{ Server = $Server; Identity = $UsersRootOU }
    if ($Credential) { $rootArguments.Credential = $Credential }
    try {
        $rootOu = Get-ADOrganizationalUnit @rootArguments -ErrorAction Stop
    } catch {
        throw "Users root OU '$UsersRootOU' was not found: $($_.Exception.Message)"
    }
    $rootDn = [string]$rootOu.DistinguishedName
    if (-not $rootDn.EndsWith($domainDn, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Users root OU '$rootDn' is outside the domain '$domainDn'."
    }

    if ([string]::IsNullOrWhiteSpace($UpnSuffix)) { $UpnSuffix = $configuration.UpnSuffix }
    if ([string]::IsNullOrWhiteSpace($UpnSuffix)) { $UpnSuffix = [string]$domain.DNSRoot }
    $validSuffixes = @([string]$domain.DNSRoot) + @($forest.UPNSuffixes | ForEach-Object { [string]$_ })
    if ($validSuffixes -notcontains $UpnSuffix) {
        throw "UPN suffix '$UpnSuffix' is not registered in the forest. Valid suffixes: $($validSuffixes -join ', ')"
    }

    if ([string]::IsNullOrWhiteSpace($EmailDomain)) { $EmailDomain = $configuration.EmailDomain }
    if (-not [string]::IsNullOrWhiteSpace($EmailDomain) -and $EmailDomain -notmatch '^[^@\s]+\.[^@\s]+$') {
        throw "EmailDomain '$EmailDomain' is not a valid domain name."
    }

    if ([string]::IsNullOrWhiteSpace($Company)) { $Company = $configuration.Company }

    if ($CredentialMode -eq 'Generated' -and -not $PlanOnly) {
        if ([string]::IsNullOrWhiteSpace($CredentialExportPath)) {
            throw 'PasswordMode Generated requires -CredentialExportPath so temporary passwords are written to a protected file.'
        }
        if (Test-Path -LiteralPath $CredentialExportPath) {
            throw "Credential export path already exists: $CredentialExportPath. Refusing to overwrite it."
        }
    }

    if ($PlanOnly) {
        $logFullPath = [System.IO.Path]::GetFullPath($LogPath)
    } else {
        if (-not (Test-Path -LiteralPath $LogPath)) {
            New-Item -ItemType Directory -Path $LogPath -Force -ErrorAction Stop -WhatIf:$false | Out-Null
        }
        $logFullPath = (Resolve-Path -LiteralPath $LogPath).Path
    }
    $runId = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $auditPath = Join-Path $logFullPath ("provisioning-$runId.csv")
    $transcriptPath = Join-Path $logFullPath ("provisioning-$runId.log")

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($csvItem.FullName)
    try {
        $csvHash = -join ($sha256.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') })
    } finally {
        $stream.Dispose()
        $sha256.Dispose()
    }

    $settings = [pscustomobject]@{
        CsvPath              = $csvItem.FullName
        CsvHash              = $csvHash
        DepartmentConfigPath = (Resolve-Path -LiteralPath $DepartmentConfigPath).Path
        Server               = $Server
        Credential           = $Credential
        Domain               = $domain
        Forest               = $forest
        DomainDn             = $domainDn
        UsersRootOU          = $UsersRootOU
        UsersRootDN          = $rootDn
        UpnSuffix            = $UpnSuffix
        ValidUpnSuffixes     = $validSuffixes
        EmailDomain          = $EmailDomain
        Company              = $Company
        LogPath              = $logFullPath
        AuditPath            = $auditPath
        TranscriptPath       = $transcriptPath
        PasswordMode         = $CredentialMode
        CredentialExportPath = $CredentialExportPath
        AllowPrivilegedGroups = [bool]$AllowPrivilegedGroups
        StopOnError          = [bool]$StopOnError
        PlanOnly             = [bool]$PlanOnly
        PrivilegedGroups     = @($configuration.PrivilegedGroups)
        Departments          = $configuration.Departments
        Operator             = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        HostName             = [string]$env:COMPUTERNAME
        StartedUtc           = (Get-Date).ToUniversalTime()
        QueryCache           = @{}
    }
    return $settings
}

function Import-ADProvisioningCsv {
    param([string]$Path)

    try {
        $rawRows = @(Import-Csv -LiteralPath $Path -ErrorAction Stop)
    } catch {
        throw "CSV could not be read: $($_.Exception.Message)"
    }
    if ($rawRows.Count -eq 0) { throw 'CSV contains no data rows.' }

    $headers = @($rawRows[0].PSObject.Properties.Name)
    foreach ($required in 'FirstName', 'LastName', 'Department') {
        if ($headers -notcontains $required) {
            throw "CSV is missing required column '$required'. Required columns: FirstName, LastName, Department."
        }
    }

    $knownColumns = @(
        'FirstName', 'MiddleName', 'LastName', 'Department', 'Title', 'Manager',
        'SamAccountName', 'UserPrincipalName', 'EmailAddress', 'EmployeeID',
        'Office', 'OfficePhone', 'MobilePhone', 'StreetAddress', 'City', 'State',
        'PostalCode', 'Country', 'Description', 'Groups', 'OU'
    )
    $unknownColumns = @($headers | Where-Object { $knownColumns -notcontains $_ })
    if ($unknownColumns.Count -gt 0) {
        Write-Warning ("Ignoring unknown CSV columns: {0}" -f ($unknownColumns -join ', '))
    }

    $rows = New-Object System.Collections.Generic.List[object]
    $rowNumber = 1
    foreach ($raw in $rawRows) {
        $rowNumber++
        $row = [pscustomobject]@{
            RowNumber        = $rowNumber
            FirstName        = [string](Get-ADPropertyValue $raw 'FirstName')
            MiddleName       = [string](Get-ADPropertyValue $raw 'MiddleName')
            LastName         = [string](Get-ADPropertyValue $raw 'LastName')
            Department       = [string](Get-ADPropertyValue $raw 'Department')
            Title            = [string](Get-ADPropertyValue $raw 'Title')
            Manager          = [string](Get-ADPropertyValue $raw 'Manager')
            SamAccountName   = [string](Get-ADPropertyValue $raw 'SamAccountName')
            UserPrincipalName = [string](Get-ADPropertyValue $raw 'UserPrincipalName')
            EmailAddress     = [string](Get-ADPropertyValue $raw 'EmailAddress')
            EmployeeID       = [string](Get-ADPropertyValue $raw 'EmployeeID')
            Office           = [string](Get-ADPropertyValue $raw 'Office')
            OfficePhone      = [string](Get-ADPropertyValue $raw 'OfficePhone')
            MobilePhone      = [string](Get-ADPropertyValue $raw 'MobilePhone')
            StreetAddress    = [string](Get-ADPropertyValue $raw 'StreetAddress')
            City             = [string](Get-ADPropertyValue $raw 'City')
            State            = [string](Get-ADPropertyValue $raw 'State')
            PostalCode       = [string](Get-ADPropertyValue $raw 'PostalCode')
            Country          = [string](Get-ADPropertyValue $raw 'Country')
            Description      = [string](Get-ADPropertyValue $raw 'Description')
            Groups           = [string](Get-ADPropertyValue $raw 'Groups')
            OU               = [string](Get-ADPropertyValue $raw 'OU')
            Errors           = (New-ADStringList)
            Warnings         = (New-ADStringList)
        }

        foreach ($field in 'FirstName', 'MiddleName', 'LastName', 'Department', 'Title', 'Manager',
            'SamAccountName', 'UserPrincipalName', 'EmailAddress', 'EmployeeID', 'Office',
            'OfficePhone', 'MobilePhone', 'StreetAddress', 'City', 'State', 'PostalCode',
            'Country', 'Description', 'Groups', 'OU') {
            $value = [string](Get-ADPropertyValue $row $field)
            $value = [regex]::Replace($value, '[\x00-\x1F\x7F]', '')
            $value = [regex]::Replace($value, '\s+', ' ').Trim()
            $row.$field = $value
        }

        $isEmpty = $true
        foreach ($field in 'FirstName', 'LastName', 'Department', 'Title', 'Manager',
            'SamAccountName', 'UserPrincipalName', 'EmailAddress', 'EmployeeID') {
            if (-not [string]::IsNullOrWhiteSpace([string](Get-ADPropertyValue $row $field))) {
                $isEmpty = $false
                break
            }
        }
        if ($isEmpty) {
            Add-ADPlanError $row 'Row is empty.'
        }
        $rows.Add($row)
    }
    return $rows.ToArray()
}

function Get-ADProvisioningPlan {

    [CmdletBinding()]
    param($Settings)

    $rows = Import-ADProvisioningCsv -Path $Settings.CsvPath

    foreach ($row in $rows) {
        foreach ($field in 'FirstName', 'LastName') {
            $problem = Test-ADPersonName -Value ([string]$row.$field) -Field $field
            if ($problem) { Add-ADPlanError $row $problem }
        }
        if ([string]::IsNullOrWhiteSpace($row.Department)) {
            Add-ADPlanError $row 'Department is required.'
        }

        $displayParts = @($row.FirstName, $row.MiddleName, $row.LastName) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        $row | Add-Member -NotePropertyName DisplayName -NotePropertyValue (($displayParts -join ' ').Trim()) -Force

        $sam = $row.SamAccountName
        if ([string]::IsNullOrWhiteSpace($sam)) {
            $sam = ConvertTo-ADSamAccountName -FirstName $row.FirstName -LastName $row.LastName
            $row | Add-Member -NotePropertyName SamWasGenerated -NotePropertyValue $true -Force
        } else {
            $row | Add-Member -NotePropertyName SamWasGenerated -NotePropertyValue $false -Force
        }
        $samProblem = Test-ADSamAccountName -Value $sam
        if ($samProblem) { Add-ADPlanError $row $samProblem }
        $row | Add-Member -NotePropertyName Sam -NotePropertyValue $sam -Force

        $upn = $row.UserPrincipalName
        $upnWasGenerated = $false
        if ([string]::IsNullOrWhiteSpace($upn) -and -not [string]::IsNullOrWhiteSpace($sam)) {
            $upn = '{0}@{1}' -f $sam.ToLowerInvariant(), $Settings.UpnSuffix
            $upnWasGenerated = $true
        }
        if (-not [string]::IsNullOrWhiteSpace($upn)) {
            $upnProblem = Test-ADUpn -Value $upn -ValidSuffixes $Settings.ValidUpnSuffixes
            if ($upnProblem) { Add-ADPlanError $row $upnProblem }
        } else {
            Add-ADPlanError $row 'UserPrincipalName could not be generated.'
        }
        $row | Add-Member -NotePropertyName Upn -NotePropertyValue $upn -Force
        $row | Add-Member -NotePropertyName UpnWasGenerated -NotePropertyValue $upnWasGenerated -Force

        $email = $row.EmailAddress
        if ([string]::IsNullOrWhiteSpace($email) -and -not [string]::IsNullOrWhiteSpace($Settings.EmailDomain) -and -not [string]::IsNullOrWhiteSpace($sam)) {
            $email = '{0}@{1}' -f $sam.ToLowerInvariant(), $Settings.EmailDomain
        }
        $emailProblem = Test-ADEmailAddress -Value $email
        if ($emailProblem) { Add-ADPlanError $row $emailProblem }
        $row | Add-Member -NotePropertyName Email -NotePropertyValue $email -Force

        if (-not [string]::IsNullOrWhiteSpace($row.EmployeeID) -and $row.EmployeeID.Length -gt 16) {
            Add-ADPlanError $row 'EmployeeID must be 16 characters or fewer.'
        }
        if (-not [string]::IsNullOrWhiteSpace($row.Title) -and $row.Title.Length -gt 128) {
            Add-ADPlanError $row 'Title must be 128 characters or fewer.'
        }
        if (-not [string]::IsNullOrWhiteSpace($row.Description) -and $row.Description.Length -gt 1024) {
            Add-ADPlanError $row 'Description must be 1024 characters or fewer.'
        }
        if (-not [string]::IsNullOrWhiteSpace($row.Country) -and $row.Country.Length -gt 128) {
            Add-ADPlanError $row 'Country must be 128 characters or fewer.'
        }

        $row | Add-Member -NotePropertyName TargetOU -NotePropertyValue $null -Force
        $row | Add-Member -NotePropertyName DepartmentConfig -NotePropertyValue $null -Force
        $row | Add-Member -NotePropertyName GroupObjects -NotePropertyValue @() -Force
        $row | Add-Member -NotePropertyName ManagerUser -NotePropertyValue $null -Force
        $row | Add-Member -NotePropertyName Action -NotePropertyValue 'Skip' -Force
        $row | Add-Member -NotePropertyName SkipReason -NotePropertyValue '' -Force
    }

    $keyGroups = @{}
    foreach ($attribute in 'Sam', 'Upn', 'Email') {
        $map = @{}
        foreach ($row in $rows) {
            $value = [string](Get-ADPropertyValue $row $attribute)
            if ([string]::IsNullOrWhiteSpace($value)) { continue }
            $key = $value.ToLowerInvariant()
            if (-not $map.ContainsKey($key)) { $map[$key] = New-Object System.Collections.Generic.List[object] }
            $map[$key].Add($row)
        }
        $keyGroups[$attribute] = $map
    }

    $employeeMap = @{}
    foreach ($row in $rows) {
        if ([string]::IsNullOrWhiteSpace($row.EmployeeID)) { continue }
        $key = $row.EmployeeID.ToLowerInvariant()
        if (-not $employeeMap.ContainsKey($key)) { $employeeMap[$key] = New-Object System.Collections.Generic.List[object] }
        $employeeMap[$key].Add($row)
    }
    $keyGroups['EmployeeID'] = $employeeMap

    foreach ($attribute in 'Sam', 'Upn', 'Email', 'EmployeeID') {
        foreach ($entry in $keyGroups[$attribute].GetEnumerator()) {
            if ($entry.Value.Count -lt 2) { continue }
            $rowsInConflict = @($entry.Value | ForEach-Object { $_.RowNumber }) -join ', '
            foreach ($row in $entry.Value) {
                Add-ADPlanError $row ("Duplicate {0} '{1}' within the CSV (rows {2})." -f $attribute, $entry.Key, $rowsInConflict)
            }
        }
    }

    $cnMap = @{}
    foreach ($row in $rows) {
        if ($row.Department -and $Settings.Departments.ContainsKey($row.Department)) {
            $row.DepartmentConfig = $Settings.Departments[$row.Department]
        } elseif ($row.Department) {
            Add-ADPlanError $row ("Unknown department '{0}'." -f $row.Department)
        }

        if (-not [string]::IsNullOrWhiteSpace($row.OU)) {
            try {
                $row.TargetOU = Resolve-ADTargetOu -Settings $Settings -Ou $row.OU
            } catch {
                Add-ADPlanError $row $_.Exception.Message
            }
        } elseif ($row.DepartmentConfig -and -not [string]::IsNullOrWhiteSpace($row.DepartmentConfig.OU)) {
            try {
                $row.TargetOU = Resolve-ADTargetOu -Settings $Settings -Ou $row.DepartmentConfig.OU
            } catch {
                Add-ADPlanError $row $_.Exception.Message
            }
        } else {
            Add-ADPlanError $row 'No target OU was resolved.'
        }

        if (-not [string]::IsNullOrWhiteSpace($row.TargetOU) -and -not [string]::IsNullOrWhiteSpace($row.DisplayName)) {
            $cnKey = ('{0}|{1}' -f $row.TargetOU, $row.DisplayName).ToLowerInvariant()
            if (-not $cnMap.ContainsKey($cnKey)) { $cnMap[$cnKey] = New-Object System.Collections.Generic.List[object] }
            $cnMap[$cnKey].Add($row)
        }

        if ($row.Errors.Count -gt 0) { continue }

        $arguments = Get-ADServerArgument $Settings

        if (-not [string]::IsNullOrWhiteSpace($row.Sam)) {
            $filter = '(sAMAccountName={0})' -f (ConvertTo-ADLdapFilterValue $row.Sam)
            $arguments.LDAPFilter = $filter
            $arguments.Properties = @('SamAccountName', 'UserPrincipalName')
            try {
                $duplicates = @(Get-ADUser @arguments -ErrorAction Stop)
            } catch {
                Add-ADPlanError $row ("SamAccountName lookup failed: {0}" -f (Get-ADExceptionMessage $_))
                $duplicates = @()
            }
            if ($duplicates.Count -gt 0) {
                Add-ADPlanError $row ("SamAccountName '{0}' already exists ({1})." -f $row.Sam, $duplicates[0].DistinguishedName)
            }
        }

        $filter = '(userPrincipalName={0})' -f (ConvertTo-ADLdapFilterValue $row.Upn)
        $forestResult = Get-ADForestUserByFilter -Settings $Settings -Filter $filter
        if ($forestResult.Errors.Count -gt 0) {
            Add-ADPlanError $row ("UserPrincipalName lookup failed: {0}" -f ($forestResult.Errors -join '; '))
        } elseif ($forestResult.Users.Count -gt 0) {
            Add-ADPlanError $row ("UserPrincipalName '{0}' already exists ({1})." -f $row.Upn, $forestResult.Users[0].DistinguishedName)
        }

        if (-not [string]::IsNullOrWhiteSpace($row.Email)) {
            $emailFilter = '(|(mail={0})(proxyAddresses=smtp:{0}))' -f (ConvertTo-ADLdapFilterValue $row.Email)
            $emailResult = Get-ADForestUserByFilter -Settings $Settings -Filter $emailFilter
            if ($emailResult.Errors.Count -gt 0) {
                Add-ADPlanError $row ("Email lookup failed: {0}" -f ($emailResult.Errors -join '; '))
            } elseif ($emailResult.Users.Count -gt 0) {
                Add-ADPlanError $row ("Email '{0}' already exists ({1})." -f $row.Email, $emailResult.Users[0].DistinguishedName)
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($row.EmployeeID)) {
            $employeeFilter = '(employeeID={0})' -f (ConvertTo-ADLdapFilterValue $row.EmployeeID)
            $employeeResult = Get-ADForestUserByFilter -Settings $Settings -Filter $employeeFilter
            if ($employeeResult.Errors.Count -gt 0) {
                Add-ADPlanError $row ("EmployeeID lookup failed: {0}" -f ($employeeResult.Errors -join '; '))
            } elseif ($employeeResult.Users.Count -gt 0) {
                Add-ADPlanError $row ("EmployeeID '{0}' already exists ({1})." -f $row.EmployeeID, $employeeResult.Users[0].DistinguishedName)
            }
        }

        $cnFilter = '(cn={0})' -f (ConvertTo-ADLdapFilterValue $row.DisplayName)
        $arguments = Get-ADServerArgument $Settings
        $arguments.SearchBase = $row.TargetOU
        $arguments.SearchScope = 'OneLevel'
        $arguments.LDAPFilter = $cnFilter
        try {
            $cnMatches = @(Get-ADObject @arguments -ErrorAction Stop)
        } catch {
            Add-ADPlanError $row ("Common-name lookup failed: {0}" -f (Get-ADExceptionMessage $_))
            $cnMatches = @()
        }
        if ($cnMatches.Count -gt 0) {
            Add-ADPlanError $row ("An object named '{0}' already exists in the target OU." -f $row.DisplayName)
        }

        if (-not [string]::IsNullOrWhiteSpace($row.Manager)) {
            $managerResult = Resolve-ADUserReference -Settings $Settings -Value $row.Manager
            if ($managerResult.Error) {
                Add-ADPlanError $row $managerResult.Error
            } else {
                $manager = $managerResult.User
                if ($manager.SamAccountName -eq $row.Sam) {
                    Add-ADPlanError $row 'User cannot be their own manager.'
                } else {
                    $row.ManagerUser = $manager
                    if (-not $manager.Enabled) {
                        Add-ADPlanWarning $row ("Manager '{0}' is disabled." -f $manager.SamAccountName)
                    }
                }
            }
        } else {
            Add-ADPlanWarning $row 'No manager was specified.'
        }

        $groupNames = New-Object System.Collections.Generic.List[string]
        foreach ($groupName in @($row.DepartmentConfig.Groups)) {
            if (-not [string]::IsNullOrWhiteSpace($groupName) -and -not $groupNames.Contains($groupName)) { $groupNames.Add($groupName) }
        }
        foreach ($groupName in @($row.Groups.Split(';'))) {
            $trimmed = $groupName.Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimmed) -and -not $groupNames.Contains($trimmed)) { $groupNames.Add($trimmed) }
        }

        $groupObjects = New-Object System.Collections.Generic.List[object]
        foreach ($groupName in $groupNames) {
            $arguments = Get-ADServerArgument $Settings
            $arguments.Identity = $groupName
            $arguments.Properties = @('Name', 'GroupCategory', 'GroupScope', 'ObjectSid', 'AdminCount', 'MemberOf')
            try {
                $group = Get-ADGroup @arguments -ErrorAction Stop
            } catch {
                Add-ADPlanError $row ("Group '{0}' was not found." -f $groupName)
                continue
            }
            if ($group.GroupCategory -ne 'Security') {
                Add-ADPlanError $row ("Group '{0}' is a distribution group, not a security group." -f $groupName)
                continue
            }
            $sid = [string](Get-ADPropertyValue $group 'ObjectSid')
            if ($sid -match '-513$') {
                Add-ADPlanWarning $row ("Group '{0}' is the primary group and was skipped." -f $groupName)
                continue
            }
            $privileged = Test-ADPrivilegedGroup -Settings $Settings -Group $group
            $configuredPrivileged = $false
            foreach ($candidate in @($groupName, [string]$group.Name, [string]$group.DistinguishedName, [string](Get-ADPropertyValue $group 'SamAccountName'))) {
                if (-not [string]::IsNullOrWhiteSpace($candidate) -and $Settings.PrivilegedGroups -contains $candidate) {
                    $configuredPrivileged = $true
                    break
                }
            }
            if ($privileged -or $configuredPrivileged) {
                if (-not $Settings.AllowPrivilegedGroups) {
                    Add-ADPlanError $row ("Group '{0}' is privileged and requires -AllowPrivilegedGroups." -f $groupName)
                    continue
                }
                Add-ADPlanWarning $row ("Group '{0}' is privileged and was allowed by override." -f $groupName)
            }
            $groupObjects.Add([pscustomobject]@{
                Name              = $groupName
                DistinguishedName = [string]$group.DistinguishedName
                Privileged        = $privileged
            })
        }
        $row.GroupObjects = $groupObjects.ToArray()
    }

    foreach ($entry in $cnMap.GetEnumerator()) {
        if ($entry.Value.Count -lt 2) { continue }
        $rowsInConflict = @($entry.Value | ForEach-Object { $_.RowNumber }) -join ', '
        foreach ($row in $entry.Value) {
            Add-ADPlanError $row ("Duplicate display name and target OU within the CSV (rows {0})." -f $rowsInConflict)
        }
    }

    foreach ($row in $rows) {
        if ($row.Errors.Count -eq 0) {
            $row.Action = 'Create'
            $row.SkipReason = ''
        } else {
            $row.Action = 'Skip'
            $row.SkipReason = ($row.Errors -join ' ')
        }
    }

    $created = @($rows | Where-Object { $_.Action -eq 'Create' })
    $skipped = @($rows | Where-Object { $_.Action -eq 'Skip' })

    return [pscustomobject]@{
        Settings     = $Settings
        Rows         = $rows
        CreateCount  = $created.Count
        SkipCount    = $skipped.Count
        WarningCount = @($rows | Where-Object { $_.Warnings.Count -gt 0 }).Count
        GeneratedUtc = (Get-Date).ToUniversalTime()
    }
}

function Show-ADProvisioningPlan {

    [CmdletBinding()]
    param($Plan)

    $settings = $Plan.Settings
    Write-Host ''
    Write-Host 'AD user provisioning plan' -ForegroundColor Cyan
    Write-Host ('  Domain:        {0} ({1})' -f $settings.Domain.DNSRoot, $settings.DomainDn)
    Write-Host ('  DC:            {0}' -f $settings.Server)
    Write-Host ('  Users root:    {0}' -f $settings.UsersRootDN)
    Write-Host ('  CSV:           {0}' -f $settings.CsvPath)
    Write-Host ('  CSV SHA-256:   {0}' -f $settings.CsvHash)
    Write-Host ('  Operator:      {0} on {1}' -f $settings.Operator, $settings.HostName)
    Write-Host ('  Password mode: {0}' -f $settings.PasswordMode)
    if ($settings.PasswordMode -eq 'Generated') {
        Write-Host ('  Credentials:   {0} (current user + SYSTEM + Administrators only)' -f $settings.CredentialExportPath)
    } elseif ($settings.PasswordMode -eq 'Single') {
        Write-Host '  Credentials:   one shared temporary password; every user must change it at first logon'
    } else {
        Write-Host '  Credentials:   none; new accounts stay disabled'
    }
    Write-Host ''

    $createRows = @($Plan.Rows | Where-Object { $_.Action -eq 'Create' })
    $skipRows = @($Plan.Rows | Where-Object { $_.Action -eq 'Skip' })

    foreach ($row in $createRows) {
        $manager = if ($row.ManagerUser) { $row.ManagerUser.SamAccountName } else { '(none)' }
        $groups = @($row.GroupObjects | ForEach-Object { $_.Name }) -join ', '
        Write-Host ('[CREATE] row {0}: {1} ({2})' -f $row.RowNumber, $row.Sam, $row.DisplayName) -ForegroundColor Green
        Write-Host ('         OU:      {0}' -f $row.TargetOU)
        Write-Host ('         UPN:     {0}' -f $row.Upn)
        if ($row.Email) { Write-Host ('         Email:   {0}' -f $row.Email) }
        Write-Host ('         Manager: {0}' -f $manager)
        if ($row.Title) { Write-Host ('         Title:   {0}' -f $row.Title) }
        Write-Host ('         Dept:    {0}' -f $row.Department)
        if ($settings.Company) { Write-Host ('         Company: {0}' -f $settings.Company) }
        if ($row.EmployeeID) { Write-Host ('         Emp ID:  {0}' -f $row.EmployeeID) }
        if ($row.Office) { Write-Host ('         Office:  {0}' -f $row.Office) }
        if ($row.OfficePhone) { Write-Host ('         Phone:   {0}' -f $row.OfficePhone) }
        if ($row.MobilePhone) { Write-Host ('         Mobile:  {0}' -f $row.MobilePhone) }
        if ($row.StreetAddress) { Write-Host ('         Street:  {0}' -f $row.StreetAddress) }
        if ($row.City -or $row.State -or $row.PostalCode) {
            Write-Host ('         City:    {0}, {1} {2}' -f $row.City, $row.State, $row.PostalCode)
        }
        if ($row.Country) { Write-Host ('         Country: {0}' -f $row.Country) }
        if ($row.Description) { Write-Host ('         Desc:    {0}' -f $row.Description) }
        if ($row.Groups) { Write-Host ('         Extra:   per-row groups: {0}' -f $row.Groups) }
        if ($row.OU) { Write-Host '         OU src:  per-row override' } else { Write-Host '         OU src:  department mapping' }
        Write-Host ('         Groups:  {0}' -f $groups)
        foreach ($warning in $row.Warnings) {
            Write-Host ('         WARNING: {0}' -f $warning) -ForegroundColor Yellow
        }
        if ($settings.PasswordMode -eq 'None') {
            Write-Host '         State:   disabled; no password set' -ForegroundColor Yellow
        } else {
            Write-Host '         State:   disabled -> groups + attributes verified -> enabled' -ForegroundColor DarkGray
        }
    }

    foreach ($row in $skipRows) {
        Write-Host ('[SKIP]   row {0}: {1}' -f $row.RowNumber, $row.SkipReason) -ForegroundColor DarkYellow
        foreach ($warning in $row.Warnings) {
            Write-Host ('         WARNING: {0}' -f $warning) -ForegroundColor Yellow
        }
    }

    Write-Host ''
    Write-Host ('Summary: {0} create, {1} skip, {2} row(s) with warnings.' -f $Plan.CreateCount, $Plan.SkipCount, $Plan.WarningCount) -ForegroundColor Cyan
    Write-Host 'Effects: only new user objects are created; existing groups receive the new user as a member.' -ForegroundColor Cyan
    Write-Host '         Existing users and OUs are never modified or deleted; no group membership is removed.' -ForegroundColor Cyan
    Write-Host '         New users are created disabled, added to the listed groups, verified, then enabled.' -ForegroundColor Cyan
    if ($settings.PasswordMode -eq 'None') {
        Write-Host '         Accounts will remain disabled because no password will be set.' -ForegroundColor Yellow
    }
    Write-Host ''
}

function Test-ADProvisioningConfirmation {
    param([string]$Answer)

    return ($Answer -match '^(?i:y|yes)$')
}

function New-ADTemporaryPassword {

    param([int]$Length = 20)

    $sets = @(
        'ABCDEFGHJKLMNPQRSTUVWXYZ',
        'abcdefghijkmnopqrstuvwxyz',
        '23456789',
        '!@#$%^&*-_=+?'
    )
    $all = -join $sets
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $characters = New-Object System.Collections.Generic.List[char]
        foreach ($set in $sets) {
            $characters.Add($set[(Get-ADRandomInteger -Rng $rng -Maximum $set.Length)])
        }
        while ($characters.Count -lt $Length) {
            $characters.Add($all[(Get-ADRandomInteger -Rng $rng -Maximum $all.Length)])
        }
        for ($index = $characters.Count - 1; $index -gt 0; $index--) {
            $swapIndex = Get-ADRandomInteger -Rng $rng -Maximum ($index + 1)
            $temporary = $characters[$index]
            $characters[$index] = $characters[$swapIndex]
            $characters[$swapIndex] = $temporary
        }
        return (-join $characters)
    } finally {
        $rng.Dispose()
    }
}

function Get-ADRandomInteger {
    param($Rng, [int]$Maximum)

    $bytes = New-Object byte[] 4
    $Rng.GetBytes($bytes)
    $value = [System.BitConverter]::ToUInt32($bytes, 0)
    return [int]($value % $Maximum)
}

function Set-ADProtectedFileAcl {

    param([string]$Path)

    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $identities = @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
        'NT AUTHORITY\SYSTEM',
        'BUILTIN\Administrators'
    )
    foreach ($identity in ($identities | Select-Object -Unique)) {
        $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
            $identity,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule) | Out-Null
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

function Initialize-ADCredentialFile {
    param($Settings)

    $path = $Settings.CredentialExportPath
    $parent = Split-Path -Parent $path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop -WhatIf:$false | Out-Null
    }
    if (Test-Path -LiteralPath $path) { throw "Credential export path already exists: $path" }
    Set-Content -LiteralPath $path -Value 'SamAccountName,UserPrincipalName,TemporaryPassword,CreatedUtc' -Encoding UTF8 -ErrorAction Stop -WhatIf:$false
    try {
        Set-ADProtectedFileAcl -Path $path
    } catch {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        throw "Could not protect the credential file with an ACL: $($_.Exception.Message)"
    }
}

function Add-ADCredentialRecord {

    param($Settings, [string]$Sam, [string]$Upn, [string]$Password)

    $record = [pscustomobject]@{
        SamAccountName    = $Sam
        UserPrincipalName = $Upn
        TemporaryPassword = $Password
        CreatedUtc        = (Get-Date).ToUniversalTime().ToString('o')
    }
    Export-Csv -LiteralPath $Settings.CredentialExportPath -InputObject $record -Append -NoTypeInformation -Encoding UTF8 -ErrorAction Stop -WhatIf:$false
}

function Write-ADAuditRecord {
    param(
        $Settings,
        $Row,
        [string]$Status,
        [string]$Action,
        [string]$Reason,
        [string]$ErrorText
    )

    if ($WhatIfPreference) { return }

    $groups = ''
    if ($Row.GroupObjects) { $groups = (@($Row.GroupObjects | ForEach-Object { $_.Name }) -join ';') }
    $manager = ''
    if ($Row.ManagerUser) { $manager = [string]$Row.ManagerUser.DistinguishedName }

    $record = [pscustomobject]@{
        TimestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
        Operator          = $Settings.Operator
        HostName          = $Settings.HostName
        Domain            = $Settings.Domain.DNSRoot
        CsvPath           = $Settings.CsvPath
        CsvSha256         = $Settings.CsvHash
        RowNumber         = $Row.RowNumber
        SamAccountName    = [string]$Row.Sam
        UserPrincipalName = [string]$Row.Upn
        Status            = $Status
        Action            = $Action
        TargetOU          = [string]$Row.TargetOU
        Groups            = $groups
        Manager           = $manager
        Reason            = $Reason
        Error             = $ErrorText
    }
    Export-Csv -LiteralPath $Settings.AuditPath -InputObject $record -Append -NoTypeInformation -Encoding UTF8 -ErrorAction Stop -WhatIf:$false
}

function Test-ADProvisionedUser {
    param($Settings, $Row, [string]$DistinguishedName, [bool]$ExpectEnabled)

    $arguments = Get-ADServerArgument $Settings
    $arguments.Identity = $DistinguishedName
    $arguments.Properties = (Get-ADUserProperty)
    $user = Get-ADUser @arguments -ErrorAction Stop

    $checks = @(
        @{ Name = 'SamAccountName'; Expected = $Row.Sam },
        @{ Name = 'UserPrincipalName'; Expected = $Row.Upn },
        @{ Name = 'EmailAddress'; Expected = $Row.Email },
        @{ Name = 'GivenName'; Expected = $Row.FirstName },
        @{ Name = 'Surname'; Expected = $Row.LastName },
        @{ Name = 'DisplayName'; Expected = $Row.DisplayName },
        @{ Name = 'Department'; Expected = $Row.Department },
        @{ Name = 'Title'; Expected = $Row.Title },
        @{ Name = 'Company'; Expected = $Settings.Company },
        @{ Name = 'EmployeeID'; Expected = $Row.EmployeeID },
        @{ Name = 'physicalDeliveryOfficeName'; Expected = $Row.Office },
        @{ Name = 'telephoneNumber'; Expected = $Row.OfficePhone },
        @{ Name = 'mobile'; Expected = $Row.MobilePhone },
        @{ Name = 'streetAddress'; Expected = $Row.StreetAddress },
        @{ Name = 'l'; Expected = $Row.City },
        @{ Name = 'st'; Expected = $Row.State },
        @{ Name = 'postalCode'; Expected = $Row.PostalCode },
        @{ Name = 'co'; Expected = $Row.Country }
    )
    foreach ($check in $checks) {
        $expected = [string]$check.Expected
        $actual = Get-ADPropertyValue $user $check.Name
        if ($null -eq $actual) { $actual = '' }
        if (-not [string]::Equals([string]$actual, $expected, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw ("Verification failed for {0}: expected '{1}', got '{2}'." -f $check.Name, $expected, $actual)
        }
    }

    if ($Row.ManagerUser) {
        $expectedManager = [string]$Row.ManagerUser.DistinguishedName
        $actualManager = [string](Get-ADPropertyValue $user 'Manager')
        if (-not [string]::Equals($actualManager, $expectedManager, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw ("Verification failed for Manager: expected '{0}', got '{1}'." -f $expectedManager, $actualManager)
        }
    }

    if ($Settings.PasswordMode -ne 'None') {
        $pwdLastSet = Get-ADPropertyValue $user 'pwdLastSet'
        if ($null -eq $pwdLastSet -or [int64]$pwdLastSet -ne 0) {
            throw 'Verification failed: the account is not flagged to change password at next logon.'
        }
    }

    if ($ExpectEnabled -and -not [bool](Get-ADPropertyValue $user 'Enabled')) {
        throw 'Verification failed: the account is not enabled.'
    }
    if (-not $ExpectEnabled -and [bool](Get-ADPropertyValue $user 'Enabled')) {
        throw 'Verification failed: the account should be disabled.'
    }
    return $user
}

function Invoke-ADProvisioningPlan {

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        $Plan,
        [securestring]$SharedPassword
    )

    $settings = $Plan.Settings
    if ($settings.PasswordMode -eq 'Single' -and $null -eq $SharedPassword) {
        throw 'PasswordMode Single requires a shared temporary password.'
    }

    if (-not $WhatIfPreference) {
        Set-Content -LiteralPath $settings.AuditPath -Value $script:AuditHeader -Encoding UTF8 -ErrorAction Stop -WhatIf:$false
        if ($settings.PasswordMode -eq 'Generated') {
            Initialize-ADCredentialFile -Settings $settings
        }
    }

    $results = New-Object System.Collections.Generic.List[object]
    $processedRows = New-Object 'System.Collections.Generic.HashSet[int]'
    $created = 0
    $createdDisabled = 0
    $failed = 0
    $stopped = $false

    foreach ($row in @($Plan.Rows | Where-Object { $_.Action -eq 'Skip' })) {
        Write-ADAuditRecord -Settings $settings -Row $row -Status 'Skipped' -Action 'Skip' -Reason $row.SkipReason -ErrorText ''
    }

    foreach ($row in @($Plan.Rows | Where-Object { $_.Action -eq 'Create' })) {
        if ($stopped) { break }

        $target = '{0} ({1})' -f $row.Sam, $row.DisplayName
        if (-not $PSCmdlet.ShouldProcess($target, 'Create Active Directory user')) {
            Write-ADAuditRecord -Settings $settings -Row $row -Status 'WhatIf' -Action 'Create' -Reason 'ShouldProcess declined' -ErrorText ''
            $null = $processedRows.Add([int]$row.RowNumber)
            continue
        }

        $createdObject = $false
        $distinguishedName = $null
        $plainPassword = $null
        $status = 'Failed'
        $reason = ''
        $errorText = ''

        try {
            $arguments = @{
                Name                  = $row.DisplayName
                GivenName             = $row.FirstName
                Surname               = $row.LastName
                DisplayName           = $row.DisplayName
                SamAccountName        = $row.Sam
                UserPrincipalName     = $row.Upn
                Path                  = $row.TargetOU
                Enabled               = $false
                Server                = $settings.Server
            }
            if ($settings.Credential) { $arguments.Credential = $settings.Credential }
            if ($row.Email) { $arguments.EmailAddress = $row.Email }
            if ($row.Title) { $arguments.Title = $row.Title }
            if ($row.Department) { $arguments.Department = $row.Department }
            if ($settings.Company) { $arguments.Company = $settings.Company }
            if ($row.Description) { $arguments.Description = $row.Description }
            if ($row.EmployeeID) { $arguments.EmployeeID = $row.EmployeeID }
            if ($row.Office) { $arguments.Office = $row.Office }
            if ($row.OfficePhone) { $arguments.OfficePhone = $row.OfficePhone }
            if ($row.MobilePhone) { $arguments.MobilePhone = $row.MobilePhone }
            if ($row.StreetAddress) { $arguments.StreetAddress = $row.StreetAddress }
            if ($row.City) { $arguments.City = $row.City }
            if ($row.State) { $arguments.State = $row.State }
            if ($row.PostalCode) { $arguments.PostalCode = $row.PostalCode }
            if ($row.ManagerUser) { $arguments.Manager = $row.ManagerUser.DistinguishedName }
            if ($row.Country) { $arguments.OtherAttributes = @{ co = $row.Country } }

            if ($settings.PasswordMode -eq 'Generated') {
                $plainPassword = New-ADTemporaryPassword
                $securePassword = New-Object System.Security.SecureString
                foreach ($character in $plainPassword.ToCharArray()) { $securePassword.AppendChar($character) }
                $securePassword.MakeReadOnly()
                $arguments.AccountPassword = $securePassword
            } elseif ($settings.PasswordMode -eq 'Single') {
                $arguments.AccountPassword = $SharedPassword
            }

            New-ADUser @arguments -ErrorAction Stop
            $createdObject = $true

            $identityArguments = Get-ADServerArgument $settings
            $identityArguments.Identity = $row.Sam
            $distinguishedName = [string](Get-ADUser @identityArguments -ErrorAction Stop).DistinguishedName

            if ($settings.PasswordMode -ne 'None') {
                $passwordArguments = Get-ADServerArgument $settings
                $passwordArguments.Identity = $distinguishedName
                $passwordArguments.ChangePasswordAtLogon = $true
                Set-ADUser @passwordArguments -ErrorAction Stop
            }

            foreach ($group in $row.GroupObjects) {
                $groupArguments = Get-ADServerArgument $settings
                $groupArguments.Identity = $group.DistinguishedName
                $groupArguments.Members = $distinguishedName
                Add-ADGroupMember @groupArguments -ErrorAction Stop
            }

            Test-ADProvisionedUser -Settings $settings -Row $row -DistinguishedName $distinguishedName -ExpectEnabled $false | Out-Null

            foreach ($group in $row.GroupObjects) {
                $memberArguments = Get-ADServerArgument $settings
                $memberArguments.Identity = $group.DistinguishedName
                $members = @(Get-ADGroupMember @memberArguments -ErrorAction Stop | ForEach-Object { [string]$_.DistinguishedName })
                if ($members -notcontains $distinguishedName) {
                    throw ("Verification failed: user is not a member of group '{0}'." -f $group.Name)
                }
            }

            if ($settings.PasswordMode -eq 'Generated') {
                Add-ADCredentialRecord -Settings $settings -Sam $row.Sam -Upn $row.Upn -Password $plainPassword
            }

            if ($settings.PasswordMode -ne 'None') {
                $enableArguments = Get-ADServerArgument $settings
                $enableArguments.Identity = $distinguishedName
                Enable-ADAccount @enableArguments -ErrorAction Stop
                Test-ADProvisionedUser -Settings $settings -Row $row -DistinguishedName $distinguishedName -ExpectEnabled $true | Out-Null
                $status = 'Created'
                $created++
                Write-Host ('[CREATED] {0} ({1})' -f $row.Sam, $row.DisplayName) -ForegroundColor Green
            } else {
                $status = 'CreatedDisabled'
                $createdDisabled++
                Write-Host ('[CREATED-DISABLED] {0} ({1})' -f $row.Sam, $row.DisplayName) -ForegroundColor Yellow
            }
        } catch {
            $errorText = Get-ADExceptionMessage $_
            $reason = 'Creation or verification failed.'
            $failed++
            if ($createdObject -and $distinguishedName) {
                try {
                    $disableArguments = Get-ADServerArgument $settings
                    $disableArguments.Identity = $distinguishedName
                    Disable-ADAccount @disableArguments -ErrorAction Stop
                    $reason = 'Creation or verification failed; the account was left disabled.'
                } catch {
                    $reason = 'Creation or verification failed; disabling the new account also failed. Manual cleanup is required.'
                    $errorText = '{0} Disable error: {1}' -f $errorText, (Get-ADExceptionMessage $_)
                }
            }
            Write-Host ('[FAILED]  {0}: {1} {2}' -f $row.Sam, $reason, $errorText) -ForegroundColor Red
        } finally {
            $plainPassword = $null
        }

        Write-ADAuditRecord -Settings $settings -Row $row -Status $status -Action 'Create' -Reason $reason -ErrorText $errorText
        $null = $processedRows.Add([int]$row.RowNumber)
        $results.Add([pscustomobject]@{
            RowNumber         = $row.RowNumber
            SamAccountName    = $row.Sam
            UserPrincipalName = $row.Upn
            Status            = $status
            Reason            = $reason
            Error             = $errorText
        })

        if ($failed -gt 0 -and $settings.StopOnError) {
            $stopped = $true
        }
    }

    $remaining = @($Plan.Rows | Where-Object { $_.Action -eq 'Create' } | Where-Object {
        -not $processedRows.Contains([int]$_.RowNumber)
    })
    foreach ($row in $remaining) {
        Write-ADAuditRecord -Settings $settings -Row $row -Status 'NotProcessed' -Action 'Create' -Reason 'Run stopped before this row.' -ErrorText ''
    }

    $exitCode = 0
    if ($failed -gt 0) { $exitCode = 1 }
    return [pscustomobject]@{
        ExitCode       = $exitCode
        Created        = $created
        CreatedDisabled = $createdDisabled
        Failed         = $failed
        Skipped        = $Plan.SkipCount
        Results        = $results.ToArray()
        AuditPath      = $settings.AuditPath
        TranscriptPath = $settings.TranscriptPath
    }
}

Export-ModuleMember -Function Get-ADProvisioningSetting, Import-ADProvisioningCsv, Get-ADProvisioningPlan, Show-ADProvisioningPlan, Invoke-ADProvisioningPlan, Test-ADProvisioningConfirmation
