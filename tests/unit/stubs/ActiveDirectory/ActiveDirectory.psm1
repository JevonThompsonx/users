function Get-ADDomain {
    [CmdletBinding()]
    param($Server, $Credential)
}

function Get-ADForest {
    [CmdletBinding()]
    param($Server, $Credential)
}

function Get-ADDomainController {
    [CmdletBinding()]
    param($DomainName, [switch]$Discover, $Service, [switch]$ForceDiscover)
}

function Get-ADOrganizationalUnit {
    [CmdletBinding()]
    param($Identity, $Server, $Credential)
}

function Get-ADUser {
    [CmdletBinding()]
    param($Identity, $LDAPFilter, $Properties, $Server, $Credential, $SearchBase, $SearchScope)
}

function Get-ADGroup {
    [CmdletBinding()]
    param($Identity, $Properties, $Server, $Credential)
}

function Get-ADObject {
    [CmdletBinding()]
    param($SearchBase, $SearchScope, $LDAPFilter, $Server, $Credential)
}

function Get-ADGroupMember {
    [CmdletBinding()]
    param($Identity, $Server, $Credential)
}

function New-ADUser {
    [CmdletBinding()]
    param(
        $Name, $GivenName, $Surname, $DisplayName,
        [Alias('SamAccountName')] $AccountName, $UserPrincipalName,
        $EmailAddress, $Title, $Department, $Company, $Description, $EmployeeID,
        $Office, $OfficePhone, $MobilePhone, $StreetAddress, $City, $State,
        $PostalCode, $Manager, $Path,
        [Alias('AccountPassword')] $AccountSecret,
        [Alias('ChangePasswordAtLogon')] $ForceChange,
        $Enabled, $Server, $Credential, [hashtable]$OtherAttributes
    )
}

function Set-ADUser {
    [CmdletBinding()]
    param($Identity, $Server, $Credential, [Alias('ChangePasswordAtLogon')] $ForceChange)
}

function Add-ADGroupMember {
    [CmdletBinding()]
    param($Identity, $Members, $Server, $Credential)
}

function Remove-ADGroupMember {
    [CmdletBinding()]
    param($Identity, $Members, $Server, $Credential, [switch]$Confirm)
}

function Enable-ADAccount {
    [CmdletBinding()]
    param($Identity, $Server, $Credential)
}

function Disable-ADAccount {
    [CmdletBinding()]
    param($Identity, $Server, $Credential)
}

function Remove-ADUser {
    [CmdletBinding()]
    param($Identity, $Server, $Credential, [switch]$Confirm)
}

Export-ModuleMember -Function *
