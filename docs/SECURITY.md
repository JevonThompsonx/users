# Security model

## Scope

The script creates new Active Directory users from a CSV supplied by an
operator. It is an onboarding tool, not an identity-governance or deprovisioning
tool.

## Non-destructive design

The production code contains no destructive directory operation:

- No `Remove-ADUser`, `Remove-ADGroupMember`, `Move-ADObject`, `Rename-ADObject`,
  or deletion of OUs/groups.
- No `Set-ADUser` on an existing account. `Set-ADUser` is called only on the
  distinguished name of the account just created, to set the
  must-change-password flag.
- `Disable-ADAccount` is called only on the account just created, only after a
  failure, and only when its distinguished name is known.
- `Add-ADGroupMember` is additive. Existing group membership is never removed.
- OUs and groups must already exist. The script validates them; it does not
  create, move, or modify them.

The plan preview states these effects before the `Y` gate.

## Duplicate detection

Before any write, each row is checked for:

1. Existing `sAMAccountName` in the target domain.
2. Existing `userPrincipalName` across every domain in the forest.
3. Existing `mail` and `proxyAddresses: smtp:<address>` across the forest.
4. Existing `employeeID` across the forest.
5. An object with the same CN in the target OU.
6. Duplicate Sam/UPN/email/employeeID or display-name+target-OU combinations
   inside the CSV itself.

LDAP filter values are escaped per RFC 4515 (`\00`, `\28`, `\29`, `\2a`,
`\5c`) before every `-LDAPFilter` query.

## Privileged groups

The following are refused by default: Domain Admins, Enterprise Admins, Schema
Admins, Administrators, Account/Backup/Server/Print Operators, Group Policy
Creator Owners, Protected Users, Key Admins, Enterprise Key Admins, DnsAdmins,
Cert Publishers, Domain Controllers, Read-only Domain Controllers, Exchange
Organization Administrators, Organization Management, and Recipient Management.
Well-known privileged RIDs and `adminCount=1` are also treated as privileged.
Nested membership is checked recursively. The lookup fails closed: if a parent
group cannot be read, the group is treated as privileged.

A customer-specific `privilegedGroups` list in the department configuration is
matched against the resolved group name, DN, and SamAccountName, not only the
CSV text. `-AllowPrivilegedGroups` is the explicit override; it is recorded as a
warning in the plan and audit.

## Credentials

- Generated passwords use `System.Security.Cryptography.RandomNumberGenerator`,
  20 characters, at least one upper-case, lower-case, digit, and symbol
  character. Passwords are unique per user.
- The plaintext exists only in process memory long enough to create the
  `SecureString` and write the protected export. It is never written to the
  audit CSV, transcript, console, or error text.
- The generated credential file is created before the first password is written,
  with inheritance disabled and full control limited to the current user,
  SYSTEM, and BUILTIN\Administrators. If the ACL cannot be applied, the empty
  file is removed and the run aborts before user creation. Existing files are
  never overwritten.
- `Single` mode prompts twice, validates at least 12 characters and three
  character classes, and requires a password change at first logon. It is
  intended only where the onboarding process requires one shared initial secret.
- `None` mode creates disabled accounts without a password and is intended for a
  separate approved password-setting process.

## Logging

The audit CSV contains the operator, host, domain, CSV path, SHA-256 of the CSV,
row number, proposed identity, status, action, target OU, groups, manager,
reason, and error. It has no password field. The transcript is the normal
PowerShell host transcript; the script never prints a password. `-WhatIf` writes
no audit or credential file and makes no AD changes.

## Least privilege

Run with a delegated account, not Domain Admin. The account needs:

- Read access to the forest/domain and the target OUs and groups.
- `Create Child` for user objects under each target OU.
- `Write` on the `member` attribute (or the delegated "Add/remove members"
  right) on each target group.
- Read on the manager accounts.

The script discovers one domain controller and pins all reads and writes to it
to avoid replication races. It does not modify domain, forest, schema, or
Group Policy settings.

## Trust boundaries

The CSV and department JSON are operator-controlled inputs. They are validated,
but they are still trusted to contain the intended onboarding data. The script
does not fetch data from HR, email, or ticketing systems.

The `Manager`, `Groups`, and `OU` fields are references into the directory. They
are resolved and validated, not executed as code. LDAP filter values are escaped.

## Static-analysis exceptions

`PSScriptAnalyzer` reports zero Error-severity findings for `users.ps1` and
`src/ADUserProvisioning.psm1`. The remaining warnings are intentional:

- `PSAvoidUsingWriteHost`: the plan and result are an interactive colored
  operator interface. Output is also captured by the transcript.
- `PSAvoidUsingPlainTextForPassword` on `CredentialMode` and
  `CredentialExportPath`: these are a policy value and a path, not secrets. The
  only plaintext password is the by-design credential-export row, protected by
  an ACL.
- `PSUseShouldProcessForStateChangingFunctions` on `New-ADStringList`,
  `New-ADTemporaryPassword`, and `Set-ADProtectedFileAcl`: internal helpers that
  either create an in-memory object or run only after the one public
  confirmation gate.

Test fixtures contain their own analyzer warnings; they are not shipped as
production code.

## Known limitations

- No Exchange mailbox, licensing, LAPS, MFA, or home-directory provisioning.
- No HR/ticketing integration; the CSV is the interface.
- Single-domain group membership only; a group in another domain is reported as
  missing rather than resolved cross-domain.
- `Single` mode shares one temporary password by design; prefer `Generated`.
- No automatic deletion of failed new accounts. This is deliberate: an
  administrator reviews the disabled account and the audit record.

## Reporting

Do not open a public issue with a live credential or directory export. Report
security issues privately to the repository owner and include the version,
command line with secrets removed, and the audit record with personal data
redacted.
