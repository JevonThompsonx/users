# AD User Provisioning

A reviewed, non-destructive PowerShell 5.1 script that creates Active Directory
users from a CSV and then gets out of the way. It is built for the case where an
IT administrator receives an onboarding list and needs a repeatable, auditable
run without touching existing accounts.

## Safety guarantees

- **No deletes, no disables of existing accounts.** The production code never
  calls `Remove-ADUser`, `Remove-ADGroupMember`, `Move-ADObject`, or
  `Disable-ADAccount` on an existing user.
- **Additive group membership only.** Existing groups receive the new user as a
  member; no membership is removed, no group is renamed or deleted.
- **Duplicate-first planning.** SamAccountName, UPN (forest-wide), email and
  `proxyAddresses` (forest-wide), employeeID (forest-wide), CN-in-target-OU, and
  duplicates inside the CSV are checked before the plan is offered.
- **Disabled-first creation.** Each user is created disabled, populated, added
  to groups, verified, and only then enabled. A failure leaves the new account
  disabled and reports that manual cleanup is required.
- **One explicit approval.** The complete effect plan is printed, then the
  script asks for `Y`. Anything else aborts without writing. `-WhatIf` prints
  the same plan and makes no changes.
- **Unique temporary passwords.** Generated per user with a cryptographic RNG,
  never written to the audit log or console, and exported only to an
  ACL-protected file that must not already exist.
- **Privileged groups are refused.** Domain Admins, Enterprise Admins,
  Administrators, and similar groups block the row unless
  `-AllowPrivilegedGroups` is supplied deliberately.

## Requirements

- Windows PowerShell 5.1 (not PowerShell 7 only).
- The `ActiveDirectory` module (RSAT `ActiveDirectory.DS-LDS.Tools` or a domain
  controller).
- Rights delegated to create user objects under the target OUs and to write
  membership on the target groups. Domain Admin is **not** required.

## Quick start

1. Copy the example department map and edit it for the domain:

   ```powershell
   Copy-Item .\config\departments.example.json .\config\departments.json
   notepad .\config\departments.json
   ```

   Set `usersRootOU`, `upnSuffix`, `emailDomain`, `company`, and the department
   OU/group mapping. `usersRootOU` is required; there is no unsafe fallback.

2. Copy the CSV template and fill in the onboarding rows:

   ```powershell
   Copy-Item .\templates\UserImport.template.csv .\users.csv
   notepad .\users.csv
   ```

3. Dry run. This shows every proposed effect and makes no AD or credential-file
   changes:

   ```powershell
   .\users.ps1 -CsvPath .\users.csv `
       -DepartmentConfigPath .\config\departments.json `
       -CredentialMode Generated `
       -CredentialExportPath C:\secure\new-users.csv `
       -WhatIf
   ```

4. Real run. The script prints the full plan and waits for `Y`:

   ```powershell
   .\users.ps1 -CsvPath .\users.csv `
       -DepartmentConfigPath .\config\departments.json `
       -CredentialMode Generated `
       -CredentialExportPath C:\secure\new-users.csv
   ```

`-PasswordMode` is accepted as an alias for `-CredentialMode`.

## CSV schema

Required columns:

| Column | Meaning |
|---|---|
| `FirstName` | Given name. |
| `LastName` | Surname. |
| `Department` | Must exist in the department map. |

Optional columns:

| Column | Destination |
|---|---|
| `MiddleName` | Included in the display name. |
| `Title` | `title` |
| `Manager` | SamAccountName, UPN, DN, employeeID, or unique display name. |
| `SamAccountName` | Override the generated `first.last` value (max 20). |
| `UserPrincipalName` | Override the generated UPN. Suffix must be registered. |
| `EmailAddress` | `mail`; otherwise generated from `emailDomain`. |
| `EmployeeID` | `employeeID` (max 16). |
| `Office` | `physicalDeliveryOfficeName` |
| `OfficePhone` | `telephoneNumber` |
| `MobilePhone` | `mobile` |
| `StreetAddress` | `streetAddress` |
| `City` | `l` |
| `State` | `st` |
| `PostalCode` | `postalCode` |
| `Country` | `co` |
| `Description` | `description` |
| `Groups` | Semicolon-separated extra groups. |
| `OU` | Per-row OU override (DN or relative to `usersRootOU`). |

Names with accents, apostrophes, and hyphens are normalized for the generated
SamAccountName. CSV-internal duplicates are rejected, including two rows with
the same display name and target OU but different explicit SamAccountNames.

## Department configuration

```json
{
  "usersRootOU": "OU=Users,OU=Company",
  "upnSuffix": "corp.example.com",
  "emailDomain": "example.com",
  "company": "Example Corporation",
  "privilegedGroups": [],
  "departments": {
    "Finance": {
      "ou": "OU=Finance,OU=Administrative,OU=Departments",
      "groups": ["Finance Team", "Standard Employee Access", "Remote Access"]
    }
  }
}
```

`usersRootOU` and department `ou` values may be relative to the domain or full
DNs. Every target OU must already exist and must sit under `usersRootOU`; the
script does not create OUs. `privilegedGroups` adds customer-specific groups to
the built-in privileged denylist.

The built-in department map is an example. Replace it with the real OU and group
names before use. A department that is not in the map is skipped with a clear
reason.

## Parameters

| Parameter | Default | Notes |
|---|---|---|
| `-CsvPath` | required | Input CSV. |
| `-DepartmentConfigPath` | `config\departments.json` | Must exist. |
| `-UsersRootOU` | config value | Required somewhere; no unsafe default. |
| `-UpnSuffix` | config, then domain DNS | Must be registered in the forest. |
| `-EmailDomain` | config | Used only when the CSV has no email. |
| `-Company` | config | Written to `company`. |
| `-Server` | discovered DC | All reads/writes pinned to it. |
| `-Credential` | current identity | Delegated admin account. |
| `-CredentialMode` | `Generated` | `Generated`, `Single`, or `None`. Alias: `-PasswordMode`. |
| `-CredentialExportPath` | required for `Generated` | Must not exist. ACL-restricted. |
| `-AllowPrivilegedGroups` | off | Explicit override for privileged groups. |
| `-StopOnError` | off | Stop after the first failed row. |
| `-Force` | off | Skip the interactive `Y` gate after printing the plan. |
| `-SkipTranscript` | off | Do not start a PowerShell transcript. |
| `-WhatIf` | off | Show the plan and make no changes. |

## Password modes

- **Generated** (default): a unique 20-character password per user, containing
  upper case, lower case, digits, and symbols. Written only to the credential
  file after creation, before enable. The file must not already exist and is
  restricted to the current user, SYSTEM, and Administrators.
- **Single**: prompts twice for one shared temporary password, validates length
  and at least three character classes, and requires every user to change it at
  first logon. Use only when the onboarding process requires a shared initial
  secret.
- **None**: creates disabled accounts with no password. Set passwords through a
  separate approved process, then enable the accounts.

## What happens per user

1. Create the user disabled in the target OU.
2. Set the generated or shared password and flag it to change at next logon.
3. Add the user to the department and per-row groups.
4. Re-read the account and every group membership and verify the result.
5. Write the credential row (Generated mode), then enable the account.
6. Re-read the account and confirm it is enabled.

Any failure after creation disables the new account and records
`Creation or verification failed; the account was left disabled.` The script
never deletes the account; an administrator reviews the audit CSV and decides
what to do.

## Output and exit codes

- Audit CSV: `C:\ProgramData\ADUserProvisioning\Logs\provisioning-<run>.csv`
  with operator, host, domain, CSV path and SHA-256, row, identity, status,
  action, OU, groups, manager, reason, and error.
- Transcript: same directory, unless `-SkipTranscript` or `-WhatIf`.
- Generated credentials: the explicit `-CredentialExportPath`.

Exit codes:

| Code | Meaning |
|---|---|
| `0` | All rows created/skipped cleanly, or the run was aborted/WhatIf. |
| `1` | One or more rows failed; review the audit CSV. |
| `2` | Preflight/configuration failure; no users were created. |

## Testing

```powershell
# Unit tests (Windows PowerShell 5.1 + Pester 3.4)
Invoke-Pester .\tests\unit\ADUserProvisioning.Tests.ps1

# Integration (disposable lab domain; see tests/integration)
.\tests\integration\lab-fixtures.ps1 -FixturePassword '<lab-only-secret>'
.\tests\integration\Run-IntegrationTests.ps1 -RepoRoot C:\adup
```

See [docs/TEST-MATRIX.md](docs/TEST-MATRIX.md) and
[docs/VERIFICATION.md](docs/VERIFICATION.md) for the recorded results.

## Troubleshooting

- **`OU=Users` collision**: a domain already has `CN=Users`; create a parent OU
  such as `OU=Users,OU=Company` and point `usersRootOU` there.
- **Missing group/OU**: the row is skipped, not created. Fix the directory or
  the config and rerun. Reruns are idempotent.
- **Privileged group refused**: that is the intended default. Use
  `-AllowPrivilegedGroups` only after a documented approval.
- **Manager ambiguous**: use the manager's SamAccountName or DN.
- **UPN suffix rejected**: the suffix is not registered in the forest. Add it or
  use the domain suffix.

## Security and operations

Read [docs/SECURITY.md](docs/SECURITY.md) and
[docs/RUNBOOK.md](docs/RUNBOOK.md) before the first production run. The short
version: run `-WhatIf`, review the plan, use a delegated account, protect the
credential export, and keep the audit CSV.

## Release bundle

A packaged copy of this repository is delivered to the Seafile `agent_files`
library under `/outgoing/2026-11-06-ad-user-provisioning/` for the requesting
operator. The bundle includes `MANIFEST.txt` with per-file SHA-256 hashes.

No license is granted by this repository; add one before redistributing.
