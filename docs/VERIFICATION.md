# Verification record

Date: 2026-11-06.

## Environment

| Component | Value |
|---|---|
| Client test VM | `win11-pslab` (Proxmox VM 9300), Windows 11 Pro, Windows PowerShell 5.1.26100 |
| Pester | 3.4.0 |
| Domain controller | disposable Windows Server 2022 Standard Core evaluation VM, `ADLAB-DC`, domain `lab.example.test` |
| Domain DN | `DC=lab,DC=example,DC=test` |
| Users root | `OU=Users,OU=Company,DC=lab,DC=example,DC=test` |
| Production systems | none contacted |

The DC was built only for this test. The user-provisioning script ran on the DC
itself, where the ActiveDirectory module is present.

## Commands and results

### Unit tests

```powershell
Invoke-Pester C:\Users\labadmin\Desktop\adup\tests\unit\ADUserProvisioning.Tests.ps1
```

```text
Tests completed in 9.81s
Passed: 37 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
```

### Integration tests

```powershell
& C:\adup\tests\integration\Run-IntegrationTests.ps1 -RepoRoot C:\adup -RunId 14d
```

```text
Integration result: 124 passed, 0 failed.
HARNESS_EXIT=0
```

The integration suite ran against real AD DS with real groups, managers, and
duplicate fixtures. It asserted object counts, OU placement, attributes,
manager DNs, enabled state, `pwdLastSet=0`, group membership, idempotency,
preflight rejection, privileged-group refusal/override, and credential-file ACL.

### Interactive confirmation

On the DC console, `C:\adup\confirm-manual.cmd` ran `users.ps1` without `-Force`.
The script printed the plan and `Type Y to create these users, or anything else
to abort:`.

- Typed `n` + Enter: `USER_EXISTS=False`, `CREDS_EXISTS=False`.
- Typed `y` + Enter: `USER_EXISTS=True`, `ENABLED=True`, `PWDLASTSET=0`,
  DN `CN=ManualN User,OU=Finance,OU=Administrative,OU=Departments,OU=Users,OU=Company,DC=lab,DC=example,DC=test`,
  credential file present.

### Real-AD failure injection

A test group `CN=Deny Membership,OU=Groups,DC=lab,DC=example,DC=test` received a
deny `WriteProperty` ACE on the `member` attribute for `LAB\Administrator`.
Direct `Add-ADGroupMember` then failed with `Insufficient access rights to
perform the operation`.

Running `users.ps1` with a row referencing that group:

```text
[FAILED]  failure.inject.14d: Creation or verification failed; the account was left disabled. Insufficient access rights to perform the operation
Result: 0 created, 0 created disabled, 1 failed, 0 skipped.
EXISTS=True ENABLED=False
```

This proves the disabled-on-failure path on real AD and confirms the account is
not deleted.

### Static analysis

```text
users.ps1: 0 Error severity
src/ADUserProvisioning.psm1: 0 Error severity
Parser: 0 syntax errors across all PowerShell files
```

Warnings are intentional and listed in `docs/SECURITY.md`.

### Sanitization

A tree scan for internal hostnames, real domains, IP addresses, personal names,
passwords, tokens, and internal file-share paths found no real identifiers. Example values
use reserved domains (`example.com`, `corp.example.com`, `lab.example.test`).
`artifacts/` and local `config/departments.json` are excluded by `.gitignore`.

## Limitations of this record

- The unit and integration runs were executed on disposable lab systems; the
  raw artifacts live on the lab VM, not in the repository.
- The integration suite is designed for a fresh lab domain. It creates users and
  does not delete them; rerun with a new `-RunId` or rebuild the lab.
- No production domain, licensing system, Exchange, or HR system was contacted.
