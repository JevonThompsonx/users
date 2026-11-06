# AD User Provisioning — Plan and Acceptance Criteria

Status: **complete** · Owner: T3 Code session · Started and completed 2026-11-06

## 1. Objective

Deliver a production-ready, non-destructive PowerShell 5.1 script that creates
Active Directory users from a reviewed CSV, with a CSV template, automated tests,
independent review evidence, and a sanitized public repository.

The script must be safe to run in an enterprise AD by an administrator with
delegated rights. It must never modify or delete existing directory objects.

## 2. Starter review — why a rewrite is required

Source: requester-supplied starter script (`users.ps1`).

| # | Defect | Risk |
|---|---|---|
| 1 | One hardcoded temporary password for every user | Credential compromise; no per-user secrecy |
| 2 | No duplicate detection | `New-ADUser` failures, ambiguous identities |
| 3 | No `try/catch` | Partial accounts, enabled accounts with no groups |
| 4 | Group lookup happens after user creation with `continue` | Orphaned enabled users |
| 5 | Finance mapped to **Administrators** | Privilege escalation by default |
| 6 | No preview or confirmation | Unreviewed bulk changes |
| 7 | No logging or audit trail | No accountability |
| 8 | Hardcoded `DC=company,DC=local`, UPN suffix, company name | Not portable; wrong-domain risk |
| 9 | Manager resolution can throw; no validation | Aborts mid-batch |
| 10 | No `-WhatIf`, no idempotency, no exit codes | Unsafe reruns and automation |

## 3. Non-negotiable safety properties

1. **No destructive operations.** No `Remove-AD*`, no deletion, no disabling of
   existing accounts, no modification of existing users, groups, or OUs.
2. **Additive only.** The only writes are: create new user, set attributes on
   that new user, add that new user to existing groups, enable that new user.
3. **Fail closed.** Create disabled → set attributes → add groups → verify →
   enable last. Any failure leaves the new account disabled and logged.
4. **No silent skips.** Every input row ends in `Created`, `Skipped`, or
   `Failed`, with a reason.
5. **No secrets in logs.** Passwords never enter the transcript, console, audit
   CSV, or error records.
6. **Explicit approval.** A full effect preview and a `y/N` gate precede every
   write. `-WhatIf` is the supported dry run.

## 4. Deliverables

```
users.ps1                         Entry point, comment-based help, confirmation gate
src/ADUserProvisioning.psm1       Testable implementation
config/departments.example.json   Department → OU/groups map (copy and edit)
templates/UserImport.template.csv CSV schema with one example row
tests/unit/*.Tests.ps1            Pester 3.4.0 unit tests (mocked AD)
tests/integration/*               Real-AD harness and fixtures
docs/PLAN.md                      This plan
docs/TEST-MATRIX.md               Test IDs, method, result
docs/SECURITY.md                  Threat model and operating constraints
docs/RUNBOOK.md                   Operator procedure and rollback
README.md                         Quick start, parameters, CSV schema
```

## 5. Acceptance criteria

Each criterion must be demonstrated with command output or a test result.

| ID | Criterion | Proof |
|---|---|---|
| AC-01 | `-WhatIf` and answering `n` make **zero** AD writes | Before/after object-count snapshot + transcript |
| AC-02 | Duplicate detection covers SamAccountName, UPN, email, employeeID, CN-in-OU, and duplicates inside the CSV | Unit tests + real-AD fixtures |
| AC-03 | Happy path creates users with correct OU, attributes, manager, groups, UPN, enabled state, and must-change-password flag | `Get-ADUser` / `Get-ADGroupMember` assertions |
| AC-04 | Re-running the same CSV creates zero users (idempotent) | Second-run report + object counts |
| AC-05 | Missing OU/group/manager, malformed CSV, unknown department, or invalid UPN suffix blocks the affected row before any write | Preflight output; no partial objects |
| AC-06 | Privileged groups are refused unless explicitly overridden | Unit test + real-AD attempt |
| AC-07 | A simulated failure after creation leaves the account disabled and does not delete it | Mocked failure test + real-AD fault injection |
| AC-08 | Generated passwords are unique, meet complexity, and never appear in logs or console | Password tests + log scan |
| AC-09 | Audit CSV and transcript record operator, host, domain, CSV hash, and per-row outcome | Inspect artifacts |
| AC-10 | PowerShell 5.1 compatible; PSScriptAnalyzer has no Error-severity findings | Parse + analyzer output |
| AC-11 | Unit tests pass on `win11-pslab`; integration tests pass against a real AD domain | Test transcripts |
| AC-12 | Independent code, security, and verification reviews have no unresolved material findings | Review reports |
| AC-13 | Repository is sanitized and pushed to GitHub and Forgejo | Remote refs + sanitization scan |

## 6. Architecture

- `users.ps1` validates its own parameters, imports the module, and calls one
  public function. It owns the single confirmation gate.
- `ADUserProvisioning.psm1` contains small functions:
  - configuration load/validation
  - CSV import and normalization
  - SamAccountName/UPN generation and LDAP filter escaping
  - duplicate and reference resolution (OU, group, manager)
  - plan construction
  - preview rendering
  - per-user transactional creation
  - password generation and protected credential export
  - audit logging
- AD access is through the built-in `ActiveDirectory` module, pinned to one
  discovered domain controller for consistent reads and writes.
- No external dependencies; Windows PowerShell 5.1 and RSAT only.

## 7. Configuration model

- Department map is external JSON (`config/departments.json`), validated at
  startup. The example file is sanitized and uses relative OU paths under a
  `UsersRootOU`.
- CSV required columns: `FirstName`, `LastName`, `Department`.
- Optional columns: `MiddleName`, `Title`, `Manager`, `SamAccountName`,
  `UserPrincipalName`, `EmailAddress`, `EmployeeID`, `Office`, `OfficePhone`,
  `MobilePhone`, `StreetAddress`, `City`, `State`, `PostalCode`, `Country`,
  `Description`, `Groups`, `OU`.
- `Groups` and `OU` are optional per-row overrides; both are validated against
  the configured root and the privileged-group denylist.

## 8. Test strategy

### Unit (Pester 3.4.0, `win11-pslab`)

Mocks for every AD cmdlet. Covers CSV/schema validation, name normalization,
LDAP escaping, duplicate detection, plan/skip logic, privileged groups,
confirmation abort, `-WhatIf`, password generation, failure rollback, and log
redaction.

### Integration (disposable Windows Server 2022 eval DC)

A dedicated lab VM provides a real AD DS forest (`lab.example.test`), OUs,
groups, and manager accounts. The script runs on the DC (AD module present).
Assertions use `Get-ADUser`, `Get-ADGroupMember`, and object-count snapshots.
The VM is deleted after the test session; no production system is touched.

### Static

PowerShell 5.1 parser, PSScriptAnalyzer, secret/identifier scan, comment-based
help check, and a git-history sanitization scan.

## 9. Milestones and exit checks

| M | Milestone | Exit check |
|---|---|---|
| M1 | Plan approved and frozen | This document committed |
| M2 | Lab ready | pslab reachable; RSAT installed; DC answers `Get-ADDomain` |
| M3 | Tests red | Unit tests fail for missing behavior |
| M4 | Unit green | All unit tests pass on pslab |
| M5 | Integration green | All integration cases pass on real AD |
| M6 | Reviews complete | Code/security/verifier reports; material findings fixed and re-tested |
| M7 | Publish | Sanitized repo pushed; remote refs verified |

Maximum two repair cycles per review finding set; unresolved issues are reported
as PARTIAL, not hidden.

## 10. Risks and controls

| Risk | Control |
|---|---|
| Wrong domain/OU | Discover domain live; validate every OU DN under the configured root; preview shows full DNs |
| Duplicate identity | Six-way duplicate check before any write; CSV-internal duplicate detection |
| Privilege escalation | Privileged-group denylist; no default admin groups; override requires explicit switch |
| Credential exposure | Unique random passwords; secure prompt option; ACL-locked export; no secrets in logs |
| Partial creation | Disabled-first sequence; enable only after verification; no deletion |
| Replication race | All operations pinned to one DC; duplicate checks on that DC |
| Accidental rerun | Idempotent duplicate checks; second run reports skips |
| Test residue | Disposable DC deleted; pslab snapshot restored; logs/credentials removed from repo |

## 11. Out of scope

- Deleting, disabling, renaming, or modifying existing users.
- Creating OUs or groups (must exist; validated).
- Exchange mailbox provisioning, licensing, MFA enrollment, LAPS.
- HR/ticketing system integration (CSV is the interface).
- Running against a production domain from this session.

## 12. Definition of done

All AC-01 … AC-13 pass with shown evidence, both reviews are closed, the repo
contains no real company/domain/user data or secrets, and the remote
repositories contain the same verified commit.

## 13. Results

| Gate | Result |
|---|---|
| Unit tests (Pester 3.4.0, `win11-pslab`) | 37/37 passed |
| Real-AD integration (disposable `lab.example.test`) | 124/124 assertions passed |
| Interactive `n` / `y` gate | `n`: no user, no credential file; `y`: created, enabled, `pwdLastSet=0` |
| Real-AD failure injection | Account left disabled, exit 1, no deletion |
| PSScriptAnalyzer (production files) | 0 Error-severity findings |
| Independent code review | All material findings fixed and re-tested |
| Independent verification | PASS against AC-01 … AC-13 |

Detailed evidence: `docs/TEST-MATRIX.md`, `docs/VERIFICATION.md`,
`docs/REVIEW-code.md`, `docs/REVIEW-verification.md`.
