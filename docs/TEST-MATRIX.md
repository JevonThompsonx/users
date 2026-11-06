# Test matrix and results

Date: 2026-11-06. Windows PowerShell 5.1.26100 on `win11-pslab`; Active
Directory on a disposable Windows Server 2022 Standard Core evaluation domain
`lab.example.test` (`ADLAB-DC`). No production system was contacted.

## Acceptance criteria

| ID | Result | Evidence |
|---|---|---|
| AC-01 `-WhatIf` and `n` make zero AD writes | **PASS** | Integration A1–A5: exit 0, no user, no credential file, count unchanged, output states no changes. Manual console: `n` produced no user and no credential file; `y` created the user. Unit: confirmation helper accepts only y/yes. |
| AC-02 duplicate detection | **PASS** | Unit: existing Sam/UPN/email/employeeID, CN collision, CSV duplicates, display-name+OU duplicate. Integration F/G: existing objects and CSV duplicates blocked. Forest-wide UPN/email/employeeID queries. |
| AC-03 happy path | **PASS** | Integration D: 6 users across 6 departments; OU, UPN, email, manager, enabled, `pwdLastSet=0`, and 28 group-membership assertions. |
| AC-04 idempotency | **PASS** | Integration E: second run creates 0, count unchanged, `Summary: 0 create`. |
| AC-05 preflight blocking | **PASS** | Integration H/L/M: missing group, missing OU, unknown department, invalid UPN suffix, missing root OU. No user created before validation. |
| AC-06 privileged groups | **PASS** | Unit: Domain Admins blocked, override allowed with warning; configured custom group matched by resolved name even when CSV uses a DN. Integration I/J: Domain Admins refused; configured `Lab Tier 0` override works. |
| AC-07 failure leaves disabled, no deletion | **PASS** | Unit: create failure and group failure; no `Remove-ADUser`. Real-AD fault injection: denied `WriteProperty` on a test group's `member` attribute; group add failed, account remained disabled, exit 1, no enable. |
| AC-08 password hygiene | **PASS** | Unit: 100 unique 20-char passwords, all four classes. Integration D: credential file header+6 rows, ACL protected, password absent from audit and console. |
| AC-09 audit content | **PASS** | Audit header/rows include operator, host, domain, CSV path and SHA-256, row, status, action, OU, groups, manager, reason, error. Tested in integration and unit. `-WhatIf` intentionally writes no audit file. |
| AC-10 PS 5.1 + analyzer | **PASS** | Parser: 0 errors. PSScriptAnalyzer 1.25: 0 Error-severity findings in `users.ps1` and `src/ADUserProvisioning.psm1`; warnings documented in `docs/SECURITY.md`. |
| AC-11 unit + real AD | **PASS** | 37/37 Pester 3.4 unit assertions on `win11-pslab`; 124/124 real-AD integration assertions on `lab.example.test`. |
| AC-12 independent reviews | **PASS** | `docs/REVIEW-code.md` and `docs/REVIEW-verification.md`; all material findings fixed and re-tested. |
| AC-13 sanitized publish | **PASS** | Sanitization scan; `.gitignore` excludes artifacts and local config; repository pushed to GitHub and Forgejo (URLs in `docs/PUBLICATION.md`). |

## Unit suite (Pester 3.4.0, `win11-pslab`)

`Invoke-Pester .\tests\unit\ADUserProvisioning.Tests.ps1`

Result: **37 passed, 0 failed**. Areas: Sam normalization, name validation,
RFC 4515 escaping, CSV import, plan construction, all duplicate dimensions,
privileged groups, missing references, password generation, confirmation gate,
execution, failure handling, `-WhatIf`, settings validation.

## Integration suite (real AD)

`.\tests\integration\Run-IntegrationTests.ps1 -RepoRoot C:\adup -RunId 14d`

Result: **124 passed, 0 failed**, exit 0. Sections: WhatIf, forced creation,
6-user batch across departments, idempotent rerun, existing-object duplicates,
CSV-internal duplicates, missing references, privileged refusal, privileged
override, password mode None, invalid suffix, missing root OU, fixture
integrity, total object delta.

## Manual proofs

### Interactive y/N gate

On the domain controller console, using a one-row CSV:

- Answered `n`: no user, no credential file.
- Answered `y`: `manual.n14b` created, enabled, in
  `OU=Finance,OU=Administrative,OU=Departments,OU=Users,OU=Company,DC=lab,DC=example,DC=test`,
  `pwdLastSet=0`, credential file present.

### Real-AD fault injection (AC-07)

A test group (`Deny Membership`) was given a deny `WriteProperty` ACE on the
`member` attribute for the operator. The script created the user, failed the
group add with `Insufficient access rights`, disabled the account, returned exit
1, and left the account in place:

```
EXISTS=True ENABLED=False
Result: 0 created, 0 created disabled, 1 failed, 0 skipped.
```

## Static analysis

- `PSScriptAnalyzer` 1.25.0, `users.ps1`: 0 errors.
- `src/ADUserProvisioning.psm1`: 0 errors.
- Remaining warnings: `PSAvoidUsingWriteHost` (interactive UI),
  `PSAvoidUsingPlainTextForPassword` on policy/path values (false positives),
  and `PSUseShouldProcessForStateChangingFunctions` on internal helpers. Each is
  explained in `docs/SECURITY.md`.
- Parser check on all PowerShell files: 0 syntax errors.

## Sanitization

- No real company names, internal domains, IP addresses, hostnames, usernames,
  passwords, API tokens, or internal file-share paths in the repository.
- Example values use RFC 2606/6761 reserved names (`example.com`,
  `corp.example.com`, `lab.example.test`).
- `artifacts/`, local `config/departments.json`, logs, and credential CSVs are
  excluded by `.gitignore`.

## Not covered

- Multi-domain group membership (groups are resolved in the creation domain).
- Exchange/365 mailbox provisioning, licensing, LAPS, MFA.
- Unattended Scheduled Task execution; `-Force` is available but should be
  gated by the change process.
- Production-scale timing (hundreds of rows); duplicate queries are per-row and
  forest-wide.
