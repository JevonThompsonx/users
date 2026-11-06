# Independent code review — findings and disposition

Reviewer: independent `code-reviewer` subagent (read-only), 2026-11-06.
Scope: `users.ps1`, `src/ADUserProvisioning.psm1`, unit and integration tests.

## Findings and disposition

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | Medium | Nested privileged-group lookup failed open when a parent group could not be read. | **Fixed.** The lookup now returns `$true` (privileged) on an unreadable parent, so the row is refused unless explicitly overridden. |
| 2 | Medium | Customer `privilegedGroups` was compared with the raw CSV value, allowing a DN/alias to bypass the list. | **Fixed.** The check now matches the resolved group name, DN, and SamAccountName. Unit test covers a DN-form group. |
| 3 | Medium | The docs/plan output claimed existing groups were "not modified"; group membership is additive by design. | **Fixed.** README, script help, plan output, PLAN, and SECURITY now state that existing users/OUs are untouched and existing groups are only added to. |
| 4 | Medium | `Single` password mode prompted once, without confirmation or complexity validation. | **Fixed.** It prompts twice, compares in memory, validates at least 12 characters and three character classes, and clears the BSTR buffers. |
| 5 | Medium | The plan preview omitted material attributes. | **Fixed.** It now prints title, department, company, employeeID, office, phones, address, country, description, group extras, and OU source. |
| 6 | Low | `-WhatIf` still wrote audit/log files in a direct `Invoke` call. | **Fixed.** `-WhatIf` skips audit rows, the audit header, credential initialization, the log directory, and the transcript. |
| 7 | Low | No CSV-internal display-name+OU duplicate check. | **Fixed.** A CN map rejects two rows with the same display name and target OU before any write. |
| 8 | Low | employeeID was checked only in the creation domain. | **Fixed.** employeeID now uses the forest-wide query used for UPN/email. |
| 9 | Low | Dead "manager cannot be the target OU" check compared a user DN with an OU DN. | **Removed.** The self-manager check remains. |
| 10 | Low | `New-ADTemporaryPassword` accepted lengths below four characters. | **Fixed.** `ValidateRange(12, 64)`. |
| 11 | Low | Run IDs could collide within the same second. | **Fixed.** Run IDs include milliseconds. |

## Residual, accepted warnings

- `PSAvoidUsingWriteHost`: intentional interactive plan/result UI; captured by
  the transcript.
- `PSAvoidUsingPlainTextForPassword` on `CredentialMode` and
  `CredentialExportPath`: false positives (policy value and path). The only
  plaintext password is the by-design ACL-protected credential export.
- `PSUseShouldProcessForStateChangingFunctions` on `New-ADStringList`,
  `New-ADTemporaryPassword`, and `Set-ADProtectedFileAcl`: internal helpers
  after the single public confirmation gate.

## Verdict after repair

**PASS** for production behavior. No Critical/High findings remained. The
Medium findings were fixed and re-tested with the 37/37 unit suite, the 124/124
integration suite, and a real-AD failure-injection run.
