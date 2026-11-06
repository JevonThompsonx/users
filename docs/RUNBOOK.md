# Operator runbook

## 1. Before the run

- Confirm the CSV is the approved onboarding list and contains `FirstName`,
  `LastName`, and `Department`.
- Confirm every department in the CSV exists in `config\departments.json`.
- Confirm the target OUs and security groups already exist and are under
  `usersRootOU`.
- Confirm the managers resolve uniquely (SamAccountName or DN is safest).
- Use a delegated account with create-user and group-membership rights.
- Decide the credential mode:
  - `Generated` for normal onboarding, with a new `-CredentialExportPath`.
  - `None` if passwords are set by a separate process and accounts stay disabled.
  - `Single` only when a shared initial password is required; the prompt asks
    twice and validates length/classes.

## 2. Dry run

```powershell
.\users.ps1 -CsvPath .\users.csv `
    -DepartmentConfigPath .\config\departments.json `
    -CredentialMode Generated `
    -CredentialExportPath C:\secure\new-users.csv `
    -WhatIf
```

Review the plan:

- Each `[CREATE]` row lists the OU, UPN, email, manager, title, department,
  company, employeeID, office/phone/address fields, group source, and password
  state.
- Each `[SKIP]` row states every reason.
- The summary shows create/skip/warning counts.

`-WhatIf` makes no AD changes and writes no audit or credential file.

## 3. Execute

```powershell
.\users.ps1 -CsvPath .\users.csv `
    -DepartmentConfigPath .\config\departments.json `
    -CredentialMode Generated `
    -CredentialExportPath C:\secure\new-users.csv
```

Read the plan, then type `Y` (case-insensitive `y`/`yes`). Any other answer
aborts with no changes. `-Force` skips the gate and is intended only for a
pre-approved automated run; the plan is still printed.

## 4. Verify

- The console prints per-row `[CREATED]`, `[CREATED-DISABLED]`, `[FAILED]`, and
  a final result.
- The audit CSV is at `C:\ProgramData\ADUserProvisioning\Logs\provisioning-*.csv`
  unless `-LogPath` was supplied.
- Generated credentials are in the explicit export file. It is readable only by
  the operator, SYSTEM, and Administrators. Move it to the approved secret
  handoff location and remove the local copy when done.
- Check a sample in AD:

  ```powershell
  Get-ADUser -Identity jane.doe -Properties Department,Title,Manager,Enabled,pwdLastSet
  Get-ADGroupMember -Identity 'Finance Team' | Where-Object SamAccountName -eq 'jane.doe'
  ```

  `pwdLastSet = 0` means the user must change the temporary password at first
  logon.

## 5. If a row fails

A failure after creation leaves the new account **disabled**. The audit row says
`Creation or verification failed; the account was left disabled.` The script
does not delete the account.

1. Read the audit `Error` and `Reason` columns.
2. Fix the directory cause (missing group permission, group deleted, invalid
   manager, etc.).
3. Decide whether to rerun the CSV. A rerun with the same Sam will be skipped as
   a duplicate, so either:
   - enable the existing disabled account after fixing the cause, or
   - remove the disabled test/onboarding account through the approved manual
     process and rerun.
4. Do not delete an account just because the script failed; check whether it was
   already communicated to the user.

## 6. Rollback

The script does not implement bulk rollback, by design. To undo a successful
run, use the audit CSV to identify the exact SamAccountNames created and disable
or remove them through the approved administrative process. Never delete a user
without confirming the identity and retention requirements.

## 7. Audit retention

Keep the audit CSV and, when used, the transcript according to the
organization's onboarding-retention policy. The audit contains usernames and
directory references, not passwords. The credential export is a separate secret
and should have a shorter retention period.
