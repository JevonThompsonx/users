# Publication record

Date: 2026-11-06.

| Remote | URL | Branch |
|---|---|---|
| GitHub | https://github.com/JevonThompsonx/users | `main` |
| Forgejo | https://forge.jsquaredadventures.com/zLeafNinja/users | `main` |

Implementation commit: `70040811aea7703c711e6f0134b316194b0277cc`
("Add safe AD user provisioning script with tests and operator docs").

Both remotes were created from the sanitized local tree. The commit does not
contain test artifacts, credential exports, local `config/departments.json`,
logs, internal hostnames, or real organization data.

Verification of the published tree:

- The implementation commit above is the same commit on both remotes.
- The commit containing this publication record is the current `main` head on
  both remotes.
- Test evidence for the implementation commit: 37/37 unit, 124/124 real-AD
  integration, 0 PSScriptAnalyzer errors.

The code and test content in the published tree is identical to the verified
local tree. The public history is a single clean root commit; earlier local
work-in-progress history was replaced so internal author metadata is not
published.

## Seafile delivery

The packaged release was also delivered to the Seafile `agent_files` library so
the requesting operator can grab it directly.

| Item | Value |
|---|---|
| Library | `agent_files` |
| Folder | `/outgoing/2026-11-06-ad-user-provisioning/` |
| Bundle | `ad-user-provisioning-2026-11-06.zip` |
| Source | `main` head at delivery time (recorded in `MANIFEST.txt`) |

Files in the delivery folder:

- `ad-user-provisioning-2026-11-06.zip` — complete repository snapshot.
- `MANIFEST.txt` — source commit, bundle SHA-256, per-file SHA-256.
- `users.ps1` — standalone entry script.
- `UserImport.template.csv` — standalone CSV template.
- `departments.example.json` — standalone department map.
- `README.md` — standalone quick start.

The bundle is built with `git archive` from the repository head at delivery
time. `MANIFEST.txt` is the authoritative hash record.
