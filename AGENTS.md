# M2A / GADE Contributor Instructions

These instructions apply to every task that reads, changes, validates, or reports on this repository's M2A or GADE work. They supplement `PROJECT_CONTEXT.md`; they do not relax its safety boundaries.

## Obsidian-first knowledge workflow

The canonical project vault is `C:\Users\p2166\Documents\ChatGPT\總規則\03 專案（Projects）\M2A 專案（M2A）`. Use its existing canonical notes; do not create duplicate project notes.

### Before work

1. Read the relevant canonical note(s) for the task. For M2A/GADE troubleshooting, always read **M2A Known Issues** and **M2A Build History** first; also read **M2A Runbook** and **GADE Boundary Experiment Design** when operational steps or experiment methods are involved.
2. Search for the same or similar failure, and record the note path, heading, prior root cause, fix, verification result, and whether that fix applies to the current code/version.
3. Then inspect the current repository code, Git state/history, and run-specific evidence needed to confirm applicability. Historical notes are evidence leads, not proof that current runtime state still matches.
4. If the vault is unavailable or access is denied, report `OBSIDIAN_READ=FAIL`, identify the unavailable path, and do not claim that the notes were read. Continue only with work independent of that missing context; do not make a history-dependent fix by guessing.

### During work

1. Reuse a historical fix only after comparing its conditions and version with the current implementation.
2. Separate verified facts from hypotheses. Do not report a hypothesis as a root cause.
3. Preserve prior run evidence and avoid rerunning completed experiments to diagnose low-level code or runner defects. Prefer targeted local regression tests; perform host/runtime verification only when required and authorized.

### After work

1. Add only verified, reusable findings to the existing canonical note(s), updating issue status and reproducible operating steps as appropriate. Do not edit notes merely to create activity. If there is no durable project information to add, report `OBSIDIAN_WRITE=NOT_NEEDED` with the reason.
2. After writing, reopen/read the changed note(s) and verify the inserted text, canonical path, relevant links/backlinks, no duplicate event/section, and UTF-8 content. If any check fails, report `OBSIDIAN_WRITE=FAIL` or `READBACK_VERIFICATION=FAIL`; do not claim synchronization.
3. Report `OBSIDIAN_SYNC=PASS` only after a successful write and readback verification. A no-op does not qualify as a sync pass.

## Required task-closeout fields

Every M2A/GADE task report must include:

- `OBSIDIAN_READ`: `PASS` or `FAIL`.
- `READ_REFERENCES`: actual note paths and relevant headings read.
- `HISTORICAL_FIX_REUSED`: the verified prior fix reused, or `NONE` with a reason.
- `OBSIDIAN_WRITE`: `PASS`, `NOT_NEEDED`, or `FAIL`.
- `CHANGED_NOTES`: actual canonical note paths changed, or `NONE`.
- `READBACK_VERIFICATION`: `PASS` or `FAIL`; for `NOT_NEEDED`, state that no note was written and why.
- `REMAINING_ISSUES`: unresolved or unverified items; use `NONE` only when supported by evidence.

Do not claim Obsidian-first compliance without read evidence. Do not claim `OBSIDIAN_SYNC=PASS` without write and readback evidence. When older task-level logs are absent, classify the historical operation as `NOT_VERIFIED`; do not infer either completion or omission.
