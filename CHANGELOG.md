# BBAgent Changelog

## 2026-03-21 — Layout Divergence Pass

- Renamed the visible repo scaffolding to `tracks/`, `playbooks/`, `roles/`, `guardrails/`, `manual/`, `session-hooks/`, `automation/`, and `contract-notes/`
- Renamed the specialist surface to `control-room`, `surface-cartographer`, `verdict-engine`, `evidence-editor`, `pivot-engine`, and `contract-cartographer`
- Renamed the procedure surface to `boundary`, `survey`, `probe`, `screen`, `gate`, `pivot`, `brief`, and `contract-sweep`
- Switched the installer to [bootstrap.sh](/home/xacce/dev/bbagent/bootstrap.sh)
- Rewrote the entry docs and Opencode config around the new vocabulary

## 2026-03-20 — Initial BBAgent Fork

- Forked the upstream methodology into `/home/xacce/dev/bbagent`
- Renamed the core Python and shell entrypoints to the `bbagent_*` tool family
- Added Codex and Opencode-facing entry files
