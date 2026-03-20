# BBAgent

`BBAgent` is a mission-control repository for bug bounty work across Codex, Opencode, Claude, and other agent clients.

This fork keeps the useful hunting content, but the project surface is now organized around a different operating model:

- `tracks/` for knowledge lanes
- `playbooks/` for runnable procedures
- `roles/` for specialist briefings
- `guardrails/` for always-on constraints
- `manual/` for neutral operating guidance
- `automation/` and the root `bbagent_*` tools for direct execution

## Start Here

- Codex: [clients/codex/README.md](./clients/codex/README.md)
- Claude Code: [clients/claude/README.md](./clients/claude/README.md)
- Opencode: [clients/opencode/README.md](./clients/opencode/README.md)
- Generic workflow: [manual/workflow.md](./manual/workflow.md)

Install client assets with:

```bash
chmod +x bootstrap.sh
./bootstrap.sh --client codex
./bootstrap.sh --client claude
./bootstrap.sh --client opencode
```

For Opencode, `bootstrap.sh` renders an example config with absolute repo paths into `~/.config/opencode/opencode-bbagent.example.json`. Follow [clients/opencode/README.md](./clients/opencode/README.md) and merge the `default_agent`, `skills`, `agent`, and `command` sections from that rendered file into your live Opencode config.

## Mission Loop

The repository now revolves around a six-step loop:

1. `boundary` to confirm scope
2. `survey` to map the surface
3. `probe` to run a focused hunt
4. `screen` or `gate` to kill weak findings fast
5. `pivot` if the finding needs escalation
6. `brief` when the evidence is strong enough to submit

## Opencode Surface

After merging the rendered Opencode config, users get:

- a primary `bbagent` agent for the full workflow
- slash commands for each track, such as `/field-manual`, `/payload-bank`, `/verdict-gate`, and `/contract-review`
- slash commands for each playbook, such as `/survey`, `/probe`, `/screen`, `/gate`, and `/brief`
- a documented way to set one model globally or assign different models per agent

## Repository Map

| Area | Purpose |
|:---|:---|
| `tracks/field-manual` | Full end-to-end hunting doctrine |
| `tracks/surface-mapping` | Recon pipeline and target mapping |
| `tracks/exploit-atlas` | Bug-class reference for web targets |
| `tracks/payload-bank` | Payloads, bypasses, and submission kill-lists |
| `tracks/verdict-gate` | Validation, triage, and report go/no-go |
| `tracks/disclosure-lab` | Submission writing and severity framing |
| `tracks/contract-review` | Smart contract and DeFi review lane |
| `playbooks/` | Command-shaped operating procedures |
| `roles/` | Specialist personas for delegation or direct use |
| `guardrails/` | Hunting and reporting constraints |
| `contract-notes/` | Long-form smart contract references |
| `session-hooks/` | Optional session lifecycle helpers |
| `automation/` | Auxiliary shell and helper scripts |

## Roles

| Role | Purpose |
|:---|:---|
| `control-room` | Main coordinator from scope to report |
| `surface-cartographer` | Recon and attack-surface ranking |
| `verdict-engine` | Hard gate for findings before write-up |
| `evidence-editor` | Submission-ready report writing |
| `pivot-engine` | Escalation and exploit chaining |
| `contract-cartographer` | Smart contract audit lane |

## Direct Tooling

The renamed Python and shell entrypoints are still available directly from the repo root:

- `bbagent_hunt.py`
- `bbagent_recon.sh`
- `bbagent_learn.py`
- `bbagent_map.py`
- `bbagent_validate.py`
- `bbagent_report.py`
- `bbagent_idor_scan.py`
- `bbagent_graphql_idor.py`
- `bbagent_oauth_audit.py`
- `bbagent_race_lab.py`
- `bbagent_ai_probe.py`
- `bbagent_ai_payloads.py`
- `bbagent_ai_browser.js`

Example:

```bash
./bbagent_recon.sh target.com
python3 bbagent_learn.py --tech "nextjs,graphql,jwt"
python3 bbagent_hunt.py --target target.com --scan-only
python3 bbagent_validate.py
python3 bbagent_report.py findings/
```

## Tree Snapshot

```text
bbagent/
├── AGENTS.md
├── CLAUDE.md
├── SKILL.md
├── bootstrap.sh
├── tracks/
├── playbooks/
├── roles/
├── guardrails/
├── manual/
├── contract-notes/
├── session-hooks/
├── automation/
├── clients/
├── wordlists/
└── bbagent_*.py / bbagent_*.sh
```

## Attribution

The methodology and source material originate from [shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty), but this repository now uses a different layout, naming scheme, and client workflow surface.
