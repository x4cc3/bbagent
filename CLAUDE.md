# BBAgent — Claude Guide

This file is the Claude-specific doorway into the BBAgent layout.

## Install

```bash
chmod +x bootstrap.sh
./bootstrap.sh --client claude
```

## Read First

- [workflow.md](/home/xacce/dev/bbagent/manual/workflow.md)
- [hunting.md](/home/xacce/dev/bbagent/guardrails/hunting.md)
- [control-room](/home/xacce/dev/bbagent/roles/control-room.md)

## Available Tracks

| Track | Purpose |
|---|---|
| `field-manual` | Full hunt loop |
| `surface-mapping` | Recon and surface ranking |
| `exploit-atlas` | Web bug-class reference |
| `payload-bank` | Payloads and bypasses |
| `verdict-gate` | Triage and validation |
| `disclosure-lab` | Report writing |
| `contract-review` | Smart contract review |

## Playbooks

- `/survey`
- `/probe`
- `/screen`
- `/gate`
- `/pivot`
- `/brief`
- `/boundary`
- `/contract-sweep`

## Roles

- `control-room`
- `surface-cartographer`
- `verdict-engine`
- `evidence-editor`
- `pivot-engine`
- `contract-cartographer`

## Direct Tools

- `bbagent_hunt.py`
- `bbagent_recon.sh`
- `bbagent_learn.py`
- `bbagent_map.py`
- `bbagent_validate.py`
- `bbagent_report.py`

Use `control-room` as the default entrypoint. Switch to the narrower role only when the task is clearly bounded.
