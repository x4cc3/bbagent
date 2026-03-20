# AGENTS.md — BBAgent Control Surface

Use this repository as an operations pack, not as a monolithic skill dump.

## Read Order

1. [workflow.md](/home/xacce/dev/bbagent/manual/workflow.md)
2. [hunting.md](/home/xacce/dev/bbagent/guardrails/hunting.md)
3. [field-manual](/home/xacce/dev/bbagent/tracks/field-manual/SKILL.md) or the narrower track you need
4. A role brief from [roles](/home/xacce/dev/bbagent/roles)
5. A playbook from [playbooks](/home/xacce/dev/bbagent/playbooks) when execution starts

## Canonical Vocabulary

- `tracks/` are knowledge lanes
- `playbooks/` are procedures
- `roles/` are specialist briefs
- `guardrails/` are mandatory rules
- `manual/` is the cross-client operating guide

## Recommended Loop

1. Run `boundary` before touching an asset.
2. Use `survey` to build a target map.
3. Use `probe` for one bug class or one feature at a time.
4. Use `screen` or `gate` before writing anything.
5. Use `pivot` only when the finding needs stronger impact.
6. Use `brief` after the evidence is real and reproducible.

## Track Selection

- [field-manual](/home/xacce/dev/bbagent/tracks/field-manual/SKILL.md) for end-to-end hunts
- [surface-mapping](/home/xacce/dev/bbagent/tracks/surface-mapping/SKILL.md) for recon
- [exploit-atlas](/home/xacce/dev/bbagent/tracks/exploit-atlas/SKILL.md) for class-specific testing
- [payload-bank](/home/xacce/dev/bbagent/tracks/payload-bank/SKILL.md) for payloads and bypasses
- [verdict-gate](/home/xacce/dev/bbagent/tracks/verdict-gate/SKILL.md) for validation
- [disclosure-lab](/home/xacce/dev/bbagent/tracks/disclosure-lab/SKILL.md) for report writing
- [contract-review](/home/xacce/dev/bbagent/tracks/contract-review/SKILL.md) for smart contracts

## Role Entry Points

- [control-room](/home/xacce/dev/bbagent/roles/control-room.md) is the default orchestrator
- [surface-cartographer](/home/xacce/dev/bbagent/roles/surface-cartographer.md) handles recon
- [verdict-engine](/home/xacce/dev/bbagent/roles/verdict-engine.md) handles finding decisions
- [evidence-editor](/home/xacce/dev/bbagent/roles/evidence-editor.md) handles write-ups
- [pivot-engine](/home/xacce/dev/bbagent/roles/pivot-engine.md) handles chaining
- [contract-cartographer](/home/xacce/dev/bbagent/roles/contract-cartographer.md) handles web3 review

## Output Standard

- Lead with the best current surface, finding, or blocker.
- Prefer exact requests, responses, and exploit steps over general commentary.
- If proof is incomplete, name the missing check and stop there.
