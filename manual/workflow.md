# BBAgent Workflow

This repository uses a control-room model:

1. `boundary`
2. `survey`
3. `probe`
4. `screen`
5. `gate`
6. `pivot`
7. `brief`

## Routing

- [playbooks/boundary.md](/home/xacce/dev/bbagent/playbooks/boundary.md) for scope checks
- [playbooks/survey.md](/home/xacce/dev/bbagent/playbooks/survey.md) for recon
- [playbooks/probe.md](/home/xacce/dev/bbagent/playbooks/probe.md) for active testing
- [playbooks/screen.md](/home/xacce/dev/bbagent/playbooks/screen.md) for fast triage
- [playbooks/gate.md](/home/xacce/dev/bbagent/playbooks/gate.md) for full validation
- [playbooks/pivot.md](/home/xacce/dev/bbagent/playbooks/pivot.md) for chaining
- [playbooks/brief.md](/home/xacce/dev/bbagent/playbooks/brief.md) for final write-up
- [playbooks/contract-sweep.md](/home/xacce/dev/bbagent/playbooks/contract-sweep.md) for smart contracts

## Role Routing

- [roles/control-room.md](/home/xacce/dev/bbagent/roles/control-room.md) as the default driver
- [roles/surface-cartographer.md](/home/xacce/dev/bbagent/roles/surface-cartographer.md) for mapping
- [roles/verdict-engine.md](/home/xacce/dev/bbagent/roles/verdict-engine.md) for decisions
- [roles/evidence-editor.md](/home/xacce/dev/bbagent/roles/evidence-editor.md) for write-ups
- [roles/pivot-engine.md](/home/xacce/dev/bbagent/roles/pivot-engine.md) for escalation
- [roles/contract-cartographer.md](/home/xacce/dev/bbagent/roles/contract-cartographer.md) for DeFi work

## Track Routing

- [tracks/field-manual/SKILL.md](/home/xacce/dev/bbagent/tracks/field-manual/SKILL.md)
- [tracks/surface-mapping/SKILL.md](/home/xacce/dev/bbagent/tracks/surface-mapping/SKILL.md)
- [tracks/exploit-atlas/SKILL.md](/home/xacce/dev/bbagent/tracks/exploit-atlas/SKILL.md)
- [tracks/payload-bank/SKILL.md](/home/xacce/dev/bbagent/tracks/payload-bank/SKILL.md)
- [tracks/verdict-gate/SKILL.md](/home/xacce/dev/bbagent/tracks/verdict-gate/SKILL.md)
- [tracks/disclosure-lab/SKILL.md](/home/xacce/dev/bbagent/tracks/disclosure-lab/SKILL.md)
- [tracks/contract-review/SKILL.md](/home/xacce/dev/bbagent/tracks/contract-review/SKILL.md)

## Stop Conditions

- Out of scope
- No real exploit path
- Only theoretical impact remains
- The surface stays cold after a short disciplined pass
