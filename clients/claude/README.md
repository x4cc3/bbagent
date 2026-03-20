# Claude Setup

Use BBAgent in Claude by installing the tracks and playbooks, then using the Claude-facing guide in this repository.

## Files

- Claude guide: [CLAUDE.md](../../CLAUDE.md)
- Generic workflow: [workflow.md](../../manual/workflow.md)
- Main full-loop track: [field-manual](../../tracks/field-manual/SKILL.md)

## Install

From the repo root:

```bash
./bootstrap.sh --client claude
```

That installs:

- tracks into `~/.claude/skills`
- playbooks into `~/.claude/commands`

## What Gets Installed

Tracks:

- `field-manual`
- `surface-mapping`
- `exploit-atlas`
- `payload-bank`
- `verdict-gate`
- `disclosure-lab`
- `contract-review`

Playbooks:

- `boundary`
- `survey`
- `probe`
- `screen`
- `gate`
- `pivot`
- `brief`
- `contract-sweep`

## How Claude Uses It

Use [CLAUDE.md](../../CLAUDE.md) as the client-facing doorway for this repository. The default working pattern is:

1. read [workflow.md](../../manual/workflow.md)
2. choose the right track
3. run the matching playbook
4. validate with [verdict-gate](../../tracks/verdict-gate/SKILL.md) before writing

## What Users Should Start With

For general bug bounty work:

- start from `field-manual`
- use `control-room` as the default mental model

Use narrower playbooks or tracks only when the task is clearly scoped:

- `/survey` for recon
- `/probe` for focused testing
- `/screen` or `/gate` for validation
- `/brief` for write-up
- [contract-review](../../tracks/contract-review/SKILL.md) for smart contracts

## Verification

Useful checks:

```bash
ls ~/.claude/skills
ls ~/.claude/commands
```

You should see the BBAgent tracks and playbooks after installation.
