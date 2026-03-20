# Opencode Setup

Use BBAgent in Opencode with one primary agent and explicit slash commands.

## Files

- Config template: [opencode.example.json](./opencode.example.json)
- Rendered local example after bootstrap: `~/.config/opencode/opencode-bbagent.example.json`
- Your live config: `~/.config/opencode/opencode.json`

## Install

From the repo root:

```bash
./bootstrap.sh --client opencode
```

That writes a rendered example file with absolute paths to:

```bash
~/.config/opencode/opencode-bbagent.example.json
```

Merge these sections from the rendered example into your live Opencode config:

- `default_agent`
- `skills`
- `agent`
- `command`

## Default Entry Point

Set BBAgent as the default Opencode agent:

```json
{
  "default_agent": "bbagent"
}
```

The `bbagent` agent is the main bug bounty operator. Start there unless you already know you only want a narrower lane like recon or report writing.

## Model Selection

Opencode supports both global and per-agent model selection.

### One model for everything

Set the top-level `model` field:

```json
{
  "model": "openai/gpt-5.4"
}
```

That becomes the default model for normal sessions unless you override it on the command line.

### Different model for a specific agent

Set `model` on that agent:

```json
{
  "agent": {
    "bbagent": {
      "model": "openai/gpt-5.4"
    },
    "verdict_engine": {
      "model": "anthropic/claude-sonnet-4"
    }
  }
}
```

This is useful when you want:

- a stronger general model for `bbagent`
- a cheaper or faster model for narrow roles
- a different provider for a specific lane

### Optional variant

Opencode also supports an agent-level `variant` field:

```json
{
  "agent": {
    "bbagent": {
      "model": "openai/gpt-5.4",
      "variant": "fast"
    }
  }
}
```

Use `variant` only if your provider/model supports variants.

## Command Line Overrides

You can override both the agent and model per run:

```bash
opencode --agent bbagent --model openai/gpt-5.4
```

Examples:

```bash
opencode --agent bbagent
opencode --agent verdict_engine --model openai/gpt-5.4
opencode --agent surface_cartographer --model anthropic/claude-sonnet-4
```

## Recommended Starter Config

This is the simplest pattern:

```json
{
  "default_agent": "bbagent",
  "model": "openai/gpt-5.4"
}
```

Then add agent-specific `model` overrides only if you have a reason.

## What Users Should Use

For normal bug bounty work:

- use the `bbagent` agent
- or run the `/bbagent` command

Use narrower commands only when you already know the task:

- `/survey` or `/surface-mapping`
- `/probe`
- `/screen` or `/verdict-gate`
- `/brief` or `/disclosure-lab`
- `/contract-review`

## Verification

Useful checks:

```bash
opencode debug config
opencode debug skill
opencode debug agent bbagent
```

If your skills are installed correctly, `opencode debug skill` should list the BBAgent tracks from this repo.
