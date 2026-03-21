#!/bin/bash

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "== Python compile =="
python3 -m py_compile \
  "$ROOT/bbagent_paths.py" \
  "$ROOT/bbagent_hunt.py" \
  "$ROOT/bbagent_scope.py" \
  "$ROOT/bbagent_lifecycle.py" \
  "$ROOT/bbagent_autonomous.py" \
  "$ROOT/cve_hunter.py" \
  "$ROOT/zero_day_fuzzer.py" \
  "$ROOT/target_selector.py" \
  "$ROOT/bbagent_map.py"

echo "== Shell syntax =="
bash -n "$ROOT/bbagent_recon.sh"
bash -n "$ROOT/bootstrap.sh"
bash -n "$ROOT/install_tools.sh"
bash -n "$ROOT/automation/full_hunt.sh"
bash -n "$ROOT/bbagent_lab.sh"

echo "== Target selector relative output =="
python3 "$ROOT/target_selector.py" --top 1 --output "$ROOT/selected.json"
rm -f "$ROOT/selected.json"

echo "== Scope custom output =="
TMP_CSV="/tmp/bbagent-smoke-scope.csv"
TMP_SCOPE_OUT="/tmp/bbagent-smoke/out.json"
mkdir -p "/tmp/bbagent-smoke"
printf 'Asset,Asset Type,Eligible for Bounty,Instruction\n*.example.com,WILDCARD,Yes,Safe harbor applies\n' > "$TMP_CSV"
python3 "$ROOT/bbagent_scope.py" --csv "$TMP_CSV" --output "$TMP_SCOPE_OUT"

echo "== Map custom output =="
python3 "$ROOT/bbagent_map.py" --target example.com --type website --tech nextjs --output "/tmp/bbagent-smoke/map.md"

echo "== Bootstrap arg handling =="
if "$ROOT/bootstrap.sh" --client >/tmp/bbagent-bootstrap.out 2>&1; then
  echo "bootstrap missing-arg test unexpectedly succeeded" >&2
  exit 1
fi
grep -q "Missing value for --client" /tmp/bbagent-bootstrap.out

echo "== Zero-day recon-dir no-op guard =="
mkdir -p /tmp/bbagent-empty-recon/live
if python3 "$ROOT/zero_day_fuzzer.py" --recon-dir /tmp/bbagent-empty-recon >/tmp/bbagent-zdf.out 2>&1; then
  echo "zero_day_fuzzer no-target test unexpectedly succeeded" >&2
  exit 1
fi
grep -q "No targets resolved" /tmp/bbagent-zdf.out

echo "== Smoke tests passed =="
