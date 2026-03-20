---
description: Validate a finding — runs the 7-Question Gate, required evidence-pack check, confidence scoring, and 4-gate checklist. Kills weak findings before report writing. Prevents N/A submissions that hurt validity ratio. Usage: /gate
---

# /gate

Run full validation on the current finding before writing a report.

## What This Does

1. Runs 7-Question Gate (one wrong answer = kill it)
2. Checks the required evidence pack
3. Checks against the always-rejected list
4. Runs 4 pre-submission gates
5. Outputs a decision plus confidence and the missing proof, if any

## Usage

```
/gate
```

Describe the finding when prompted. Include:
- The endpoint
- The bug class
- The exact request and exact response
- What the PoC shows
- The target program
- Scope proof
- Victim or target-object proof
- Negative control, if you have one

Before a final PASS, load:

- `tracks/verdict-gate/references/proof-matrix.md`

## The 7-Question Gate

Answer each. ONE wrong answer = STOP.

### Q1: Can I demonstrate this step-by-step RIGHT NOW?

Write this out:
```
1. Setup:   I need [own account / another user's ID / no account]
2. Request: [exact HTTP method, URL, headers, body]
3. Result:  Response shows [exact data / action completed]
4. Impact:  Real consequence is [account takeover / PII exposed / money stolen]
5. Cost:    Time: [X min], Capital: [$0 / $X]
```

If step 2 is "I need to look at the code more" → KILL IT.

### Q2: Is the impact accepted by this program?

Check program scope page. Is your bug class listed? Is it excluded?

### Q3: Is the vulnerable asset in scope?

Exact domain in scope? Not staging/dev? Not a third-party service?

### Q4: Does it need admin or privileged access that an attacker can't get?

"Admin can do X" with no reachable privilege boundary → KILL IT.
"Regular user can do X that only admin should" → valid.

### Q5: Is this known or documented behavior?

Search disclosed reports + changelog + API docs.

### Q6: Can you prove impact beyond "technically possible"?

- XSS → actual cookie value in exfil request, not just alert()
- SSRF → response body from internal service, not just DNS callback
- IDOR → actual other-user's private data in response, not just 200 status

### Q7: Is this on the never-submit list?

```
Missing headers, GraphQL introspection alone, clickjacking without PoC,
self-XSS, open redirect alone, SSRF DNS-only, logout CSRF, banner disclosure,
rate limit on non-critical forms, missing cookie flags alone...
```

If yes → KILL IT unless you have a chain.

## Required Evidence Pack

PASS is forbidden unless you have all of these:

```
[ ] Scope proof for the asset or feature
[ ] Exact request and exact response
[ ] Attacker identity or account used
[ ] Victim or target-object proof
[ ] Negative control or expected-safe comparison
[ ] Impact artifact
```

If any are missing, do not PASS yet.

## Check: Conditionally Valid?

If it's on the never-submit list, can you chain it?

| You Have | Chain Available? |
|---|---|
| Open redirect | + OAuth code theft → ATO? |
| SSRF DNS-only | + internal service data? |
| Clickjacking | + sensitive action + PoC? |
| CORS wildcard | + credentialed data exfil? |
| Prompt injection | + IDOR → other user's data? |

If no chain → KILL IT. If chain confirmed → report both together.

## 4 Gates — All Must Pass

**Gate 0 (30 sec):**
```
[ ] Confirmed with real HTTP requests (not just code reading)
[ ] In scope (checked program page)
[ ] Reproducible from scratch
[ ] Evidence captured
[ ] Confidence is not LOW
```

**Gate 1 — Impact (2 min):**
```
[ ] Can answer "What does attacker walk away with?"
[ ] More than "sees non-sensitive data"
[ ] Real victim exists
[ ] No unlikely preconditions
```

**Gate 2 — Dedup (5 min):**
```
[ ] Searched HackerOne Hacktivity for endpoint + bug class
[ ] Searched GitHub issues
[ ] Read 5 most recent disclosed reports
[ ] Not in changelog as known issue
[ ] Wrote one line on why this is not the same as the closest public report
```

**Gate 3 — Report quality (10 min):**
```
[ ] Title formula: [Class] in [Endpoint] allows [actor] to [impact]
[ ] Steps have exact HTTP request
[ ] Evidence shows actual impact
[ ] CVSS calculated
[ ] Fix: 1-2 concrete sentences
[ ] Confidence score included
```

## Output

Use this structure:

```
DECISION: [PASS / KILL Q# / DOWNGRADE / CHAIN REQUIRED]
CONFIDENCE: [HIGH / MEDIUM / LOW]
FAILED_AT: [Q# / Gate # / N/A]
MISSING_PROOF: [none or exact artifact still missing]
ACTION: [next step]
```

Rules:

- Never PASS at LOW confidence
- If scope proof, request/response, or victim/object proof is missing, do not PASS
- If the bug class row in `references/proof-matrix.md` is incomplete, do not PASS

**PASS:** "All 7 questions pass. All 4 gates pass. Confidence is HIGH. Proceed to /brief."

**KILL:** "Q[N] fails because [reason]. Confidence is LOW. Missing proof: [artifact]. Move on."

**DOWNGRADE:** "Q6 only shows technical possibility. Confidence is MEDIUM. Requires [artifact] before severity can be raised."
