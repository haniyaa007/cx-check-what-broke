# CX Check What Broke

**Open-source toolkit for Customer Experience engineers.** Find out *why* a customer's website or integration is broken, with evidence and a next step you can send straight to the customer.

Rules decide, models assist: every check is deterministic and free to run. No AI model is required, and nothing is sent to a third party.

[![CI](../../actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)

## What it does

### 1. Website check: "my site is broken"
Runs end to end, or only the parts you pick.

| Check | Looks at |
|---|---|
| `dns` | Domain resolves; `www` and apex both work |
| `tls` | Certificate valid and not about to expire |
| `http` | Status code, redirect chain/loops, HTTP-to-HTTPS, response time |
| `headers` | HSTS, CSP, nosniff |
| `browser` | Real Chromium: JS errors, failed scripts/CSS, blank page, failing API calls, CORS, mixed content, screenshot |
| `mobile` | Same browser checks on a mobile device profile |

Presets for the most common questions: `full`, `up` ("is it up?"), `ssl`, `broken-page`, `mobile`.

### 2. Integration health check: "the integration won't connect"
A checklist for each connected service, covering the usual causes:

| Cause | How it's detected |
|---|---|
| Expired / expiring token | `expires_at` or the token's JWT `exp` claim |
| Revoked or wrong token | Live call to a test endpoint: 401 / 403 / 429 explained |
| Missing scopes | Required vs. granted (config, response header, or JWT claim) |
| Webhook unreachable | DNS, TLS, redirect, 404, timeout, non-public URL, slow response |
| Provider outage | Statuspage-style status JSON |

### Remembers what you do
Every run is logged **locally** (SQLite in `~/.whatbroke`). CX Check What Broke tells you what you run most and offers to re-run it: *"You've run 'dns,tls' on shop.example.com 5x. Run it again?"*

## Quick start

```bash
git clone https://github.com/haniyaa007/cx-check-what-broke.git && cd cx-check-what-broke
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
playwright install chromium        # one time, ~150 MB, needed for browser/mobile checks

whatbroke web                       # open http://127.0.0.1:5000
```

### Command line

```bash
whatbroke site https://example.com                      # full check
whatbroke site example.com --checks ssl                 # preset
whatbroke site example.com --checks dns,http,browser    # pick checks
whatbroke integrations --example > integrations.yaml    # starter config
GITHUB_TOKEN=... whatbroke integrations integrations.yaml
whatbroke again                                         # re-run something you run often
whatbroke history
```
Exit code is `1` when a medium-or-higher problem is found, so it works in scripts and playbooks.

### Integration config

```yaml
integrations:
  - name: GitHub
    api_status_url: https://www.githubstatus.com/api/v2/status.json
    test_url: https://api.github.com/user
    token_env: GITHUB_TOKEN          # NAME of an env var - the token is never stored
    scopes_header: X-OAuth-Scopes
    required_scopes: [repo, read:org]
  - name: Orders webhook
    webhook_url: https://example.com/hooks/orders
```
All fields are optional per integration; checks without config are skipped.

## Design

One shared core (`whatbroke/`), thin interfaces on top (CLI, web). Every check returns the same finding shape, so new checks and new interfaces plug in without changes elsewhere:

```json
{"id": "missing_scopes", "title": "...", "severity": "high", "confidence": 0.95,
 "evidence": ["..."], "next_step": "..."}
```

## Security

- **Run it locally.** The web UI has no login and binds to `127.0.0.1`. Do not expose it to the internet.
- URLs to private/internal addresses are refused (SSRF guard). For stronger isolation, run it in a container with private ranges blocked at the network level.
- Secrets are redacted from URLs, console output and errors. Tokens come only from environment variables and are never written to history.
- The webhook check sends a `HEAD` request only, with no side effects.

## Limits

Login-gated pages are not supported yet. Checks run from one location. Browser heuristics (e.g. blank page) are simple and worth tuning on real tickets.

## Roadmap

Authenticated site checks · multi-region runs · more provider presets (Slack, Stripe, Shopify, HubSpot) · bug-packet JSON export for Linear/Jira · playbook YAML to chain checks · Docker image.

## Contributing

New rules are the easiest contribution. Add one in `whatbroke/diagnose.py` (browser evidence), `sitecheck.py` or `integrations.py`, plus a test in `tests/`. Run `pip install -e . pytest && pytest`.

## License

MIT
