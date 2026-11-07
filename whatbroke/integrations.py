"""Integration health checker: a deterministic checklist per connected service.

Checks: provider API status, token expiry, live token test, scopes, webhook reachability.
Tokens are read from environment variables (token_env) and never stored or logged.
"""
import base64
import json
import os
import re
import time
from datetime import datetime, timezone

import requests
import yaml

from .browser import check_target
from .diagnose import SEV_RANK, finding

UA = {"User-Agent": "cx-check-what-broke/0.1"}
EXAMPLE = """integrations:
  - name: GitHub
    api_status_url: https://www.githubstatus.com/api/v2/status.json   # Statuspage-style JSON
    test_url: https://api.github.com/user          # any cheap authenticated endpoint
    token_env: GITHUB_TOKEN                        # NAME of an env var; the token itself is never stored
    scopes_header: X-OAuth-Scopes                  # read granted scopes from this response header
    required_scopes: [repo, read:org]
  - name: Orders webhook
    webhook_url: https://example.com/hooks/orders
"""


def load_config(text):
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML: {e}")
    items = data.get("integrations") if isinstance(data, dict) else None
    if not items or not all(isinstance(i, dict) and i.get("name") for i in items):
        raise ValueError("Config must contain 'integrations:' - a list where each item has a 'name'.")
    return items


def _ts(v):
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, datetime):
        return (v if v.tzinfo else v.replace(tzinfo=timezone.utc)).timestamp()
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _jwt_claims(tok):
    try:
        p = tok.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        return {}


def _split(v):
    if isinstance(v, list):
        return [str(x) for x in v]
    return [x for x in re.split(r"[,\s]+", v.strip()) if x] if isinstance(v, str) else []


def _dur(s):
    return f"{int(s // 86400)}d" if s >= 86400 else f"{int(s // 3600)}h"


def _api_status(cfg):
    url = cfg.get("api_status_url")
    if not url:
        return None
    if check_target(url):
        return []
    try:
        r = requests.get(url, timeout=10, headers=UA)
        ind = r.json()["status"]["indicator"]
    except Exception:
        return [finding("status_unavailable", "Provider status page not readable", "low", 0.5, [url],
                        "Check the provider's status page manually.")]
    if ind in ("major", "critical"):
        return [finding("provider_outage", "Provider reports a major outage", "critical", 0.9, [f"indicator={ind}"],
                        "Not a customer configuration issue. Tell the customer, monitor the status page, retry later.")]
    if ind == "minor":
        return [finding("provider_degraded", "Provider reports degraded service", "medium", 0.8, ["indicator=minor"],
                        "Failures may be transient. Retry, and watch the status page.")]
    return []


def _expiry(cfg, claims, now=None):
    exp = _ts(cfg.get("expires_at")) or _ts(claims.get("exp"))
    if exp is None:
        return None
    left = exp - (now or time.time())
    if left <= 0:
        return [finding("token_expired", "Access token has expired", "critical", 0.95, [f"Expired {_dur(-left)} ago"],
                        "Refresh with the refresh token, or have the customer re-authorize the integration.")]
    if left < 86400:
        return [finding("token_expiring", "Access token expires within 24h", "medium", 0.9, [f"Expires in {_dur(left)}"],
                        "Confirm automatic refresh works; if not, re-authorize.")]
    return []


LIVE_RULES = {
    401: ("token_rejected", "API rejected the token (401)", "critical", 0.9,
          "Token is expired, revoked, from the wrong environment (test vs live) or mistyped. Re-authorize or generate a new one."),
    403: ("permission_denied", "API denied permission (403)", "high", 0.8,
          "Usually missing scopes, app not approved/installed for this resource, or an IP allowlist. Check app permissions."),
    429: ("api_rate_limited", "API rate limit hit (429)", "medium", 0.9, "Back off and retry after the Retry-After period."),
}


def _live(cfg, token):
    url = cfg.get("test_url")
    if not url:
        return None, None
    if cfg.get("token_env") and not token:
        return [finding("token_missing", f"Environment variable {cfg['token_env']} is not set", "high", 1.0, [],
                        "Export the token and re-run the check.")], None
    if check_target(url):
        return [finding("url_blocked", "test_url is not a public address", "low", 1.0, [check_target(url)],
                        "Use a public API URL.")], None
    try:
        r = requests.get(url, headers={"Authorization": f"Bearer {token}", **UA} if token else UA,
                         timeout=15, allow_redirects=False)
    except requests.RequestException as e:
        return [finding("api_unreachable", "API endpoint unreachable", "high", 0.7, [type(e).__name__],
                        "Check provider status and network access, then retry.")], None
    st, fs = r.status_code, []
    if st in LIVE_RULES:
        i, title, sev, conf, step = LIVE_RULES[st]
        fs.append(finding(i, title, sev, conf, [f"HTTP {st}"] + ([f"Retry-After: {r.headers['Retry-After']}"]
                                                                 if "Retry-After" in r.headers else []), step))
    elif st >= 500:
        fs.append(finding("provider_error", f"API error {st}", "high", 0.8, [f"HTTP {st}"], "Provider-side error. Retry and check status."))
    hdr = cfg.get("scopes_header")
    return fs, (_split(r.headers.get(hdr)) if hdr else None)


def _scopes(cfg, claims, header_scopes):
    req = cfg.get("required_scopes")
    if not req:
        return None
    granted = _split(cfg.get("granted_scopes")) or header_scopes or _split(claims.get("scope") or claims.get("scp"))
    if not granted:
        return [finding("scopes_unverified", "Could not verify granted scopes", "low", 0.5, [],
                        "Provide granted_scopes, a scopes_header, or a JWT token with a scope claim.")]
    missing = sorted(set(req) - set(granted))
    if not missing:
        return []
    return [finding("missing_scopes", f"Missing scopes: {', '.join(missing)}", "high", 0.95,
                    [f"Required: {', '.join(req)}", f"Granted: {', '.join(sorted(granted))}"],
                    "Add the scopes in the app settings, then have the user re-authorize. Existing tokens do not gain scopes automatically.")]


def _webhook(cfg):
    url = cfg.get("webhook_url")
    if not url:
        return None
    blocked = check_target(url)
    if blocked:
        return [finding("webhook_not_public", "Webhook URL is not publicly reachable", "high", 0.9, [blocked],
                        "Providers cannot reach private/localhost URLs. Use a public HTTPS URL (or a tunnel for testing).")]
    fs, t = [], time.monotonic()
    if url.startswith("http://"):
        fs.append(finding("webhook_not_https", "Webhook uses plain HTTP", "medium", 0.8, [url],
                          "Most providers require HTTPS. Switch the endpoint to HTTPS."))
    ex = requests.exceptions
    try:  # HEAD is non-mutating; 405/400/401/403 still prove the endpoint is reachable
        r = requests.head(url, timeout=10, allow_redirects=False, headers=UA)
    except ex.SSLError as e:
        return fs + [finding("webhook_tls", "Webhook TLS certificate problem", "critical", 0.9, [str(e)[:200]],
                             "Fix the certificate; providers refuse invalid certs.")]
    except ex.Timeout:
        return fs + [finding("webhook_timeout", "Webhook endpoint timed out", "high", 0.8, ["No response in 10s"],
                             "Check the server and firewall. Respond 2xx quickly and process asynchronously.")]
    except ex.ConnectionError as e:
        return fs + [finding("webhook_unreachable", "Webhook endpoint unreachable", "critical", 0.85, [type(e).__name__],
                             "Check DNS, that the server is up, and that the firewall allows the provider's IPs.")]
    ms, st = int((time.monotonic() - t) * 1000), r.status_code
    if 300 <= st < 400:
        fs.append(finding("webhook_redirect", "Webhook URL redirects", "high", 0.85, [f"HTTP {st} -> {r.headers.get('Location', '?')}"],
                          "Many providers do not follow redirects. Register the final URL directly."))
    elif st == 404:
        fs.append(finding("webhook_wrong_path", "Webhook path returns 404", "high", 0.85, ["HTTP 404"],
                          "Check the path/route registered with the provider."))
    elif st >= 500:
        fs.append(finding("webhook_server_error", f"Webhook endpoint error {st}", "high", 0.8, [f"HTTP {st}"],
                          "Check the receiving app's logs."))
    if ms > 3000:
        fs.append(finding("webhook_slow", "Webhook responds slowly", "medium", 0.7, [f"{ms} ms"],
                          "Many providers time out at 3-10s. Acknowledge fast, process in the background."))
    return fs


def check_integration(cfg):
    token = os.environ.get(cfg["token_env"]) if cfg.get("token_env") else None
    claims = _jwt_claims(token) if token else {}
    live, header_scopes = _live(cfg, token)
    steps = {"api_status": _api_status(cfg), "token_expiry": _expiry(cfg, claims), "token_live": live,
             "scopes": _scopes(cfg, claims, header_scopes), "webhook": _webhook(cfg)}
    findings, states = [], {}
    for k, fs in steps.items():
        if fs is None:
            states[k] = "skipped"
            continue
        for f in fs:
            f["check"] = k
        findings += fs
        states[k] = "issues" if any(SEV_RANK[f["severity"]] >= 2 for f in fs) else "warn" if fs else "pass"
    findings.sort(key=lambda f: (SEV_RANK[f["severity"]], f["confidence"]), reverse=True)
    top = findings[0] if findings else None
    return {"name": cfg["name"], "checks": states, "findings": findings,
            "severity": top["severity"] if top else "none",
            "reproduced": bool(top and SEV_RANK[top["severity"]] >= 2),
            "likely_cause": top["title"] if top else "No problem found by the checklist"}


def run_integrations(text):
    results = [check_integration(c) for c in load_config(text)]
    worst = max(results, key=lambda r: SEV_RANK.get(r["severity"], 0))
    return {"integrations": results, "severity": worst["severity"], "reproduced": any(r["reproduced"] for r in results)}
