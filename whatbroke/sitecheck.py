"""End-to-end website check made of selectable checks. Rules decide; no model needed."""
import socket
import ssl
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests

from .browser import check_target, collect, redact_url
from .diagnose import SEV_RANK, diagnose, finding

UA = {"User-Agent": "cx-check-what-broke/0.1"}
DESCRIPTIONS = {
    "dns": "Domain resolves; www/apex variants both work",
    "tls": "Certificate valid and not expiring soon",
    "http": "Status code, redirects, HTTPS redirect, response time",
    "headers": "Common security headers (HSTS, CSP, nosniff)",
    "browser": "Real browser: JS errors, failed assets, blank page, API calls, CORS, mixed content",
    "mobile": "Same browser checks on a mobile device profile",
}
ALL_CHECKS = list(DESCRIPTIONS)
PRESETS = {"full": ALL_CHECKS, "up": ["dns", "http"], "ssl": ["dns", "tls"],
           "broken-page": ["http", "browser"], "mobile": ["mobile"]}
STATUS_RULES = {
    404: ("not_found", "Page returns 404", "high", "Check routing, the deployed build and domain-to-project mapping."),
    401: ("access_denied", "Access denied (401)", "medium", "Check the site's privacy/auth settings or WAF rules."),
    403: ("access_denied", "Access denied (403)", "medium", "Check the site's privacy/auth settings or WAF rules."),
    429: ("rate_limited", "Rate limited (429)", "medium", "Check rate limits or bot protection."),
}
NOISE_WHEN_DNS_DOWN = {"tls_error", "connection_failed", "navigation_failed", "page_timeout"}


def resolve_checks(spec):
    if not spec:
        return list(ALL_CHECKS)
    names = spec.split(",") if isinstance(spec, str) else list(spec)
    out = []
    for n in (x.strip() for x in names if x.strip()):
        out += PRESETS.get(n, [n])
    bad = [n for n in out if n not in DESCRIPTIONS]
    if bad:
        raise ValueError(f"Unknown check(s): {', '.join(bad)}. Valid: {', '.join(ALL_CHECKS)} or presets {', '.join(PRESETS)}")
    return list(dict.fromkeys(out))


def _resolve(host):
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
    except socket.gaierror:
        return []


def check_dns(url, ctx):
    host = urlparse(url).hostname
    ips = _resolve(host)
    if not ips:
        return [finding("dns_failure", "Domain does not resolve", "critical", 0.95, [host],
                        "Check DNS records, nameservers and domain expiry.")], {"ips": []}
    alt = host[4:] if host.startswith("www.") else "www." + host
    out = []
    if not _resolve(alt):
        out.append(finding("www_apex_mismatch", f"{alt} does not resolve", "low", 0.6,
                           [f"{host} resolves but {alt} does not"],
                           "Add a DNS record or redirect so both variants work."))
    return out, {"ips": ips}


def _fetch(url, ctx):
    if "fetch" not in ctx:
        t = time.monotonic()
        try:
            r = requests.get(url, timeout=15, headers=UA)
            ctx["fetch"] = (r, None, int((time.monotonic() - t) * 1000))
        except requests.RequestException as e:
            ctx["fetch"] = (None, e, int((time.monotonic() - t) * 1000))
    return ctx["fetch"]


def check_http(url, ctx):
    r, err, ms = _fetch(url, ctx)
    ex = requests.exceptions
    if err is not None:
        if isinstance(err, ex.SSLError):
            f = finding("tls_certificate", "TLS certificate problem", "critical", 0.9, [str(err)[:200]],
                        "Renew/reissue the certificate or fix hostname/chain.")
        elif isinstance(err, ex.TooManyRedirects):
            f = finding("redirect_loop", "Redirect loop", "high", 0.9, [str(err)[:200]],
                        "Check redirect rules (www/non-www, http/https, auth).")
        elif isinstance(err, ex.Timeout):
            f = finding("page_timeout", "Request timed out", "high", 0.7, [f"No response after {ms} ms"],
                        "Check server response time and hosting status.")
        elif isinstance(err, ex.ConnectionError):
            f = finding("connection_failed", "Could not connect to the server", "critical", 0.8,
                        [type(err).__name__], "Origin may be down or firewalled. Check hosting status.")
        else:
            f = finding("navigation_failed", "Request failed", "high", 0.5, [str(err)[:200]], "Retry and review the error.")
        return [f], {"error": str(err)[:200], "ms": ms}
    st, out = r.status_code, []
    if st >= 500:
        out.append(finding("server_error", f"Server error {st}", "critical", 0.95, [f"HTTP {st}"],
                           "Check server/function logs and the latest deploy."))
    elif st in STATUS_RULES:
        i, title, sev, step = STATUS_RULES[st]
        out.append(finding(i, title, sev, 0.9, [f"HTTP {st}"], step))
    if url.startswith("http://") and r.url.startswith("http://"):
        out.append(finding("no_https_redirect", "HTTP does not redirect to HTTPS", "medium", 0.8, [r.url],
                           "Force HTTPS at the host/CDN."))
    if ms > 8000:
        out.append(finding("slow_load", "Very slow response", "low", 0.7, [f"{ms} ms"], "Check server and heavy assets."))
    return out, {"status": st, "ms": ms, "final_url": redact_url(r.url),
                 "redirects": [redact_url(h.url) for h in r.history]}


def check_tls(url, ctx):
    p = urlparse(url)
    if p.scheme != "https":
        return [], {"skipped": "not https"}
    host = p.hostname
    try:
        with socket.create_connection((host, p.port or 443), timeout=10) as s, \
                ssl.create_default_context().wrap_socket(s, server_hostname=host) as t:
            cert = t.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return [finding("tls_certificate", "TLS certificate problem", "critical", 0.95, [e.verify_message],
                        "Renew/reissue the certificate or fix hostname mismatch / missing chain.")], {}
    except (OSError, ssl.SSLError) as e:
        return [finding("tls_error", "Could not complete TLS handshake", "high", 0.6, [str(e)[:200]],
                        "Check SSL config and that port 443 is reachable.")], {}
    days = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400)
    out = []
    if days < 30:
        out.append(finding("cert_expiring", f"Certificate expires in {days} days", "high" if days < 14 else "medium",
                           0.95, [cert["notAfter"]], "Renew now and confirm auto-renewal works."))
    return out, {"expires_in_days": days}


def check_headers(url, ctx):
    r, err, _ = _fetch(url, ctx)
    if err is not None or not r.url.startswith("https"):
        return [], {"skipped": "no https response"}
    want = ["strict-transport-security", "x-content-type-options", "content-security-policy"]
    missing = [h for h in want if h not in r.headers]
    out = [finding("missing_security_headers", "Missing security headers", "low", 0.9, missing,
                   "Add the headers at the host/CDN.")] if missing else []
    return out, {"missing": missing}


def _browser(url, ctx, mobile):
    ev = collect(url, ctx["out_dir"], ctx["timeout_ms"], mobile)
    fs = [f for f in diagnose(ev)["findings"] if f["id"] not in ("no_issue_reproduced", "blocked_target")]
    if mobile:
        for f in fs:
            f["title"] = "[mobile] " + f["title"]
    return fs, ev


CHECKS = {"dns": check_dns, "tls": check_tls, "http": check_http, "headers": check_headers,
          "browser": lambda u, c: _browser(u, c, False), "mobile": lambda u, c: _browser(u, c, True)}


def run_site_check(url, checks=None, out_dir="runs", timeout=30):
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    names = resolve_checks(checks)
    out = Path(out_dir) / datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    out.mkdir(parents=True, exist_ok=True)
    res = {"url": redact_url(url), "checks": names, "status": {}, "evidence": {}, "findings": [],
           "severity": "none", "reproduced": False, "screenshot": None}
    blocked = check_target(url)
    if blocked:
        res.update(findings=[finding("blocked_target", "URL not checked (safety rules)", "low", 1.0, [blocked],
                                     "Ask the customer for a public URL.")], severity="low")
        return res
    ctx, found = {"out_dir": out, "timeout_ms": timeout * 1000}, []
    for n in names:
        try:
            fs, ev = CHECKS[n](url, ctx)
        except Exception as e:  # e.g. browser not installed
            res["status"][n] = "error"
            res["evidence"][n] = {"error": str(e)[:300] + (" (run: playwright install chromium)" if "xecutable" in str(e) else "")}
            continue
        for f in fs:
            f["check"] = n
        res["evidence"][n] = ev
        res["status"][n] = ("skipped" if "skipped" in ev else
                            "issues" if any(SEV_RANK[f["severity"]] >= 2 for f in fs) else "warn" if fs else "pass")
        found += fs
    if any(f["id"] == "dns_failure" for f in found):
        found = [f for f in found if f["id"] not in NOISE_WHEN_DNS_DOWN]
    seen, uniq = set(), []
    for f in sorted(found, key=lambda f: (SEV_RANK[f["severity"]], f["confidence"]), reverse=True):
        if f["id"] not in seen:
            seen.add(f["id"])
            uniq.append(f)
    res["findings"] = uniq
    if uniq:
        res["severity"] = uniq[0]["severity"]
        res["reproduced"] = SEV_RANK[res["severity"]] >= 2
    shot = out / "screenshot-desktop.png"
    res["screenshot"] = f"{out.name}/{shot.name}" if shot.exists() else None
    return res
