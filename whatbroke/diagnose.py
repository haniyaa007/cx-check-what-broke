"""Rule-based diagnosis. No model needed: evidence in, ranked findings out."""
import re

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

NAV_ERRORS = [
    ("ERR_NAME_NOT_RESOLVED", "dns_failure", "Domain does not resolve", "critical",
     "Check DNS records, nameservers and domain expiry."),
    ("ERR_CONNECTION_REFUSED", "connection_refused", "Server refused the connection", "critical",
     "Origin is down or the port/firewall is wrong. Check the deployment status."),
    ("ERR_CONNECTION_TIMED_OUT", "connection_timeout", "Connection timed out", "critical",
     "Origin unreachable. Check hosting status and firewall rules."),
    ("ERR_TOO_MANY_REDIRECTS", "redirect_loop", "Redirect loop", "high",
     "Check redirect rules (www/non-www, http/https, auth redirects)."),
    ("ERR_CERT", "tls_certificate", "TLS certificate problem", "critical",
     "Certificate expired, mismatched or not issued. Check the domain's SSL settings."),
    ("ERR_SSL", "tls_error", "TLS/SSL handshake error", "critical",
     "Check SSL configuration and certificate chain."),
]


def _f(id_, title, severity, confidence, evidence, next_step):
    return {"id": id_, "title": title, "severity": severity,
            "confidence": confidence, "evidence": evidence, "next_step": next_step}


def diagnose(ev):
    out = []

    if ev.get("blocked"):
        out.append(_f("blocked_target", "URL not checked (blocked by safety rules)", "low", 1.0,
                      [ev["blocked"]], "Ask the customer for a public URL."))
        return _summarize(out, checked=False)

    nav = ev.get("nav_error")
    if nav:
        matched = False
        for needle, id_, title, sev, step in NAV_ERRORS:
            if needle in nav:
                out.append(_f(id_, title, sev, 0.95, [nav], step))
                matched = True
                break
        if not matched:
            if "Timeout" in nav:
                out.append(_f("page_timeout", "Page did not finish loading in time", "high", 0.7,
                              [nav], "Check server response time and hung requests."))
            else:
                out.append(_f("navigation_failed", "Navigation failed", "high", 0.6,
                              [nav], "Review the raw error and retry from another region."))

    status = ev.get("main_status")
    if status:
        if status >= 500:
            out.append(_f("server_error", f"Server error {status}", "critical", 0.95,
                          [f"Main document returned {status}"],
                          "Check server/function logs and the latest deploy."))
        elif status == 404:
            out.append(_f("not_found", "Page returns 404", "high", 0.9,
                          ["Main document returned 404"],
                          "Check routing, the deployed build and the domain's project mapping."))
        elif status in (401, 403):
            out.append(_f("access_denied", f"Access denied ({status})", "medium", 0.85,
                          [f"Main document returned {status}"],
                          "Check the site's privacy/auth settings or WAF rules."))
        elif status == 429:
            out.append(_f("rate_limited", "Rate limited (429)", "medium", 0.8,
                          ["Main document returned 429"], "Check rate limits or bot protection."))

    page_errors = ev.get("page_errors", [])
    if page_errors:
        out.append(_f("js_runtime_error", "Uncaught JavaScript error(s)", "high", 0.85,
                      page_errors[:5], "Reproduce locally; map stack trace via source maps."))

    if status and status < 400 and not nav and ev.get("text_len", 0) < 20:
        conf = 0.9 if page_errors else 0.6
        out.append(_f("blank_page", "Page loaded but is blank", "high", conf,
                      [f"Visible text length: {ev.get('text_len', 0)}"],
                      "Often a JS crash or missing bundle. See JS errors and failed assets."))

    bad = ev.get("bad_responses", [])
    assets = [b for b in bad if b["resource_type"] in ("script", "stylesheet", "font")]
    if assets:
        has_script = any(b["resource_type"] == "script" for b in assets)
        out.append(_f("broken_assets", "Static assets failing to load",
                      "high" if has_script else "medium", 0.85,
                      [f'{b["status"]} {b["resource_type"]} {b["url"]}' for b in assets[:5]],
                      "Likely a stale or partial deploy (hashed filenames missing). Redeploy and purge CDN cache."))

    api = [b for b in bad if b["resource_type"] in ("fetch", "xhr")]
    if api:
        sev = "high" if any(b["status"] >= 500 for b in api) else "medium"
        out.append(_f("api_failures", "Backend/API calls failing", sev, 0.8,
                      [f'{b["status"]} {b["url"]}' for b in api[:5]],
                      "Check the API/backend logs and integration credentials."))

    texts = [c["text"] for c in ev.get("console", [])]
    if any(re.search(r"mixed content", t, re.I) for t in texts):
        out.append(_f("mixed_content", "Mixed content (http resources on https page)", "medium", 0.9,
                      [t for t in texts if re.search(r"mixed content", t, re.I)][:3],
                      "Switch hardcoded http:// resources to https://."))
    if any(re.search(r"blocked by CORS", t, re.I) for t in texts):
        out.append(_f("cors_error", "CORS policy blocking requests", "medium", 0.9,
                      [t for t in texts if re.search(r"CORS", t)][:3],
                      "Allow the site's origin on the API, or proxy the call."))

    if ev.get("load_ms", 0) > 8000 and not nav:
        out.append(_f("slow_load", "Very slow page load", "low", 0.7,
                      [f"Load took {ev['load_ms']} ms"], "Check heavy assets and server response time."))

    if not out:
        out.append(_f("no_issue_reproduced", "No problem reproduced", "low", 0.5,
                      ["Page loaded with no errors from this location."],
                      "Could be intermittent, regional, login-gated or user-side (cache, extension). "
                      "Ask for browser, console output and a screen recording."))
    return _summarize(out, checked=True)


def _summarize(findings, checked):
    findings.sort(key=lambda f: (SEV_RANK[f["severity"]], f["confidence"]), reverse=True)
    reproduced = checked and findings[0]["id"] != "no_issue_reproduced"
    return {"checked": checked, "reproduced": reproduced,
            "severity": findings[0]["severity"], "findings": findings}
finding = _f
