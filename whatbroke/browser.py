#!/usr/bin/env python3
"""Deployed-site checker: load a URL, capture evidence, diagnose with rules."""
import os
import argparse, ipaddress, json, re, socket, sys, time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

from playwright.sync_api import sync_playwright, Error as PWError


SENSITIVE_KEY = re.compile(r"(token|key|secret|sig|auth|password|session)", re.I)
MAX_ITEMS = 50


def _launch(pw):
    path = os.environ.get("WHATBROKE_BROWSER_PATH")
    if path:
        return pw.chromium.launch(executable_path=path)
    ch = os.environ.get("WHATBROKE_BROWSER_CHANNEL")
    errors = []
    for c in ([ch] if ch else [None, "chrome", "msedge"]):
        try:
            return pw.chromium.launch(channel=c) if c else pw.chromium.launch()
        except Exception as e:
            errors.append(str(e).splitlines()[0])
    raise RuntimeError("No usable browser found. Install Google Chrome or set "
                       "WHATBROKE_BROWSER_PATH. Tried: " + " | ".join(errors))


def redact_url(url):
    p = urlparse(url)
    q = [(k, "REDACTED" if SENSITIVE_KEY.search(k) else v)
         for k, v in parse_qsl(p.query, keep_blank_values=True)]
    host = p.hostname or ""
    netloc = host + (f":{p.port}" if p.port else "")  # drops user:pass@
    return urlunparse(p._replace(netloc=netloc, query=urlencode(q)))


def redact_text(s):
    s = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-]+", r"\1REDACTED", s)
    s = re.sub(r"[\w.+-]+@[\w-]+\.[\w.-]+", "REDACTED_EMAIL", s)
    return s[:500]


def check_target(url):
    """Refuse non-http(s) and private/internal addresses (SSRF guard)."""
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        return "Only http(s) URLs with a hostname are allowed."
    try:
        infos = socket.getaddrinfo(p.hostname, None)
    except socket.gaierror:
        return None  # let the browser report the DNS failure as evidence
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return f"Host resolves to a non-public address ({ip})."
    return None


def collect(url, out_dir, timeout_ms=30000, mobile=False, settle_ms=2000):
    ev = {"url": redact_url(url), "timestamp": datetime.now(timezone.utc).isoformat(),
          "device": "mobile" if mobile else "desktop", "blocked": None, "nav_error": None,
          "main_status": None, "final_url": None, "redirects": [], "title": None,
          "load_ms": None, "text_len": 0, "console": [], "page_errors": [],
          "failed_requests": [], "bad_responses": [], "screenshot": None}

    reason = check_target(url)
    if reason:
        ev["blocked"] = reason
        return ev

    with sync_playwright() as pw:
        browser = _launch(pw)
        opts = {k: v for k, v in pw.devices["iPhone 13"].items() if k != "default_browser_type"} if mobile else {"viewport": {"width": 1366, "height": 768}}
        context = browser.new_context(**opts)
        page = context.new_page()

        page.on("console", lambda m: m.type in ("error", "warning") and len(ev["console"]) < MAX_ITEMS
                and ev["console"].append({"type": m.type, "text": redact_text(m.text)}))
        page.on("pageerror", lambda e: len(ev["page_errors"]) < MAX_ITEMS
                and ev["page_errors"].append(redact_text(str(e))))
        page.on("requestfailed", lambda r: len(ev["failed_requests"]) < MAX_ITEMS
                and ev["failed_requests"].append({"url": redact_url(r.url),
                                                  "resource_type": r.resource_type,
                                                  "error": r.failure}))
        page.on("response", lambda r: r.status >= 400 and len(ev["bad_responses"]) < MAX_ITEMS
                and ev["bad_responses"].append({"url": redact_url(r.url), "status": r.status,
                                                "resource_type": r.request.resource_type}))

        start = time.monotonic()
        try:
            resp = page.goto(url, wait_until="load", timeout=timeout_ms)
            ev["load_ms"] = int((time.monotonic() - start) * 1000)
            if resp:
                ev["main_status"] = resp.status
                req, chain = resp.request, []
                while req.redirected_from:
                    req = req.redirected_from
                    chain.append(redact_url(req.url))
                ev["redirects"] = list(reversed(chain))
            page.wait_for_timeout(settle_ms)  # let late JS errors / API calls fire
            ev["final_url"] = redact_url(page.url)
            ev["title"] = page.title()
            ev["text_len"] = page.evaluate("document.body ? document.body.innerText.trim().length : 0")
        except PWError as e:
            ev["load_ms"] = int((time.monotonic() - start) * 1000)
            ev["nav_error"] = redact_text(str(e).splitlines()[0])

        try:
            shot = Path(out_dir) / f"screenshot-{ev['device']}.png"
            page.screenshot(path=str(shot), full_page=True)
            ev["screenshot"] = str(shot)
        except PWError:
            pass
        browser.close()
    return ev
