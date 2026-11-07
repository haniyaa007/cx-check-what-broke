"""whatbroke command line."""
import argparse
import json
import sys
from pathlib import Path

from . import history
from .browser import redact_url
from .integrations import EXAMPLE, run_integrations
from .sitecheck import DESCRIPTIONS, PRESETS, run_site_check

ICON = {"pass": "OK ", "warn": "!  ", "issues": "XX ", "error": "?  ", "skipped": "-  "}


def _findings(fs, indent="  "):
    for f in fs:
        print(f"{indent}[{f['severity'].upper()}] {f['title']}")
        for e in f.get("evidence", [])[:3]:
            print(f"{indent}    evidence: {e}")
        print(f"{indent}    next step: {f['next_step']}")


def _site(url, checks, out="runs", timeout=30):
    res = run_site_check(url, checks, out, timeout)
    print(f"\nWebsite check: {res['url']}  ->  severity: {res['severity'].upper()}")
    for n, s in res["status"].items():
        print(f"  {ICON[s]} {n:8} {DESCRIPTIONS[n]}")
    print()
    _findings(res["findings"]) if res["findings"] else print("  No issues found.")
    if res["screenshot"]:
        print(f"\n  screenshot: {Path(out) / res['screenshot']}")
    history.record("site", res["url"], res["checks"], res["severity"], res["reproduced"],
                   json.dumps({"url": res["url"], "checks": res["checks"]}))
    return res


def _integrations(text, target):
    res = run_integrations(text)
    for r in res["integrations"]:
        print(f"\n{r['name']}  ->  {r['severity'].upper()}   (likely cause: {r['likely_cause']})")
        for n, s in r["checks"].items():
            print(f"  {ICON[s]} {n}")
        _findings(r["findings"])
    history.record("integrations", target, [i["name"] for i in res["integrations"]], res["severity"],
                   res["reproduced"], text)
    return res


def _tip():
    s = history.suggestions(min_count=2, limit=1)
    if s:
        print(f"\nTip: {s[0]['message']}  (run: whatbroke again)")


def _again():
    sugg = history.suggestions(min_count=1, limit=5)
    if not sugg:
        print("No history yet. Run a check first.")
        return 0
    for i, s in enumerate(sugg, 1):
        print(f"  {i}. {s['message']}")
    pick = input("Re-run which one? (number, Enter to cancel) ").strip()
    if not pick.isdigit() or not 1 <= int(pick) <= len(sugg):
        return 0
    s = sugg[int(pick) - 1]
    if s["kind"] == "site":
        _site(s["target"], s["checks"])
    else:
        text = s["payload"] or Path(s["target"]).read_text()
        _integrations(text, s["target"])
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="whatbroke", description="CX Check What Broke: website + integration health checks")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("site", help="check a website end to end (or specific checks)")
    s.add_argument("url")
    s.add_argument("--checks", help=f"comma list of {','.join(DESCRIPTIONS)} or presets {','.join(PRESETS)} (default: full)")
    s.add_argument("--timeout", type=int, default=30)
    s.add_argument("--out", default="runs")
    i = sub.add_parser("integrations", help="check integrations from a YAML file")
    i.add_argument("config", nargs="?", help="path to YAML config (omit with --example)")
    i.add_argument("--example", action="store_true", help="print an example config")
    sub.add_parser("history", help="show your most-run checks")
    sub.add_parser("again", help="re-run something you run often")
    w = sub.add_parser("web", help="start the local web interface")
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=5000)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "site":
            res = _site(a.url, a.checks, a.out, a.timeout)
            _tip()
            return 1 if res["reproduced"] else 0
        if a.cmd == "integrations":
            if a.example or not a.config:
                print(EXAMPLE)
                return 0
            res = _integrations(Path(a.config).read_text(), a.config)
            _tip()
            return 1 if res["reproduced"] else 0
        if a.cmd == "history":
            for n, c in history.top_checks():
                print(f"  {n:8} {c}x")
            for x in history.suggestions(min_count=1, limit=5):
                print(" ", x["message"])
            return 0
        if a.cmd == "again":
            return _again()
        if a.cmd == "web":
            from .web import app
            print(f"CX Check What Broke running at http://{a.host}:{a.port}  (local use only - no login)")
            app.run(host=a.host, port=a.port)
            return 0
    except (ValueError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
