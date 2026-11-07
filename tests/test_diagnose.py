"""Run: python test_diagnose.py  (or pytest). Fixtures = saved evidence, no browser needed."""
from whatbroke.diagnose import diagnose


def ev(**kw):
    base = {"blocked": None, "nav_error": None, "main_status": 200, "text_len": 500,
            "console": [], "page_errors": [], "bad_responses": [], "load_ms": 1200}
    base.update(kw)
    return base


def ids(e):
    return [f["id"] for f in diagnose(e)["findings"]]


def test_dns():
    assert ids(ev(main_status=None, nav_error="net::ERR_NAME_NOT_RESOLVED at x"))[0] == "dns_failure"

def test_500():
    d = diagnose(ev(main_status=502))
    assert d["severity"] == "critical" and d["findings"][0]["id"] == "server_error"

def test_blank_with_js_error():
    e = ev(text_len=0, page_errors=["TypeError: x is undefined"],
           bad_responses=[{"url": "https://a/app.abc.js", "status": 404, "resource_type": "script"}])
    got = ids(e)
    assert "blank_page" in got and "js_runtime_error" in got and "broken_assets" in got

def test_healthy():
    d = diagnose(ev())
    assert not d["reproduced"] and d["findings"][0]["id"] == "no_issue_reproduced"

def test_blocked():
    assert ids(ev(blocked="Host resolves to a non-public address"))[0] == "blocked_target"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn(); print("ok", name)
