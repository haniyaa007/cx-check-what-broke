import pytest
from whatbroke.sitecheck import resolve_checks, run_site_check


def test_presets_and_validation():
    assert resolve_checks("ssl") == ["dns", "tls"]
    assert resolve_checks(None)[0] == "dns"
    with pytest.raises(ValueError):
        resolve_checks("nope")


def test_private_target_blocked(tmp_path):
    r = run_site_check("http://127.0.0.1:8080", None, tmp_path)
    assert r["findings"][0]["id"] == "blocked_target" and not r["reproduced"]
