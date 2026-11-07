import base64, json, os, time
import pytest
from whatbroke import integrations as I


def jwt(claims):
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{b({'alg': 'none'})}.{b(claims)}.sig"


def ids(fs):
    return [f["id"] for f in fs or []]


def test_expired_token_from_jwt():
    claims = I._jwt_claims(jwt({"exp": time.time() - 7200}))
    assert ids(I._expiry({}, claims)) == ["token_expired"]


def test_valid_token():
    assert I._expiry({"expires_at": time.time() + 10 * 86400}, {}) == []


def test_expiring_soon_from_config():
    assert ids(I._expiry({"expires_at": time.time() + 3600}, {})) == ["token_expiring"]


def test_missing_scopes():
    fs = I._scopes({"required_scopes": ["repo", "read:org"], "granted_scopes": "repo"}, {}, None)
    assert ids(fs) == ["missing_scopes"] and "read:org" in fs[0]["title"]


def test_scopes_ok_from_header():
    assert I._scopes({"required_scopes": ["repo"]}, {}, ["repo", "gist"]) == []


def test_scopes_unverified():
    assert ids(I._scopes({"required_scopes": ["repo"]}, {}, None)) == ["scopes_unverified"]


def test_webhook_private_url_is_diagnosed():
    r = I.check_integration({"name": "x", "webhook_url": "http://127.0.0.1/hook"})
    assert r["findings"][0]["id"] == "webhook_not_public" and r["reproduced"]


def test_missing_token_env(monkeypatch):
    monkeypatch.delenv("NOPE_TOKEN", raising=False)
    r = I.check_integration({"name": "x", "token_env": "NOPE_TOKEN", "test_url": "https://example.com"})
    assert r["findings"][0]["id"] == "token_missing"


def test_bad_config():
    with pytest.raises(ValueError):
        I.load_config("foo: bar")
