from whatbroke import history


def test_suggestions_and_top(tmp_path, monkeypatch):
    monkeypatch.setenv("WHATBROKE_HOME", str(tmp_path))
    for _ in range(3):
        history.record("site", "https://a.com", ["dns", "tls"], "low", False)
    history.record("site", "https://b.com", ["http"], "low", False)
    s = history.suggestions()
    assert len(s) == 1 and s[0]["count"] == 3 and "a.com" in s[0]["message"]
    assert history.top_checks()[0][1] == 3
