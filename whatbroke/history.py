"""Local run history (SQLite) so the tool can suggest checks you run often. Never stores secrets."""
import os
import sqlite3
import time
from collections import Counter
from pathlib import Path

SCHEMA = ("CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY, ts REAL, kind TEXT, target TEXT, "
          "checks TEXT, severity TEXT, reproduced INTEGER, payload TEXT)")


def _run(sql, args=(), fetch=False):
    home = Path(os.environ.get("WHATBROKE_HOME") or Path.home() / ".whatbroke")
    home.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(home / "history.db")
    try:
        c.execute(SCHEMA)
        cur = c.execute(sql, args)
        c.commit()
        return cur.fetchall() if fetch else None
    finally:
        c.close()


def record(kind, target, checks, severity, reproduced, payload=None):
    _run("INSERT INTO runs (ts,kind,target,checks,severity,reproduced,payload) VALUES (?,?,?,?,?,?,?)",
         (time.time(), kind, target, ",".join(sorted(checks)), severity, int(reproduced), payload))


def _ago(ts):
    s = time.time() - ts
    return "just now" if s < 90 else f"{int(s // 60)} min ago" if s < 5400 else \
        f"{int(s // 3600)}h ago" if s < 172800 else f"{int(s // 86400)} days ago"


def suggestions(min_count=2, limit=3):
    rows = _run("SELECT kind,target,checks,COUNT(*),MAX(ts),payload FROM runs GROUP BY kind,target,checks "
                "HAVING COUNT(*)>=? ORDER BY COUNT(*) DESC, MAX(ts) DESC LIMIT ?", (min_count, limit), True)
    return [{"kind": k, "target": t, "checks": c, "count": n, "payload": p,
             "message": f"You've run '{c}' on {t} {n}x (last {_ago(ts)}). Run it again?"}
            for k, t, c, n, ts, p in rows]


def top_checks(limit=5):
    cnt = Counter()
    for (c,) in _run("SELECT checks FROM runs WHERE kind='site'", fetch=True):
        cnt.update(c.split(","))
    return cnt.most_common(limit)
