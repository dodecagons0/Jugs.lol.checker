"""
jugs.lol username checker - website backend

The page (index.html) runs in the visitor's browser and decides what to check.
This server does the actual lookups on jugs.lol, because browsers are not
allowed to read another site's answers directly.

Settings (all optional, set as environment variables on your host):
  TARGET_URL      page to look names up on   default https://jugs.lol/{username}
  AVAILABLE_TEXT  text that appears when a name is free (blank = 404 means free)
  ACCESS_KEY      if set, visitors must type this key before they can check
  RATE_LIMIT      max lookups per visitor per 10 seconds (default 1000)
"""

import hmac
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from functools import lru_cache, wraps

from flask import Flask, jsonify, request, send_from_directory

from words_data import THREE_LETTER_WORDS, load_words

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_URL = os.environ.get("TARGET_URL", "https://jugs.lol/{username}")
AVAILABLE_TEXT = os.environ.get("AVAILABLE_TEXT", "").strip()
ACCESS_KEY = os.environ.get("ACCESS_KEY", "").strip()
RATE_LIMIT = int(os.environ.get("RATE_LIMIT", "1000"))
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
NAME_RE = re.compile(r"^[a-z0-9._]{1,16}$")

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Protection: optional access key + per-visitor rate limit
# ---------------------------------------------------------------------------
_hits = {}
_lock = threading.Lock()


def client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",")[0].strip() or request.remote_addr or "unknown"


def over_limit(ip):
    now = time.time()
    with _lock:
        if len(_hits) > 5000:
            _hits.clear()
        q = _hits.setdefault(ip, deque())
        while q and now - q[0] > 10:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            return True
        q.append(now)
        return False


def guarded(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if ACCESS_KEY and not hmac.compare_digest(request.headers.get("X-Key", ""), ACCESS_KEY):
            return jsonify(state="auth", detail="access key needed"), 401
        if over_limit(client_ip()):
            return jsonify(state="rate", detail="too many requests"), 429
        return fn(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# Looking a name up on the target site
# ---------------------------------------------------------------------------
def build_url(name):
    return TARGET_URL.replace("{username}", urllib.parse.quote(name, safe=""))


def fetch(name, want_body):
    """Return (status, final_url, body) or raise on network failure."""
    req = urllib.request.Request(build_url(name), headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read(300000).decode("utf-8", "ignore") if want_body else ""
            return r.status, r.geturl(), body
    except urllib.error.HTTPError as e:
        body = ""
        if want_body:
            try:
                body = e.read(300000).decode("utf-8", "ignore")
            except Exception:
                pass
        return e.code, build_url(name), body


def verdict_for(status, body):
    if status == 429:
        return "rate"
    if AVAILABLE_TEXT:
        if AVAILABLE_TEXT.lower() in body.lower():
            return "available"
        return "taken" if status < 400 else "unknown"
    if status == 404:
        return "available"
    if 200 <= status < 300:
        return "taken"
    return "unknown"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/api/config")
def config():
    return jsonify(needs_key=bool(ACCESS_KEY))


@lru_cache(maxsize=None)
def _words(lo, hi):
    return [w for w in load_words() if lo <= len(w) <= hi]


@app.route("/api/words")
@guarded
def words():
    if request.args.get("mode") == "3l":
        return jsonify(THREE_LETTER_WORDS.split())
    lo = max(4, min(8, request.args.get("min", 4, type=int)))
    hi = max(4, min(8, request.args.get("max", 6, type=int)))
    if lo > hi:
        lo, hi = hi, lo
    return jsonify(_words(lo, hi))


@app.route("/api/check")
@guarded
def check():
    name = request.args.get("name", "").lower()
    if not NAME_RE.match(name):
        return jsonify(state="unknown", detail="bad name"), 400
    try:
        status, _, body = fetch(name, bool(AVAILABLE_TEXT))
    except Exception as e:
        return jsonify(state="error", detail=str(e)[:80])
    return jsonify(state=verdict_for(status, body), detail=f"HTTP {status}")


@app.route("/api/test")
@guarded
def test():
    name = request.args.get("name", "").lower()
    if not NAME_RE.match(name):
        return jsonify(error="Names can only use letters, numbers, . and _ (max 16)."), 400
    try:
        status, final, body = fetch(name, True)
    except Exception as e:
        return jsonify(error=f"Could not connect: {str(e)[:100]}")
    return jsonify(
        asked=build_url(name),
        ended=final,
        status=status,
        page=" ".join(body.split())[:300],
        verdict=verdict_for(status, body),
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
