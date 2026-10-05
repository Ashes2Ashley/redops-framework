"""Stdlib-only HTTP client: per-host concurrency, backoff, disk cache, audit.

Replaces ad-hoc urllib.request.urlopen calls throughout the modules.
"""
from __future__ import annotations

import base64
import email.utils
import hashlib
import json
import os
import random
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

DEFAULT_UA = "redops/1.0 (+authorized-testing)"
RETRY_STATUS = {429, 500, 502, 503, 504}


@dataclass
class HttpResponse:
    url: str
    status: int
    headers: dict
    body: bytes
    from_cache: bool
    elapsed_ms: int
    retrieved_at: str

    def text(self, encoding=None):
        return self.body.decode(encoding or "utf-8", "replace")

    def json(self):
        return json.loads(self.body)


class HttpClient:
    def __init__(self, *, tool, scope=None, audit=None, user_agent=DEFAULT_UA,
                 cache_dir=None, cache_ttl=3600, max_per_host=2, timeout=30,
                 retries=3, allow_all=False):
        if scope is None and not allow_all:
            raise ValueError(
                "HttpClient requires a Scope (or explicit allow_all=True). "
                "Refusing to run unscoped.")
        self.tool = tool
        self.scope = scope
        self.audit = audit
        self.user_agent = user_agent
        self.cache_dir = cache_dir
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        self.retries = retries
        self.max_per_host = max_per_host
        self._host_sems = {}
        self._sems_lock = threading.Lock()
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)

    # -- internals --------------------------------------------------------

    def _sem(self, host):
        with self._sems_lock:
            sem = self._host_sems.get(host)
            if sem is None:
                sem = threading.Semaphore(self.max_per_host)
                self._host_sems[host] = sem
            return sem

    def _cache_path(self, method, url, headers):
        h = hashlib.sha256()
        h.update(method.encode()); h.update(b"\0")
        h.update(url.encode()); h.update(b"\0")
        for k in sorted(headers):
            h.update(("%s:%s" % (k, headers[k])).encode()); h.update(b"\0")
        return os.path.join(self.cache_dir, h.hexdigest() + ".json")

    def _cache_get(self, path):
        try:
            with open(path) as f:
                rec = json.load(f)
        except (OSError, ValueError):
            return None
        if time.time() - rec.get("stored_at", 0) > self.cache_ttl:
            return None
        return HttpResponse(
            url=rec["url"], status=rec["status"], headers=rec["headers"],
            body=base64.b64decode(rec["body_b64"]), from_cache=True,
            elapsed_ms=rec.get("elapsed_ms", 0), retrieved_at=rec["retrieved_at"])

    def _cache_put(self, path, resp):
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({
                "url": resp.url, "status": resp.status, "headers": resp.headers,
                "body_b64": base64.b64encode(resp.body).decode(),
                "elapsed_ms": resp.elapsed_ms, "retrieved_at": resp.retrieved_at,
                "stored_at": time.time()}, f)
        os.replace(tmp, path)

    @staticmethod
    def _retry_after(headers):
        v = headers.get("Retry-After")
        if not v:
            return None
        try:
            return max(0.0, float(v))
        except ValueError:
            pass
        try:
            dt = email.utils.parsedate_to_datetime(v)
            return max(0.0, (dt - datetime.now(timezone.utc)).total_seconds())
        except (TypeError, ValueError):
            return None

    def _audit(self, method, url, status, ms, from_cache=False, error=None):
        if self.audit is not None:
            self.audit.record(tool=self.tool, method=method, url=url,
                              status=status, elapsed_ms=ms,
                              from_cache=from_cache, error=error)

    # -- public -----------------------------------------------------------

    def get(self, url, *, headers=None, use_cache=True):
        return self._request("GET", url, headers=headers, use_cache=use_cache)

    def _request(self, method, url, *, headers=None, use_cache=True):
        headers = dict(headers or {})
        headers.setdefault("User-Agent", self.user_agent)

        if self.scope is not None:
            self.scope.require_url(url)   # raises ScopeViolation

        cache_path = None
        if use_cache and self.cache_dir and method == "GET":
            cache_path = self._cache_path(method, url, headers)
            hit = self._cache_get(cache_path)
            if hit is not None:
                self._audit(method, url, hit.status, 0, from_cache=True)
                return hit

        host = urllib.parse.urlsplit(url).hostname or ""
        sem = self._sem(host)

        for attempt in range(self.retries + 1):
            delay = None
            with sem:
                t0 = time.monotonic()
                try:
                    req = urllib.request.Request(url, headers=headers, method=method)
                    with urllib.request.urlopen(req, timeout=self.timeout) as r:
                        resp = HttpResponse(
                            url=r.geturl(), status=r.status,
                            headers={k.lower(): v for k, v in r.headers.items()},
                            body=r.read(), from_cache=False,
                            elapsed_ms=int((time.monotonic() - t0) * 1000),
                            retrieved_at=datetime.now(timezone.utc).isoformat(
                                timespec="seconds"))
                    self._audit(method, url, resp.status, resp.elapsed_ms)
                    if cache_path:
                        self._cache_put(cache_path, resp)
                    return resp

                except urllib.error.HTTPError as e:
                    ms = int((time.monotonic() - t0) * 1000)
                    body = e.read() if e.fp else b""
                    hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
                    if e.code not in RETRY_STATUS or attempt == self.retries:
                        self._audit(method, url, e.code, ms)
                        return HttpResponse(
                            url=url, status=e.code, headers=hdrs, body=body,
                            from_cache=False, elapsed_ms=ms,
                            retrieved_at=datetime.now(timezone.utc).isoformat(
                                timespec="seconds"))
                    delay = self._retry_after(hdrs)
                    self._audit(method, url, e.code, ms, error="retrying")

                except (urllib.error.URLError, TimeoutError, OSError) as e:
                    ms = int((time.monotonic() - t0) * 1000)
                    if attempt == self.retries:
                        self._audit(method, url, None, ms, error=type(e).__name__)
                        raise
                    self._audit(method, url, None, ms, error="retrying")

            if delay is None:
                delay = min(30.0, 2.0 ** attempt) * (1 + random.random() * 0.3)
            time.sleep(delay)
