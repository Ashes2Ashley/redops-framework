"""Favicon hash for origin correlation. Stdlib only.

Multi-engine corroboration (doctrine): favicon hash + page title + certificate
+ DNS history must agree before any origin claim. This module supplies the
favicon engine.
"""
import hashlib
from urllib.parse import urlsplit
from core.base_module import BaseModule, ModuleResult, gap_finding


class FaviconHashModule(BaseModule):
    @property
    def name(self) -> str:
        return "favicon_hash"

    @property
    def alias(self) -> str:
        return "site icon fingerprint"

    @property
    def description(self) -> str:
        return "Fetches /favicon.ico and hashes it (md5/sha256) for origin correlation."

    @property
    def reads(self) -> str:
        return "The target's /favicon.ico via ordinary HTTPS GET (falls back to page <link> icon)."

    @property
    def returns(self) -> str:
        return "md5/sha256 hashes, byte size, source URL, findings."

    @property
    def failure_modes(self) -> list:
        return [
            "Many sites share default favicons (framework/CMS defaults) — a match is a weak signal, not identity.",
            "Favicons change on rebrand; a mismatch across time is normal.",
            "Some sites serve no favicon or block the path — gap, not evidence.",
            "CDN-cached icons can lag the origin's current icon.",
        ]

    def _fetch(self, client, url):
        resp = client.get(url)
        if resp.status == 200 and resp.body:
            ctype = resp.headers.get("content-type", "")
            if "image" in ctype or len(resp.body) > 0:
                return resp
        return None

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        base = self.target if self.target.startswith(("http://", "https://")) else "https://" + self.target
        host = urlsplit(base).hostname or ""
        if not host:
            result.status = "FAILED"
            result.errors.append("give a hostname or URL")
            return result
        client, err = self.scoped_client()
        if err:
            result.status = "FAILED"
            result.errors.append("unscoped HTTP client refused: " + err)
            return result
        try:
            resp = self._fetch(client, base.rstrip("/") + "/favicon.ico")
            icon_url = base.rstrip("/") + "/favicon.ico"
            if resp is None:
                # Fall back: look for <link rel="icon"> in the page.
                page = client.get(base)
                icon_url = None
                if page.status == 200:
                    html = page.text().lower()
                    for marker in ('rel="icon"', "rel='icon'", 'rel="shortcut icon"'):
                        i = html.find(marker)
                        if i != -1:
                            seg = html[max(0, i - 300):i + 300]
                            h = seg.find("href=")
                            if h != -1:
                                q = seg[h + 5]
                                e = seg.find(q, h + 6)
                                href = seg[h + 6:e]
                                if href.startswith("/"):
                                    href = base.rstrip("/") + href
                                elif not href.startswith("http"):
                                    href = base.rstrip("/") + "/" + href
                                icon_url = href
                                break
                if icon_url:
                    resp = self._fetch(client, icon_url)
            if resp is None:
                result.status = "SUCCESS"
                result.data = {"host": host, "favicon": None}
                result.findings.append(gap_finding(self.name, self.target,
                                                   "no favicon retrievable for " + host))
                return result
            md5 = hashlib.md5(resp.body).hexdigest()
            sha256 = hashlib.sha256(resp.body).hexdigest()
            result.status = "SUCCESS"
            result.data = {"host": host, "icon_url": icon_url,
                           "bytes": len(resp.body), "md5": md5, "sha256": sha256,
                           "served_from_cache": resp.from_cache}
            # A favicon hash alone is a weak signal: quarantine at LEAD.
            result.add_finding(
                claim="Favicon hash for %s: md5 %s" % (host, md5),
                tag="OBSERVED", method="favicon fetch + md5/sha256",
                evidence={"sha256": sha256, "bytes": len(resp.body),
                          "icon_url": icon_url, "retrieved_at": resp.retrieved_at},
                confidence="LEAD", quarantined=True)
        except Exception as e:
            ename = type(e).__name__
            result.status = "CONNECTION_ERROR" if ename in ("ScopeViolation", "URLError") else "ERROR"
            result.errors.append("favicon fetch failed (%s): %s" % (ename, e))
        return result
