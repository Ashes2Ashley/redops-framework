"""HTTP methods + cookie flags + tech fingerprint. Stdlib only.

Note: these modules keep raw urllib with CERT_NONE (intentional — they audit
misconfigured hosts). Scope is enforced explicitly at the top of each run()
instead of via HttpClient.
"""
import socket
import ssl
import urllib.request
import urllib.error
from urllib.parse import urlsplit
from core.base_module import BaseModule, ModuleResult, gap_finding
from core.scope import ScopeViolation


def _scope_check(module, url, result):
    """Explicit fail-closed scope check for raw-urllib modules. Returns True
    if the run may proceed."""
    scope = module.config.get("_scope")
    if scope is not None:
        try:
            scope.require_url(url)
        except ScopeViolation as e:
            result.status = "FAILED"
            result.errors.append(str(e))
            return False
    elif not module.config.get("_allow_all", False):
        result.status = "FAILED"
        result.errors.append("unscoped run refused (no scope, no --allow-all)")
        return False
    return True


def _insecure_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class HTTPMethodsModule(BaseModule):
    @property
    def name(self) -> str:
        return "http_methods"

    @property
    def alias(self) -> str:
        return "dangerous verbs check"

    @property
    def description(self) -> str:
        return "Audits allowed HTTP methods (OPTIONS/TRACE) for dangerous verbs."

    @property
    def reads(self) -> str:
        return "HTTP OPTIONS response from the target URL."

    @property
    def returns(self) -> str:
        return "Advertised methods, risky-method subset, verdict, findings."

    @property
    def failure_modes(self) -> list:
        return [
            "Many servers refuse OPTIONS or lie in the Allow header — absence of advertisement is not proof of absence.",
            "WAFs may filter the response; you see the edge's policy, not the origin's.",
        ]

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        url = self.target if self.target.startswith(("http://", "https://")) else "https://" + self.target
        if not _scope_check(self, url, result):
            return result
        risky = {"TRACE", "TRACK", "PUT", "DELETE", "CONNECT"}
        try:
            req = urllib.request.Request(url, method="OPTIONS", headers={"User-Agent": "SecurityFramework/1.0"})
            with urllib.request.urlopen(req, context=_insecure_ctx(), timeout=10) as resp:
                allow = resp.headers.get("Allow", "") or resp.headers.get("allow", "")
            methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
            bad = sorted(set(methods) & risky)
            result.status = "SUCCESS"
            result.data = {"url": url, "allow_header": allow or "(not advertised)",
                           "methods_seen": methods, "risky_methods": bad,
                           "verdict": "RISKY methods enabled: " + ", ".join(bad) if bad else "no risky methods advertised"}
            if bad:
                result.add_finding(
                    claim="Risky HTTP methods advertised by %s: %s"
                          % (urlsplit(url).hostname, ", ".join(bad)),
                    tag="OBSERVED", method="HTTP OPTIONS request",
                    evidence={"allow_header": allow}, confidence="CORROBORATED")
            else:
                result.add_finding(
                    claim="No risky HTTP methods advertised by %s" % urlsplit(url).hostname,
                    tag="OBSERVED", method="HTTP OPTIONS request",
                    evidence={"allow_header": allow or "(not advertised)"},
                    confidence="LEAD", quarantined=True)
        except urllib.error.HTTPError as e:
            result.status = "SUCCESS"
            result.data = {"url": url, "note": f"server refused OPTIONS (HTTP {e.code}) — methods not advertised"}
            result.findings.append(gap_finding(self.name, self.target,
                                               "server refused OPTIONS probing"))
        except Exception as e:
            ename = type(e).__name__
            result.status = "CONNECTION_ERROR" if ename in ("URLError",) else "ERROR"
            result.errors.append("%s: %s" % (ename, e))
        return result


class CookieAuditModule(BaseModule):
    @property
    def name(self) -> str:
        return "cookie_audit"

    @property
    def alias(self) -> str:
        return "cookie flags check"

    @property
    def description(self) -> str:
        return "Checks cookie flags: Secure, HttpOnly, SameSite."

    @property
    def reads(self) -> str:
        return "Set-Cookie headers from a single GET to the target URL."

    @property
    def returns(self) -> str:
        return "Per-cookie flag issues, verdict, findings."

    @property
    def failure_modes(self) -> list:
        return [
            "Only the landing page's cookies are seen — authenticated flows set different cookies.",
            "Some flags are set via JavaScript (document.cookie) and never appear in headers.",
        ]

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        url = self.target if self.target.startswith(("http://", "https://")) else "https://" + self.target
        if not _scope_check(self, url, result):
            return result
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SecurityFramework/1.0"})
            with urllib.request.urlopen(req, context=_insecure_ctx(), timeout=10) as resp:
                raw = resp.headers.get_all("Set-Cookie") or []
            findings = []
            for c in raw:
                low = c.lower()
                name = c.split("=", 1)[0]
                issues = []
                if "secure" not in low: issues.append("missing Secure")
                if "httponly" not in low: issues.append("missing HttpOnly")
                if "samesite" not in low: issues.append("missing SameSite")
                findings.append({"cookie": name, "issues": issues, "ok": not issues})
            result.status = "SUCCESS"
            result.data = {"url": url, "cookies_seen": len(findings), "cookies": findings,
                           "verdict": "all cookies hardened" if findings and all(f["ok"] for f in findings)
                                        else f"{sum(1 for f in findings if not f['ok'])} cookie(s) need flags" if findings
                                        else "no cookies set"}
            for f in findings:
                if not f["ok"]:
                    result.add_finding(
                        claim="Cookie '%s' on %s missing flags: %s"
                              % (f["cookie"], urlsplit(url).hostname, ", ".join(f["issues"])),
                        tag="OBSERVED", method="Set-Cookie header inspection (single GET)",
                        evidence={"cookie": f["cookie"]}, confidence="CORROBORATED")
        except Exception as e:
            ename = type(e).__name__
            result.status = "CONNECTION_ERROR" if ename in ("URLError",) else "ERROR"
            result.errors.append("%s: %s" % (ename, e))
        return result


class TechFingerprintModule(BaseModule):
    @property
    def name(self) -> str:
        return "tech_fingerprint"

    @property
    def alias(self) -> str:
        return "stack guesser"

    @property
    def description(self) -> str:
        return "Infers server tech from headers and HTML markers."

    @property
    def reads(self) -> str:
        return "Response headers + first 60KB of HTML from the target URL."

    @property
    def returns(self) -> str:
        return "Technology indicators (quarantined — fingerprinting misfires), findings."

    @property
    def failure_modes(self) -> list:
        return [
            "Fingerprinting misfires on custom stacks and deliberately misleading headers.",
            "Markers are hints, not identifications — a wp-content path can be a decoy or a leftover.",
            "Minified/bundled frontends hide framework markers.",
        ]

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        url = self.target if self.target.startswith(("http://", "https://")) else "https://" + self.target
        if not _scope_check(self, url, result):
            return result
        hints = {}
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SecurityFramework/1.0"})
            with urllib.request.urlopen(req, context=_insecure_ctx(), timeout=10) as resp:
                for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator", "Via"):
                    v = resp.headers.get(h)
                    if v: hints[h] = v
                body = resp.read(60000).decode("utf-8", "replace").lower()
            markers = {
                "wordpress": ["wp-content", "wp-includes"],
                "drupal": ["drupal.js", "sites/default"],
                "shopify": ["cdn.shopify.com"],
                "cloudflare": ["__cf_bm", "cf-ray"],
                "next.js": ["_next/static"],
                "nuxt": ["_nuxt/"],
                "django": ["csrftoken", "django"],
                "laravel": ["laravel_session"],
                "php": [".php"],
            }
            found = [tech for tech, marks in markers.items() if any(m in body for m in marks)]
            if found: hints["framework_hints"] = found
            result.status = "SUCCESS"
            result.data = {"url": url, "indicators": hints or {"note": "no telltale markers found"}}
            if found:
                # Fingerprinting is inherently inferential: quarantine at LEAD.
                result.add_finding(
                    claim="Technology indicators suggest %s on %s"
                          % (", ".join(found), urlsplit(url).hostname),
                    tag="INFERRED",
                    method="header + HTML marker matching (single GET)",
                    evidence={"markers_matched": found, "headers_seen": [k for k in hints if k != "framework_hints"]},
                    confidence="LEAD", quarantined=True)
        except Exception as e:
            ename = type(e).__name__
            result.status = "CONNECTION_ERROR" if ename in ("URLError",) else "ERROR"
            result.errors.append("%s: %s" % (ename, e))
        return result
