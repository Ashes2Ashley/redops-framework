"""HTTP methods + cookie flags + tech fingerprint. Stdlib only."""
import socket
import ssl
import urllib.request
import urllib.error
from core.base_module import BaseModule, ModuleResult

class HTTPMethodsModule(BaseModule):
    @property
    def name(self) -> str:
        return "http_methods"

    @property
    def description(self) -> str:
        return "Audits allowed HTTP methods (OPTIONS/TRACE) for dangerous verbs."

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        url = self.target if self.target.startswith(("http://", "https://")) else "https://" + self.target
        risky = {"TRACE", "TRACK", "PUT", "DELETE", "CONNECT"}
        try:
            req = urllib.request.Request(url, method="OPTIONS", headers={"User-Agent": "SecurityFramework/1.0"})
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                allow = resp.headers.get("Allow", "") or resp.headers.get("allow", "")
            methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
            bad = sorted(set(methods) & risky)
            result.status = "SUCCESS"
            result.data = {"url": url, "allow_header": allow or "(not advertised)",
                           "methods_seen": methods, "risky_methods": bad,
                           "verdict": "RISKY methods enabled: " + ", ".join(bad) if bad else "no risky methods advertised"}
        except urllib.error.HTTPError as e:
            result.status = "SUCCESS"
            result.data = {"url": url, "note": f"server refused OPTIONS (HTTP {e.code}) — methods not advertised"}
        except Exception as e:
            result.status = "ERROR"; result.errors.append(str(e))
        return result


class CookieAuditModule(BaseModule):
    @property
    def name(self) -> str:
        return "cookie_audit"

    @property
    def description(self) -> str:
        return "Checks cookie flags: Secure, HttpOnly, SameSite."

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        url = self.target if self.target.startswith(("http://", "https://")) else "https://" + self.target
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SecurityFramework/1.0"})
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
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
        except Exception as e:
            result.status = "ERROR"; result.errors.append(str(e))
        return result


class TechFingerprintModule(BaseModule):
    @property
    def name(self) -> str:
        return "tech_fingerprint"

    @property
    def description(self) -> str:
        return "Infers server tech from headers and HTML markers."

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        url = self.target if self.target.startswith(("http://", "https://")) else "https://" + self.target
        hints = {}
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SecurityFramework/1.0"})
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
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
        except Exception as e:
            result.status = "ERROR"; result.errors.append(str(e))
        return result
