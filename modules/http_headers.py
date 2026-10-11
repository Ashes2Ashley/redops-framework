import urllib.request
import urllib.error
import ssl
from urllib.parse import urlsplit
from core.base_module import BaseModule, ModuleResult
from core.scope import ScopeViolation


class HTTPHeadersModule(BaseModule):
    @property
    def alias(self) -> str:
        return "headers and hygiene"

    @property
    def reads(self) -> str:
        return "Live HTTP response headers from the target URL (ordinary GET)."

    @property
    def returns(self) -> str:
        return "Present/missing security headers, server banner, findings per missing header."

    @property
    def failure_modes(self) -> list:
        return [
            "WAF or CDN can inject, strip, or rewrite headers — what you see may be the edge, not the origin.",
            "CERT_NONE is intentional (audits misconfigured hosts) — a presented page may be a captive portal or interceptor.",
            "One response is one moment: header deployments change; observed_date marks when seen.",
        ]
    @property
    def name(self) -> str:
        return "http_headers"

    @property
    def description(self) -> str:
        return "Inspects and audits standard HTTP security headers for a web target."

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)

        url = self.target
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        # Fail-closed scope check. This module keeps raw urllib (CERT_NONE is
        # intentional for auditing misconfigured hosts), so scope is enforced
        # here explicitly instead of via HttpClient.
        scope = self.config.get("_scope")
        if scope is not None:
            try:
                scope.require_url(url)
            except ScopeViolation as e:
                result.status = "FAILED"
                result.errors.append(str(e))
                return result
        elif not self.config.get("_allow_all", False):
            result.status = "FAILED"
            result.errors.append("unscoped run refused (no scope, no --allow-all)")
            return result

        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]

        req = urllib.request.Request(
            url,
            headers={"User-Agent": "SecurityFramework/1.0"}
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
                resp_headers = dict(response.headers)

                present = {}
                missing = []

                for header in security_headers:
                    found_key = next((k for k in resp_headers if k.lower() == header.lower()), None)
                    if found_key:
                        present[header] = resp_headers[found_key]
                    else:
                        missing.append(header)

                result.status = "SUCCESS"
                result.data = {
                    "url_tested": url,
                    "status_code": response.status,
                    "server": resp_headers.get("Server", "Unspecified"),
                    "security_headers_present": present,
                    "security_headers_missing": missing
                }
                for h in missing:
                    result.add_finding(
                        claim="Security header missing on %s: %s" % (urlsplit(url).hostname, h),
                        tag="OBSERVED",
                        method="HTTP response header audit (single GET, CERT_NONE)",
                        evidence={"url": url, "status": response.status},
                        confidence="CORROBORATED")
                if not missing:
                    result.add_finding(
                        claim="All six audited security headers present on %s"
                              % urlsplit(url).hostname,
                        tag="OBSERVED",
                        method="HTTP response header audit (single GET, CERT_NONE)",
                        evidence={"url": url, "status": response.status},
                        confidence="CORROBORATED")

        except urllib.error.HTTPError as e:
            result.status = "HTTP_ERROR"
            result.errors.append(f"HTTP Error {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            result.status = "CONNECTION_ERROR"
            result.errors.append(f"Connection failed: {str(e.reason)}")
        except Exception as e:
            result.status = "ERROR"
            result.errors.append(f"Unexpected error: {str(e)}")

        return result
