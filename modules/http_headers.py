import urllib.request
import urllib.error
import ssl
from core.base_module import BaseModule, ModuleResult

class HTTPHeadersModule(BaseModule):
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
