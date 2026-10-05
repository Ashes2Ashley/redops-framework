"""Domain registration data via RDAP. Stdlib only."""
import json
import urllib.request
import urllib.error
from core.base_module import BaseModule, ModuleResult

class RDAPModule(BaseModule):
    @property
    def name(self) -> str:
        return "rdap_domain"

    @property
    def description(self) -> str:
        return "RDAP whois: registrar, creation/expiry dates, status, nameservers."

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        dom = self.target.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
        if not dom or "." not in dom:
            result.status = "FAILED"
            result.errors.append("give a domain, e.g. example.com")
            return result
        try:
            req = urllib.request.Request(
                "https://rdap.org/domain/" + dom,
                headers={"User-Agent": "SecurityFramework/1.0", "accept": "application/rdap+json"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                j = json.loads(resp.read().decode("utf-8", "replace"))
            registrar = "?"
            for ent in j.get("entities", []):
                if "registrar" in (ent.get("roles") or []):
                    for v in (ent.get("vcardArray", [None, []])[1] or []):
                        if v[0] == "fn":
                            registrar = v[3]
                    break
            events = {e.get("eventAction"): (e.get("eventDate") or "")[:10] for e in j.get("events", [])}
            result.status = "SUCCESS"
            result.data = {
                "domain": dom,
                "registrar": registrar,
                "created": events.get("registration", "?"),
                "expires": events.get("expiration", "?"),
                "updated": events.get("last changed", "?"),
                "status": j.get("status", []),
                "nameservers": [n.get("ldhName") for n in j.get("nameservers", []) if n.get("ldhName")],
            }
        except urllib.error.HTTPError as e:
            result.status = "HTTP_ERROR"
            result.errors.append(f"HTTP {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            result.status = "CONNECTION_ERROR"
            result.errors.append(f"RDAP lookup failed: {e.reason}")
        except Exception as e:
            result.status = "ERROR"
            result.errors.append(f"Unexpected error: {e}")
        return result
