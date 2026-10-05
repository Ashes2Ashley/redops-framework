"""Subdomain enumeration via certificate transparency (crt.sh). Stdlib only."""
from core.base_module import BaseModule, ModuleResult


class SubdomainEnumModule(BaseModule):
    @property
    def name(self) -> str:
        return "subdomain_enum"

    @property
    def description(self) -> str:
        return "Finds subdomains from public certificate transparency logs."

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        dom = self.target.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
        if not dom or "." not in dom:
            result.status = "FAILED"; result.errors.append("give a domain, e.g. runehall.com"); return result
        try:
            client = self.http_client()  # scoped, audited, cached, retried
            resp = client.get("https://crt.sh/?q=%25." + dom + "&output=json")
            if resp.status != 200:
                result.status = "CONNECTION_ERROR"
                result.errors.append(f"crt.sh returned HTTP {resp.status}")
                return result
            rows = resp.json()
            subs = set()
            for r in rows:
                for n in str(r.get("name_value", "")).split("\n"):
                    n = n.strip().lower()
                    if n and not n.startswith("*") and n.endswith(dom):
                        subs.add(n)
            subs = sorted(subs)
            result.status = "SUCCESS"
            result.data = {"domain": dom, "certificates_seen": len(rows),
                           "subdomains_found": len(subs), "subdomains": subs[:100],
                           "served_from_cache": resp.from_cache}
        except Exception as e:
            # ScopeViolation, retries-exhausted URLError, JSON errors all land here
            ename = type(e).__name__
            result.status = "CONNECTION_ERROR" if ename in ("ScopeViolation", "URLError") else "ERROR"
            result.errors.append(f"crt.sh failed ({ename}): {e}")
        return result
