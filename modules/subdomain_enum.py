"""Subdomain enumeration via certificate transparency (crt.sh). Stdlib only."""
from core.base_module import BaseModule, ModuleResult


class SubdomainEnumModule(BaseModule):
    @property
    def name(self) -> str:
        return "subdomain_enum"

    @property
    def alias(self) -> str:
        return "what's exposed"

    @property
    def reads(self) -> str:
        return "crt.sh certificate transparency JSON API (public logs)."

    @property
    def returns(self) -> str:
        return "Deduped subdomain list, certificate count, findings."

    @property
    def failure_modes(self) -> list:
        return [
            "Certificate logs lag issuance — brand-new subdomains may be missing.",
            "Wildcard certs hide individual subdomains; absence from CT is not absence from DNS.",
            "crt.sh rate-limits aggressively; partial results look complete if you don't check the count.",
        ]

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
            if subs:
                result.add_finding(
                    claim="%d subdomains observed for %s via certificate transparency"
                          % (len(subs), dom),
                    tag="OBSERVED", method="crt.sh CT log query",
                    evidence={"certificates_seen": len(rows),
                              "sample": subs[:10],
                              "retrieved_at": resp.retrieved_at},
                    confidence="CORROBORATED" if not resp.from_cache else "LEAD")
        except Exception as e:
            # ScopeViolation, retries-exhausted URLError, JSON errors all land here
            ename = type(e).__name__
            result.status = "CONNECTION_ERROR" if ename in ("ScopeViolation", "URLError") else "ERROR"
            result.errors.append(f"crt.sh failed ({ename}): {e}")
        return result
