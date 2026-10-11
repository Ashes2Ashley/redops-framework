"""Domain registration data via RDAP. Stdlib only."""
from core.base_module import BaseModule, ModuleResult, gap_finding

class RDAPModule(BaseModule):
    @property
    def name(self) -> str:
        return "rdap_domain"

    @property
    def description(self) -> str:
        return "RDAP whois: registrar, creation/expiry dates, status, nameservers."

    @property
    def alias(self) -> str:
        return "who holds the name"

    @property
    def reads(self) -> str:
        return "Public RDAP registration data (rdap.org bootstrap)."

    @property
    def returns(self) -> str:
        return "Registrar, creation/expiry/updated dates, status flags, nameservers, findings."

    @property
    def failure_modes(self) -> list:
        return [
            "Privacy redaction hides the registrant — absence of identity is not evidence of anything.",
            "Registrar-supplied data can be stale or false; treat as self-reported.",
            "Some TLDs have no RDAP service — gap, not proof of anything.",
        ]

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        dom = self.target.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
        if not dom or "." not in dom:
            result.status = "FAILED"
            result.errors.append("give a domain, e.g. runehall.com")
            return result
        client, err = self.scoped_client()
        if err:
            result.status = "FAILED"
            result.errors.append("unscoped HTTP client refused: " + err)
            return result
        try:
            resp = client.get(
                "https://rdap.org/domain/" + dom,
                headers={"accept": "application/rdap+json"},
            )
            if resp.status == 404:
                result.status = "FAILED"
                result.errors.append("RDAP: domain not found")
                result.findings.append(gap_finding(self.name, self.target,
                                                   "no RDAP record for " + dom))
                return result
            if resp.status != 200:
                result.status = "CONNECTION_ERROR"
                result.errors.append("RDAP returned HTTP %s" % resp.status)
                return result
            j = resp.json()
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
                "served_from_cache": resp.from_cache,
            }
            if registrar and registrar != "?":
                result.add_finding(
                    claim="Domain %s registered via %s" % (dom, registrar),
                    tag="OBSERVED", method="RDAP query to rdap.org",
                    evidence={"url": "https://rdap.org/domain/" + dom,
                              "retrieved_at": resp.retrieved_at},
                    confidence="CORROBORATED" if not resp.from_cache else "LEAD")
            if events.get("registration"):
                result.add_finding(
                    claim="Domain %s created %s" % (dom, events["registration"]),
                    tag="OBSERVED", method="RDAP registration event",
                    evidence={"eventDate": events["registration"]},
                    confidence="CORROBORATED")
        except Exception as e:
            ename = type(e).__name__
            result.status = "CONNECTION_ERROR" if ename in ("ScopeViolation", "URLError") else "ERROR"
            result.errors.append(f"RDAP lookup failed ({ename}): {e}")
        return result
