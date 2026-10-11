"""DNS reconnaissance via Cloudflare DoH (JSON API). Stdlib only."""
from core.base_module import BaseModule, ModuleResult, gap_finding

DOH = "https://cloudflare-dns.com/dns-query?name={name}&type={rtype}"
TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"]


class DNSReconModule(BaseModule):
    @property
    def name(self) -> str:
        return "dns_recon"

    @property
    def alias(self) -> str:
        return "name records"

    @property
    def description(self) -> str:
        return "Enumerates DNS records (A/AAAA/MX/TXT/NS/CNAME/SOA/CAA) via DNS-over-HTTPS."

    @property
    def reads(self) -> str:
        return "Cloudflare DNS-over-HTTPS JSON API (public resolver)."

    @property
    def returns(self) -> str:
        return "Per-type answer lists, record_types_found count, plus evidence-chained findings."

    @property
    def failure_modes(self) -> list:
        return [
            "Resolver poisoning or filtering returns wrong/empty answers — cross-check critical records.",
            "Stale cache: the resolver may serve outdated records; observed_date marks when seen.",
            "Split-horizon DNS: public answers can differ from what the target's own users resolve.",
            "Empty answer is not proof of nonexistence — it is one resolver's view at one moment.",
        ]

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        host = self.target.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
        if not host or "." not in host:
            result.status = "FAILED"
            result.errors.append("give a domain, e.g. example.com")
            return result
        client, err = self.scoped_client()
        if err:
            result.status = "FAILED"
            result.errors.append("unscoped HTTP client refused: " + err)
            return result
        records = {}
        try:
            for rtype in TYPES:
                resp = client.get(DOH.format(name=host, rtype=rtype),
                                  headers={"accept": "application/dns-json"})
                if resp.status != 200:
                    result.errors.append("DoH %s returned HTTP %s" % (rtype, resp.status))
                    records[rtype] = []
                    continue
                body = resp.json()
                answers = [a.get("data", "") for a in body.get("Answer", [])]
                records[rtype] = answers
                if answers:
                    result.add_finding(
                        claim="DNS %s records observed for %s: %s"
                              % (rtype, host, ", ".join(answers[:5])),
                        tag="OBSERVED",
                        method="DNS-over-HTTPS query to cloudflare-dns.com",
                        evidence={"url": DOH.format(name=host, rtype=rtype),
                                  "retrieved_at": resp.retrieved_at,
                                  "from_cache": resp.from_cache},
                        confidence="CORROBORATED" if not resp.from_cache else "LEAD",
                    )
            if not any(records.values()):
                result.findings.append(gap_finding(self.name, self.target,
                                                   "no DNS answers from resolver"))
            result.status = "SUCCESS"
            result.data = {"domain": host, "records": records,
                           "record_types_found": sum(1 for v in records.values() if v)}
        except Exception as e:
            ename = type(e).__name__
            result.status = "CONNECTION_ERROR" if ename in ("ScopeViolation", "URLError") else "ERROR"
            result.errors.append(f"DoH lookup failed ({ename}): {e}")
        return result
