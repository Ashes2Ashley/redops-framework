"""Email security posture: SPF, DMARC, DKIM selectors via DNS. Stdlib only."""
from core.base_module import BaseModule, ModuleResult, gap_finding

DOH = "https://cloudflare-dns.com/dns-query?name={name}&type=TXT"
DKIM_SELECTORS = ["default", "google", "k1", "s1", "s2", "selector1", "selector2", "everlytick", "mail"]

class EmailSecurityModule(BaseModule):
    @property
    def name(self) -> str:
        return "email_security"

    @property
    def description(self) -> str:
        return "Checks SPF, DMARC and common DKIM selectors for a domain."

    @property
    def alias(self) -> str:
        return "mail defenses"

    @property
    def reads(self) -> str:
        return "Public DNS TXT records (SPF, DMARC, DKIM selectors) via DNS-over-HTTPS."

    @property
    def returns(self) -> str:
        return "SPF/DMARC records, found DKIM selectors, graded assessment notes, findings."

    @property
    def failure_modes(self) -> list:
        return [
            "Records present but unenforced — posture is not practice; a p=none DMARC barely defends.",
            "Only common DKIM selectors are probed — absence here is not proof of no DKIM.",
            "Resolver filtering or stale cache can hide records; observed_date marks when seen.",
        ]

    def _txt(self, name):
        try:
            resp = self._client.get(DOH.format(name=name),
                                    headers={"accept": "application/dns-json"})
            if resp.status != 200:
                return []
            body = resp.json()
            return [a.get("data", "").strip('"') for a in body.get("Answer", [])]
        except Exception:
            return []

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        dom = self.target.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
        if not dom or "." not in dom:
            result.status = "FAILED"; result.errors.append("give a domain"); return result
        self._client, err = self.scoped_client()
        if err:
            result.status = "FAILED"
            result.errors.append("unscoped HTTP client refused: " + err)
            return result
        spf = [t for t in self._txt(dom) if t.startswith("v=spf1")]
        dmarc = [t for t in self._txt("_dmarc." + dom) if t.startswith("v=DMARC1")]
        dkim = {}
        for sel in DKIM_SELECTORS:
            recs = [t for t in self._txt(sel + "._domainkey." + dom) if "v=DKIM1" in t or "p=" in t]
            if recs:
                null = "p=;" in recs[0].replace(" ", "") or recs[0].rstrip().endswith("p=")
                dkim[sel] = "null record (explicitly not signing)" if null else recs[0][:80]
        if spf:
            result.add_finding(
                claim="SPF record observed for %s: %s" % (dom, spf[0][:100]),
                tag="OBSERVED", method="DNS TXT query via DNS-over-HTTPS",
                evidence={"record": spf[0]}, confidence="CORROBORATED")
        else:
            result.findings.append(gap_finding(self.name, self.target, "no SPF record"))
        if dmarc:
            result.add_finding(
                claim="DMARC record observed for %s: %s" % (dom, dmarc[0][:100]),
                tag="OBSERVED", method="DNS TXT query via DNS-over-HTTPS",
                evidence={"record": dmarc[0]}, confidence="CORROBORATED")
        else:
            result.add_finding(
                claim="No DMARC record for %s — mail from this domain is forgeable" % dom,
                tag="INFERRED", method="absence of DMARC TXT after direct query",
                evidence={"queried": "_dmarc." + dom}, confidence="CORROBORATED")
        if dkim:
            result.add_finding(
                claim="%d DKIM selector(s) observed: %s" % (len(dkim), ", ".join(dkim)),
                tag="OBSERVED", method="DNS TXT queries for common selectors",
                evidence={"selectors": list(dkim.keys())}, confidence="LEAD",
                quarantined=True)  # common-selector sweep only — not exhaustive
        def grade():
            score = 0; notes = []
            if spf:
                score += 1
                notes.append("SPF: " + ("hardfail (-all)" if "-all" in spf[0] else "softfail (~all)" if "~all" in spf[0] else "present"))
            else: notes.append("SPF: MISSING — anyone can forge mail from this domain")
            if dmarc:
                score += 1
                p = "none"
                for part in dmarc[0].split(";"):
                    if part.strip().startswith("p="): p = part.strip()[2:]
                notes.append(f"DMARC: policy p={p}" + ("" if p in ("quarantine", "reject") else " (weak — should be quarantine/reject)"))
            else: notes.append("DMARC: MISSING")
            notes.append(f"DKIM: {len(dkim)} selector(s) found" + ("" if dkim else " (none of the common selectors)"))
            return score, notes
        score, notes = grade()
        result.status = "SUCCESS"
        result.data = {"domain": dom, "spf": spf, "dmarc": dmarc, "dkim_selectors": dkim,
                       "score": f"{score}/2 core", "assessment": notes}
        return result
