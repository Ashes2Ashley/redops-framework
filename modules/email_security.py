"""Email security posture: SPF, DMARC, DKIM selectors via DNS. Stdlib only."""
import json
import urllib.request
import urllib.error
from core.base_module import BaseModule, ModuleResult

DOH = "https://cloudflare-dns.com/dns-query?name={name}&type=TXT"
DKIM_SELECTORS = ["default", "google", "k1", "s1", "s2", "selector1", "selector2", "everlytick", "mail"]

class EmailSecurityModule(BaseModule):
    @property
    def name(self) -> str:
        return "email_security"

    @property
    def description(self) -> str:
        return "Checks SPF, DMARC and common DKIM selectors for a domain."

    def _txt(self, name):
        try:
            req = urllib.request.Request(DOH.format(name=name),
                headers={"accept": "application/dns-json", "User-Agent": "SecurityFramework/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = json.loads(resp.read().decode("utf-8", "replace"))
            return [a.get("data", "").strip('"') for a in body.get("Answer", [])]
        except Exception:
            return []

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        dom = self.target.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
        if not dom or "." not in dom:
            result.status = "FAILED"; result.errors.append("give a domain"); return result
        spf = [t for t in self._txt(dom) if t.startswith("v=spf1")]
        dmarc = [t for t in self._txt("_dmarc." + dom) if t.startswith("v=DMARC1")]
        dkim = {}
        for sel in DKIM_SELECTORS:
            recs = [t for t in self._txt(sel + "._domainkey." + dom) if "v=DKIM1" in t or "p=" in t]
            if recs:
                null = "p=;" in recs[0].replace(" ", "") or recs[0].rstrip().endswith("p=")
                dkim[sel] = "null record (explicitly not signing)" if null else recs[0][:80]
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
