"""Full recon correlation: runs the recon suite and grades the target. Stdlib only."""
from core.base_module import BaseModule, ModuleResult
from modules.dns_recon import DNSReconModule
from modules.rdap_domain import RDAPModule
from modules.tls_cert import TLSCertModule
from modules.email_security import EmailSecurityModule
from modules.http_headers import HTTPHeadersModule
from modules.subdomain_enum import SubdomainEnumModule
from modules.intel import DNSSECModule

class ReconReportModule(BaseModule):
    @property
    def name(self) -> str:
        return "recon_report"

    @property
    def description(self) -> str:
        return "Runs the full recon suite and produces one graded ops assessment."

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        t = self.target
        mods = [
            ("dns", DNSReconModule(t)),
            ("rdap", RDAPModule(t)),
            ("tls", TLSCertModule(t)),
            ("email", EmailSecurityModule(t)),
            ("headers", HTTPHeadersModule(t)),
            ("subdomains", SubdomainEnumModule(t)),
            ("dnssec", DNSSECModule(t)),
        ]
        data, findings, score, max_score = {}, [], 0, 0
        for key, mod in mods:
            try:
                r = mod.run()
            except Exception as e:
                r = ModuleResult(module_name=key, target=t, status="EXCEPTION")
                r.errors.append(str(e))
            data[key] = {"status": r.status, "data": r.data, "errors": r.errors}

        def award(points, ok, label):
            nonlocal score, max_score
            max_score += points
            if ok: score += points
            else: findings.append(label)

        d = data["dns"]["data"].get("records", {}) if data["dns"]["status"] == "SUCCESS" else {}
        award(1, bool(d.get("A")), "no A records")
        rd = data["rdap"]["data"] if data["rdap"]["status"] == "SUCCESS" else {}
        award(1, bool(rd.get("registrar") and rd["registrar"] != "?"), "registrar unknown")
        tls = data["tls"]["data"] if data["tls"]["status"] == "SUCCESS" else {}
        award(2, tls.get("days_remaining", -1) > 30, f"TLS expires in {tls.get('days_remaining', '?')} days")
        em = data["email"]["data"] if data["email"]["status"] == "SUCCESS" else {}
        award(2, bool(em.get("spf")) and bool(em.get("dmarc")), "email auth incomplete (SPF/DKIM/DMARC)")
        hh = data["headers"]["data"] if data["headers"]["status"] == "SUCCESS" else {}
        missing = hh.get("security_headers_missing", [])
        award(2, not missing, f"missing security headers: {', '.join(missing)}" if missing else "")
        if not missing: findings[:] = [f for f in findings if not f.startswith("missing security headers")]
        sd = data["subdomains"]["data"] if data["subdomains"]["status"] == "SUCCESS" else {}
        award(1, True, "")
        ds = data["dnssec"]["data"] if data["dnssec"]["status"] == "SUCCESS" else {}
        award(1, ds.get("verdict", "").startswith("DNSSEC signed"), "DNSSEC not enabled")
        findings[:] = [f for f in findings if f]

        pct = round(100 * score / max_score) if max_score else 0
        grade = "A" if pct >= 90 else "B" if pct >= 75 else "C" if pct >= 60 else "D" if pct >= 40 else "F"
        summary = {
            "domain": t,
            "hygiene_score": f"{score}/{max_score} ({pct}%)",
            "grade": grade,
            "findings": findings,
            "subdomains": sd.get("subdomains", [])[:30],
            "subdomain_count": sd.get("subdomains_found", 0),
            "mail": {"spf": bool(em.get("spf")), "dmarc": bool(em.get("dmarc")),
                     "dkim_selectors": list((em.get("dkim_selectors") or {}).keys())},
            "tls_days_left": tls.get("days_remaining"),
            "registered": f"{rd.get('created', '?')} → {rd.get('expires', '?')} ({rd.get('registrar', '?')})",
        }
        ok = all(v["status"] in ("SUCCESS", "FAILED") for v in data.values())
        result.status = "SUCCESS" if ok else "PARTIAL"
        result.data = summary
        result.errors = [f"{k}: {'; '.join(v['errors'])}" for k, v in data.items() if v["errors"]]
        return result
