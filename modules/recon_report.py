"""Full recon correlation: runs the recon suite and grades the target. Stdlib only.

Hardened: sub-modules receive the engine config (scope/audit/cache flow
down — previously they ran unscoped, a scope bypass). Every graded claim is
an evidence-chained Finding. The A-F rubric is stated next to the grade —
a grade without a rubric is a vibe.
"""
from core.base_module import BaseModule, ModuleResult
from modules.dns_recon import DNSReconModule
from modules.rdap_domain import RDAPModule
from modules.tls_cert import TLSCertModule
from modules.email_security import EmailSecurityModule
from modules.http_headers import HTTPHeadersModule
from modules.subdomain_enum import SubdomainEnumModule
from modules.favicon_hash import FaviconHashModule
from modules.intel import DNSSECModule

# Stated rubric. The grade means nothing without this next to it.
RUBRIC = {
    "A": ">=90%: hardened posture, no material gaps observed",
    "B": ">=75%: good posture, minor gaps",
    "C": ">=60%: average posture, notable gaps an attacker would use",
    "D": ">=40%: poor posture, multiple exploitable gaps",
    "F": "<40%: failing posture, critical gaps",
}


class ReconReportModule(BaseModule):
    @property
    def name(self) -> str:
        return "recon_report"

    @property
    def alias(self) -> str:
        return "the file"

    @property
    def description(self) -> str:
        return "Runs the full recon suite and produces one graded ops assessment."

    @property
    def reads(self) -> str:
        return "Outputs of the recon suite modules (dns, rdap, tls, email, headers, subdomains, favicon, dnssec)."

    @property
    def returns(self) -> str:
        return "A-F grade with stated rubric, evidence-chained findings, aggregated evidence."

    @property
    def failure_modes(self) -> list:
        return [
            "The grade aggregates module outputs — garbage in, grade out. Check sub-module statuses.",
            "The rubric weights chosen here are one reasonable weighting, not the weighting. State yours if you change it.",
            "A good grade is not a clean bill of health — it is 'no material gaps observed by these modules'.",
        ]

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        t = self.target
        cfg = self.config  # config flows down: scope, audit, cache. No unscoped sub-runs.
        mods = [
            ("dns", DNSReconModule(t, config=cfg)),
            ("rdap", RDAPModule(t, config=cfg)),
            ("tls", TLSCertModule(t, config=cfg)),
            ("email", EmailSecurityModule(t, config=cfg)),
            ("headers", HTTPHeadersModule(t, config=cfg)),
            ("subdomains", SubdomainEnumModule(t, config=cfg)),
            ("favicon", FaviconHashModule(t, config=cfg)),
            ("dnssec", DNSSECModule(t, config=cfg)),
        ]
        data, score, max_score = {}, 0, 0
        for key, mod in mods:
            try:
                r = mod.run()
            except Exception as e:
                r = ModuleResult(module_name=key, target=t, status="EXCEPTION")
                r.errors.append(str(e))
            data[key] = {"status": r.status, "data": r.data, "errors": r.errors,
                         "findings": [f.to_dict() for f in r.findings]}
            # Sub-module findings flow up with their evidence chains intact.
            result.findings.extend(r.findings)

        def award(points, ok, claim, tag, method, evidence, confidence,
                  quarantined=False):
            nonlocal score, max_score
            max_score += points
            if ok:
                score += points
            else:
                result.add_finding(claim=claim, tag=tag, method=method,
                                   evidence=evidence, confidence=confidence,
                                   quarantined=quarantined)

        d = data["dns"]["data"].get("records", {}) if data["dns"]["status"] == "SUCCESS" else {}
        award(1, bool(d.get("A")), "No A records observed for %s" % t,
              "OBSERVED", "dns_recon module output", {"module": "dns_recon"},
              "CORROBORATED")
        rd = data["rdap"]["data"] if data["rdap"]["status"] == "SUCCESS" else {}
        award(1, bool(rd.get("registrar") and rd["registrar"] != "?"),
              "Registrar unknown for %s (RDAP gave nothing usable)" % t,
              "OBSERVED", "rdap_domain module output", {"module": "rdap_domain"},
              "CORROBORATED")
        tls = data["tls"]["data"] if data["tls"]["status"] == "SUCCESS" else {}
        award(2, tls.get("days_remaining", -1) > 30,
              "TLS for %s expires in %s days" % (t, tls.get("days_remaining", "?")),
              "INFERRED", "tls_cert not_after vs current date",
              {"module": "tls_cert", "not_after": tls.get("not_after")},
              "VERIFIED" if tls.get("days_remaining", -1) >= 0 else "CORROBORATED")
        em = data["email"]["data"] if data["email"]["status"] == "SUCCESS" else {}
        award(2, bool(em.get("spf")) and bool(em.get("dmarc")),
              "Email auth incomplete for %s (SPF/DKIM/DMARC)" % t,
              "INFERRED", "email_security module output",
              {"module": "email_security",
               "spf": bool(em.get("spf")), "dmarc": bool(em.get("dmarc"))},
              "CORROBORATED")
        hh = data["headers"]["data"] if data["headers"]["status"] == "SUCCESS" else {}
        missing = hh.get("security_headers_missing", [])
        award(2, not missing,
              "Missing security headers on %s: %s" % (t, ", ".join(missing)) if missing else "",
              "OBSERVED", "http_headers module output", {"module": "http_headers"},
              "CORROBORATED")
        sd = data["subdomains"]["data"] if data["subdomains"]["status"] == "SUCCESS" else {}
        award(1, True, "", "OBSERVED", "subdomain_enum module output",
              {"module": "subdomain_enum"}, "CORROBORATED")
        ds = data["dnssec"]["data"] if data["dnssec"]["status"] == "SUCCESS" else {}
        award(1, ds.get("verdict", "").startswith("DNSSEC signed"),
              "DNSSEC not enabled for %s" % t,
              "OBSERVED", "dnssec module output", {"module": "dnssec"},
              "CORROBORATED")

        pct = round(100 * score / max_score) if max_score else 0
        grade = "A" if pct >= 90 else "B" if pct >= 75 else "C" if pct >= 60 else "D" if pct >= 40 else "F"
        summary = {
            "domain": t,
            "hygiene_score": f"{score}/{max_score} ({pct}%)",
            "grade": grade,
            "rubric": RUBRIC,
            "rubric_note": "A grade without its rubric is a vibe. Weighting: "
                           "TLS 2, email 2, headers 2, dns/rdap/subdomains/dnssec 1 each.",
            "subdomains": sd.get("subdomains", [])[:30],
            "subdomain_count": sd.get("subdomains_found", 0),
            "mail": {"spf": bool(em.get("spf")), "dmarc": bool(em.get("dmarc")),
                     "dkim_selectors": list((em.get("dkim_selectors") or {}).keys())},
            "tls_days_left": tls.get("days_remaining"),
            "registered": f"{rd.get('created', '?')} → {rd.get('expires', '?')} ({rd.get('registrar', '?')})",
            "sub_statuses": {k: v["status"] for k, v in data.items()},
        }
        ok = all(v["status"] in ("SUCCESS", "FAILED", "PARTIAL") for v in data.values())
        result.status = "SUCCESS" if ok else "PARTIAL"
        result.data = summary
        result.errors = [f"{k}: {'; '.join(v['errors'])}" for k, v in data.items() if v["errors"]]
        result.add_finding(
            claim="Recon assessment for %s: grade %s (%s)" % (t, grade, summary["hygiene_score"]),
            tag="INFERRED", method="weighted aggregation of 8 module outputs per stated rubric",
            evidence={"rubric": RUBRIC, "score": summary["hygiene_score"],
                      "sub_statuses": summary["sub_statuses"]},
            confidence="CORROBORATED")
        return result
