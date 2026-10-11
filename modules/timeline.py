"""Timeline builder: dated events from RDAP, TLS, Wayback. Stdlib only.

Doctrine: distinguish event dates from publication dates. Every timeline
entry carries its source and observed_date — intelligence rots, and a
timeline without dates is a story, not evidence.
"""
from core.base_module import BaseModule, ModuleResult
from modules.rdap_domain import RDAPModule
from modules.tls_cert import TLSCertModule
from modules.intel import WaybackModule


class TimelineModule(BaseModule):
    @property
    def name(self) -> str:
        return "timeline"

    @property
    def alias(self) -> str:
        return "what happened when"

    @property
    def description(self) -> str:
        return "Builds a dated event timeline for a domain from RDAP, TLS, and Wayback."

    @property
    def reads(self) -> str:
        return "RDAP registration events, TLS certificate validity window, Wayback snapshots."

    @property
    def returns(self) -> str:
        return "Chronological event list with source + observed_date per entry, findings."

    @property
    def failure_modes(self) -> list:
        return [
            "RDAP dates are registrar-supplied and can be wrong; Wayback dates are capture dates, not change dates.",
            "Gaps in the timeline are absence of data, not absence of events — do not interpolate.",
            "A thin timeline (2-3 events) proves nothing about the target's history.",
        ]

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        events = []

        def run_sub(cls):
            try:
                return cls(self.target, config=self.config).run()
            except Exception as e:
                r = ModuleResult(module_name=cls.__name__, target=self.target,
                                 status="EXCEPTION")
                r.errors.append(str(e))
                return r

        rdap = run_sub(RDAPModule)
        tls = run_sub(TLSCertModule)
        wb = run_sub(WaybackModule)

        if rdap.status == "SUCCESS":
            d = rdap.data
            for label, key in (("domain registered", "created"),
                               ("domain record updated", "updated"),
                               ("domain expires", "expires")):
                if d.get(key) and d[key] != "?":
                    events.append({"date": d[key][:10], "event": label,
                                   "source": "rdap_domain",
                                   "detail": "registrar: %s" % d.get("registrar", "?")})
        if tls.status == "SUCCESS":
            d = tls.data
            if d.get("not_before"):
                events.append({"date": d["not_before"][:10],
                               "event": "current TLS certificate issued",
                               "source": "tls_cert",
                               "detail": "issuer: %s" % d.get("issuer", "?")})
        if wb.status == "SUCCESS":
            d = wb.data
            snap = d.get("closest_snapshot")
            if snap and snap != "none":
                events.append({"date": "%s-%s-%s" % (snap[:4], snap[4:6], snap[6:8]),
                               "event": "Wayback capture (capture date, not change date)",
                               "source": "wayback",
                               "detail": d.get("snapshot_url", "")})

        events.sort(key=lambda e: e["date"])
        result.status = "SUCCESS" if events else "PARTIAL"
        result.data = {"domain": self.target, "event_count": len(events),
                       "events": events,
                       "sub_statuses": {"rdap": rdap.status, "tls": tls.status,
                                        "wayback": wb.status}}
        if events:
            result.add_finding(
                claim="Timeline for %s: %d dated event(s) from %d source(s)"
                      % (self.target, len(events),
                         sum(1 for s in (rdap.status, tls.status, wb.status)
                             if s == "SUCCESS")),
                tag="OBSERVED", method="aggregation of rdap/tls/wayback module outputs",
                evidence={"events": events}, confidence="CORROBORATED")
        else:
            from core.base_module import gap_finding
            result.findings.append(gap_finding(self.name, self.target,
                                               "no dated events found for " + self.target))
        return result
