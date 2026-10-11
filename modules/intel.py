"""Wayback snapshots, reverse DNS, IP info, DNSSEC. Stdlib only.

All outbound HTTP goes through the scoped, audited, cached HttpClient —
fail-closed when no scope is configured.
"""
import urllib.request
from core.base_module import BaseModule, ModuleResult, gap_finding


class WaybackModule(BaseModule):
    @property
    def name(self) -> str:
        return "wayback"

    @property
    def alias(self) -> str:
        return "history and neighbors"

    @property
    def description(self) -> str:
        return "Lists archived snapshots of a URL from the Wayback Machine."

    @property
    def reads(self) -> str:
        return "Wayback availability API + CDX search API (public archives)."

    @property
    def returns(self) -> str:
        return "Closest snapshot timestamp/URL, sampled capture count, findings."

    @property
    def failure_modes(self) -> list:
        return [
            "Archives are incomplete — absence of a snapshot is not proof of absence of the page.",
            "Snapshot timestamps are capture dates, not content-change dates.",
            "robots.txt exclusions create archival blind spots.",
        ]

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        url = self.target if self.target.startswith(("http://", "https://")) else "https://" + self.target
        client, err = self.scoped_client()
        if err:
            result.status = "FAILED"
            result.errors.append("unscoped HTTP client refused: " + err)
            return result
        try:
            q = "https://archive.org/wayback/available?url=" + urllib.request.quote(url, safe="")
            resp = client.get(q)
            j = resp.json() if resp.status == 200 else {}
            snap = (j.get("archived_snapshots") or {}).get("closest") or {}
            q2 = ("http://web.archive.org/cdx/search/cdx?url="
                  + urllib.request.quote(url, safe="")
                  + "&output=json&limit=20&collapse=digest")
            count = 0
            try:
                resp2 = client.get(q2)
                if resp2.status == 200:
                    rows = resp2.json()
                    count = max(0, len(rows) - 1)
            except Exception:
                pass
            result.status = "SUCCESS"
            result.data = {"url": url,
                           "closest_snapshot": snap.get("timestamp", "none") if snap else "none",
                           "snapshot_url": snap.get("url", "") if snap else "",
                           "total_captures_sampled": count,
                           "served_from_cache": resp.from_cache}
            if snap and snap.get("timestamp"):
                result.add_finding(
                    claim="Wayback snapshot of %s exists at %s" % (url, snap["timestamp"]),
                    tag="OBSERVED", method="Wayback availability API",
                    evidence={"snapshot_url": snap.get("url", ""),
                              "retrieved_at": resp.retrieved_at},
                    confidence="CORROBORATED" if not resp.from_cache else "LEAD")
            else:
                result.findings.append(gap_finding(self.name, self.target,
                                                   "no Wayback snapshot for " + url))
        except Exception as e:
            ename = type(e).__name__
            result.status = "CONNECTION_ERROR" if ename in ("ScopeViolation", "URLError") else "ERROR"
            result.errors.append("wayback failed (%s): %s" % (ename, e))
        return result


class ReverseDNSModule(BaseModule):
    @property
    def name(self) -> str:
        return "reverse_dns"

    @property
    def alias(self) -> str:
        return "name records (reverse)"

    @property
    def description(self) -> str:
        return "PTR lookup for an IP address via DNS-over-HTTPS."

    @property
    def reads(self) -> str:
        return "PTR record via Cloudflare DNS-over-HTTPS."

    @property
    def returns(self) -> str:
        return "PTR hostname(s) or explicit no-record gap, findings."

    @property
    def failure_modes(self) -> list:
        return [
            "Most IPs have no PTR — absence is normal, not suspicious.",
            "PTR is operator-set and can say anything; it is not identity.",
            "Resolver poisoning applies here too.",
        ]

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        ip = self.target.strip()
        client, err = self.scoped_client()
        if err:
            result.status = "FAILED"
            result.errors.append("unscoped HTTP client refused: " + err)
            return result
        try:
            parts = ip.split(".")
            if len(parts) == 4:
                arpa = ".".join(reversed(parts)) + ".in-addr.arpa"
            else:
                result.status = "FAILED"; result.errors.append("IPv4 only for now"); return result
            q = "https://cloudflare-dns.com/dns-query?name=" + arpa + "&type=PTR"
            resp = client.get(q, headers={"accept": "application/dns-json"})
            body = resp.json() if resp.status == 200 else {}
            ptrs = [a.get("data", "") for a in body.get("Answer", [])]
            result.status = "SUCCESS"
            result.data = {"ip": ip, "ptr": ptrs or ["(no PTR record)"]}
            if ptrs:
                result.add_finding(
                    claim="PTR for %s resolves to %s" % (ip, ", ".join(ptrs[:3])),
                    tag="OBSERVED", method="DNS PTR query via DNS-over-HTTPS",
                    evidence={"arpa": arpa}, confidence="CORROBORATED")
            else:
                result.findings.append(gap_finding(self.name, self.target,
                                                   "no PTR record for " + ip))
        except Exception as e:
            ename = type(e).__name__
            result.status = "CONNECTION_ERROR" if ename in ("ScopeViolation", "URLError") else "ERROR"
            result.errors.append("reverse DNS failed (%s): %s" % (ename, e))
        return result


class IPInfoModule(BaseModule):
    @property
    def name(self) -> str:
        return "ip_info"

    @property
    def alias(self) -> str:
        return "where it lives"

    @property
    def description(self) -> str:
        return "IP geolocation + ASN (free ip-api.com, no key)."

    @property
    def reads(self) -> str:
        return "ip-api.com free geolocation/ASN endpoint."

    @property
    def returns(self) -> str:
        return "Country, region, city, ISP, org, ASN, proxy/hosting flags, findings."

    @property
    def failure_modes(self) -> list:
        return [
            "Geolocation is approximate (city-level at best) and often wrong for anycast/CDN IPs.",
            "ISP/org fields reflect registration, not the actual operator.",
            "Free-tier rate limits: 45 req/min — the client backs off, but bursts fail.",
            "IP reassignment: today's mapping may not be last month's.",
        ]

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        ip = self.target.strip()
        client, err = self.scoped_client()
        if err:
            result.status = "FAILED"
            result.errors.append("unscoped HTTP client refused: " + err)
            return result
        try:
            q = ("http://ip-api.com/json/" + urllib.request.quote(ip, safe="")
                 + "?fields=status,message,country,regionName,city,isp,org,as,proxy,hosting,query")
            resp = client.get(q)
            j = resp.json() if resp.status == 200 else {}
            if j.get("status") != "success":
                result.status = "FAILED"; result.errors.append(j.get("message", "lookup failed")); return result
            result.status = "SUCCESS"
            result.data = {k: j.get(k) for k in ("query", "country", "regionName", "city",
                                                 "isp", "org", "as", "proxy", "hosting")}
            result.add_finding(
                claim="IP %s geolocates to %s/%s (ASN %s)" % (
                    ip, j.get("country"), j.get("city"), j.get("as")),
                tag="OBSERVED", method="ip-api.com geolocation lookup",
                evidence={"as": j.get("as"), "isp": j.get("isp"),
                          "retrieved_at": resp.retrieved_at},
                confidence="LEAD", quarantined=True)  # single commercial source
        except Exception as e:
            ename = type(e).__name__
            result.status = "CONNECTION_ERROR" if ename in ("ScopeViolation", "URLError") else "ERROR"
            result.errors.append("ip info failed (%s): %s" % (ename, e))
        return result


class DNSSECModule(BaseModule):
    @property
    def name(self) -> str:
        return "dnssec"

    @property
    def alias(self) -> str:
        return "DNS signing check"

    @property
    def description(self) -> str:
        return "Checks DNSSEC validation status for a domain."

    @property
    def reads(self) -> str:
        return "DS and DNSKEY records plus the AD flag via DNS-over-HTTPS."

    @property
    def returns(self) -> str:
        return "Per-type presence, AD flag, signed/unsigned verdict, findings."

    @property
    def failure_modes(self) -> list:
        return [
            "The AD flag reflects the *resolver's* validation, not universal truth.",
            "A validating resolver between you and the authority can mask a broken chain.",
        ]

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        dom = self.target.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
        client, err = self.scoped_client()
        if err:
            result.status = "FAILED"
            result.errors.append("unscoped HTTP client refused: " + err)
            return result
        try:
            out = {}
            for rtype in ("DS", "DNSKEY"):
                q = "https://cloudflare-dns.com/dns-query?name=%s&type=%s" % (dom, rtype)
                resp = client.get(q, headers={"accept": "application/dns-json"})
                body = resp.json() if resp.status == 200 else {}
                out[rtype] = {"present": bool(body.get("Answer")), "ad_flag": bool(body.get("AD"))}
            ds, dk = out["DS"], out["DNSKEY"]
            verdict = "DNSSEC signed and validating" if ds["present"] and ds["ad_flag"] else \
                      "DS present but not validating" if ds["present"] else "not DNSSEC signed"
            result.status = "SUCCESS"
            result.data = {"domain": dom, **out, "verdict": verdict}
            result.add_finding(
                claim="DNSSEC status for %s: %s" % (dom, verdict),
                tag="OBSERVED", method="DS/DNSKEY queries with AD flag via DNS-over-HTTPS",
                evidence=out, confidence="CORROBORATED")
        except Exception as e:
            ename = type(e).__name__
            result.status = "CONNECTION_ERROR" if ename in ("ScopeViolation", "URLError") else "ERROR"
            result.errors.append("DNSSEC check failed (%s): %s" % (ename, e))
        return result
