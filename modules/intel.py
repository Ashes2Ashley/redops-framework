"""Wayback snapshots, reverse DNS, IP info, DNSSEC. Stdlib only."""
import json
import urllib.request
import urllib.error
from core.base_module import BaseModule, ModuleResult


class WaybackModule(BaseModule):
    @property
    def name(self) -> str:
        return "wayback"

    @property
    def description(self) -> str:
        return "Lists archived snapshots of a URL from the Wayback Machine."

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        url = self.target if self.target.startswith(("http://", "https://")) else "https://" + self.target
        try:
            q = "https://archive.org/wayback/available?url=" + urllib.request.quote(url, safe="")
            req = urllib.request.Request(q, headers={"User-Agent": "SecurityFramework/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                j = json.loads(resp.read().decode("utf-8", "replace"))
            snap = (j.get("archived_snapshots") or {}).get("closest") or {}
            q2 = "http://web.archive.org/cdx/search/cdx?url=" + urllib.request.quote(url, safe="") + "&output=json&limit=20&collapse=digest"
            count = 0
            try:
                req2 = urllib.request.Request(q2, headers={"User-Agent": "SecurityFramework/1.0"})
                with urllib.request.urlopen(req2, timeout=15) as resp2:
                    rows = json.loads(resp2.read().decode("utf-8", "replace"))
                count = max(0, len(rows) - 1)
            except Exception:
                pass
            result.status = "SUCCESS"
            result.data = {"url": url,
                           "closest_snapshot": snap.get("timestamp", "none") if snap else "none",
                           "snapshot_url": snap.get("url", "") if snap else "",
                           "total_captures_sampled": count}
        except Exception as e:
            result.status = "ERROR"; result.errors.append(str(e))
        return result


class ReverseDNSModule(BaseModule):
    @property
    def name(self) -> str:
        return "reverse_dns"

    @property
    def description(self) -> str:
        return "PTR lookup for an IP address via DNS-over-HTTPS."

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        ip = self.target.strip()
        try:
            parts = ip.split(".")
            if len(parts) == 4:
                arpa = ".".join(reversed(parts)) + ".in-addr.arpa"
            else:
                result.status = "FAILED"; result.errors.append("IPv4 only for now"); return result
            q = "https://cloudflare-dns.com/dns-query?name=" + arpa + "&type=PTR"
            req = urllib.request.Request(q, headers={"accept": "application/dns-json", "User-Agent": "SecurityFramework/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = json.loads(resp.read().decode("utf-8", "replace"))
            ptrs = [a.get("data", "") for a in body.get("Answer", [])]
            result.status = "SUCCESS"
            result.data = {"ip": ip, "ptr": ptrs or ["(no PTR record)"]}
        except Exception as e:
            result.status = "ERROR"; result.errors.append(str(e))
        return result


class IPInfoModule(BaseModule):
    @property
    def name(self) -> str:
        return "ip_info"

    @property
    def description(self) -> str:
        return "IP geolocation + ASN (free ip-api.com, no key)."

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        ip = self.target.strip()
        try:
            q = "http://ip-api.com/json/" + urllib.request.quote(ip, safe="") + "?fields=status,message,country,regionName,city,isp,org,as,proxy,hosting,query"
            req = urllib.request.Request(q, headers={"User-Agent": "SecurityFramework/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                j = json.loads(resp.read().decode("utf-8", "replace"))
            if j.get("status") != "success":
                result.status = "FAILED"; result.errors.append(j.get("message", "lookup failed")); return result
            result.status = "SUCCESS"
            result.data = {k: j.get(k) for k in ("query", "country", "regionName", "city", "isp", "org", "as", "proxy", "hosting")}
        except Exception as e:
            result.status = "ERROR"; result.errors.append(str(e))
        return result


class DNSSECModule(BaseModule):
    @property
    def name(self) -> str:
        return "dnssec"

    @property
    def description(self) -> str:
        return "Checks DNSSEC validation status for a domain."

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        dom = self.target.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
        try:
            out = {}
            for rtype, name in (("DS", "delegation signer"), ("DNSKEY", "zone keys")):
                q = f"https://cloudflare-dns.com/dns-query?name={dom}&type={rtype}"
                req = urllib.request.Request(q, headers={"accept": "application/dns-json", "User-Agent": "SecurityFramework/1.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = json.loads(resp.read().decode("utf-8", "replace"))
                out[rtype] = {"present": bool(body.get("Answer")), "ad_flag": bool(body.get("AD"))}
            ds, dk = out["DS"], out["DNSKEY"]
            verdict = "DNSSEC signed and validating" if ds["present"] and ds["ad_flag"] else \
                      "DS present but not validating" if ds["present"] else "not DNSSEC signed"
            result.status = "SUCCESS"
            result.data = {"domain": dom, **out, "verdict": verdict}
        except Exception as e:
            result.status = "ERROR"; result.errors.append(str(e))
        return result
