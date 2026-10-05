"""DNS reconnaissance via Cloudflare DoH (JSON API). Stdlib only."""
import json
import urllib.request
import urllib.error
from core.base_module import BaseModule, ModuleResult

DOH = "https://cloudflare-dns.com/dns-query?name={name}&type={rtype}"
TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"]

class DNSReconModule(BaseModule):
    @property
    def name(self) -> str:
        return "dns_recon"

    @property
    def description(self) -> str:
        return "Enumerates DNS records (A/AAAA/MX/TXT/NS/CNAME/SOA/CAA) via DNS-over-HTTPS."

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        host = self.target.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
        if not host or "." not in host:
            result.status = "FAILED"
            result.errors.append("give a domain, e.g. example.com")
            return result
        records = {}
        try:
            for rtype in TYPES:
                req = urllib.request.Request(
                    DOH.format(name=host, rtype=rtype),
                    headers={"accept": "application/dns-json", "User-Agent": "SecurityFramework/1.0"},
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = json.loads(resp.read().decode("utf-8", "replace"))
                answers = [a.get("data", "") for a in body.get("Answer", [])]
                records[rtype] = answers
            result.status = "SUCCESS"
            result.data = {"domain": host, "records": records,
                           "record_types_found": sum(1 for v in records.values() if v)}
        except urllib.error.URLError as e:
            result.status = "CONNECTION_ERROR"
            result.errors.append(f"DoH lookup failed: {e.reason}")
        except Exception as e:
            result.status = "ERROR"
            result.errors.append(f"Unexpected error: {e}")
        return result
