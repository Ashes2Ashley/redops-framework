# Modular Security Framework

Stdlib-only plugin framework for operational security modules. Drop a Python file
in `modules/` inheriting `BaseModule` and the CLI picks it up automatically.

Hardened build (`damien/max-hardening`): every module carries a contract
(plain-English alias, reads, returns, **failure modes** — no module ships
without them), and every key observation is an evidence-chained **Finding**
(claim → tag → method → evidence → observed_date → confidence) persisted to
SQLite alongside the raw result. Claim tags: `OBSERVED` (directly seen) /
`INFERRED` (reasoned, reasoning shown) / `ASSUMED` (never briefed as fact).
Confidence: `VERIFIED` / `CORROBORATED` / `DEBUNKED` / `STALE` /
`UNVERIFIABLE` / `CONTESTED` / `LEAD`. Gaps produce exactly one output:
`UNKNOWN — not observed.`

## Layout

```
framework/
├── core/
│   ├── base_module.py   # BaseModule contract + ModuleResult dataclass
│   ├── engine.py        # dynamic module discovery + execution
│   └── storage.py       # SQLite persistence + JSON export
├── modules/
│   ├── http_headers.py  # HTTP security header audit
│   ├── http_extra.py    # methods audit, cookie flags, tech fingerprint
│   ├── dns_recon.py     # DNS records via DNS-over-HTTPS
│   ├── tls_cert.py      # live TLS certificate inspection (proxy-aware)
│   ├── rdap_domain.py   # RDAP registration data
│   ├── email_security.py# SPF / DMARC / DKIM assessment
│   ├── subdomain_enum.py# subdomains via certificate transparency
│   ├── favicon_hash.py  # favicon md5/sha256 for origin correlation
│   ├── dork_builder.py  # reviewable search-query builder (zero network)
│   ├── timeline.py      # dated event timeline (RDAP + TLS + Wayback)
│   ├── port_probe.py    # TCP connect probe — REQUIRES per-action authorization
│   ├── intel.py         # wayback, reverse DNS, IP info, DNSSEC
│   ├── cloudflare.py    # cf_zones, cf_dns, cf_purge, cf_workers (needs CF_TOKEN)
│   └── recon_report.py  # runs the suite, graded A–F ops assessment
└── main.py              # CLI orchestrator
```

## Usage

```bash
python3 main.py list
python3 main.py contracts          # audit every module contract — fails if incomplete
python3 main.py run -m recon_report -t runehall.com   # full graded assessment
python3 main.py run -m port_probe -t runehall.com --set auth_confirmed=yes  # auth-gated
python3 main.py run -m cf_zones -t account --set cf_token=...   # or export CF_TOKEN
python3 main.py export -o output.json   # results + findings with evidence chains
```

Results are stored in `results.db` (SQLite) and exportable to JSON.

## Notes

- `http_headers` intentionally skips cert verification so it can audit misconfigured hosts.
- `tls_cert` uses `CERT_OPTIONAL` (never fails the handshake on a bad cert, still
  parses the peer cert) and tunnels through `https_proxy`/`http_proxy` via CONNECT
  when one is configured.
- All modules are stdlib-only: no pip install needed.

## Adding a module

```python
from core.base_module import BaseModule, ModuleResult

class CustomModule(BaseModule):
    @property
    def name(self) -> str: return "custom_scanner"
    @property
    def description(self) -> str: return "What it does."
    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        result.status = "SUCCESS"
        result.data = {"key": "value"}
        return result
```

Save as `modules/custom.py` — no registry edits needed.
