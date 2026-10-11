# Framework TODO

## DONE in damien/max-hardening (2026-10-11)
- [x] `Finding` dataclass: claim, tag (OBSERVED/INFERRED/ASSUMED), method,
      evidence, observed_date, confidence, quarantined, burned
- [x] Findings table in SQLite with full provenance per finding; export_json
      includes findings
- [x] Findings emitted alongside the existing `data` dict, not replacing it
- [x] Module contract: alias, reads, returns, mandatory failure_modes,
      requires_auth; `python3 main.py contracts` enforces completeness
- [x] Migrated to scoped http_client(): dns_recon, email_security, rdap_domain,
      intel (wayback/reverse_dns/ip_info/dnssec); explicit scope checks in
      http_headers, http_extra, tls_cert, port_probe
- [x] recon_report: config (scope/audit/cache) flows to sub-modules (was a
      scope bypass); findings are evidence-chained; A-F rubric stated in output
- [x] New passive modules: favicon_hash, dork_builder (zero network), timeline
- [x] port_probe + cf_purge marked requires_auth; port_probe needs
      --set auth_confirmed=yes
- [x] Single-source quarantine, burn-notice API, gap discipline (UNKNOWN)

## Commit 2 — Finding type (the turning point)
- [x] `Finding` dataclass (see DONE above — hardened beyond the original sketch:
      claim tags, quarantine, burn, time decay via observed_date)
- [x] Findings table in SQLite with full provenance per finding
- [x] Modules emit findings alongside the existing `data` dict
- [ ] Backfill: recon_report sub-module findings already flow up; consider a
      `findings` rollup view in export (per-target timeline of claims)
      first_seen, last_seen, raw_ref, evidence_url
- [x] Findings table in SQLite with full provenance (exact URL + retrieval
      timestamp + response hash) per finding — implemented as evidence_json +
      method + observed_date
- [x] Migrated one module as the worked example — findings alongside the
      existing `data` dict, not replacing it, so nothing breaks mid-flight
      (done for ALL modules, not just one)

## Commit 3 — Correlation graph
- [ ] Entity resolution with scored, typed edges
      (e.g. SAME_CERT_SAN conf=0.9, SHARED_FAVICON_HASH conf=0.8) —
      links with strengths, never identity claims
- [ ] Infrastructure clustering: join favicon hashes, cert SANs, nameservers,
      analytics IDs (already computed, never joined)
- [ ] Temporal correlation: cert notBefore, wayback timestamps, GitHub
      updated_at cross-referenced
- [ ] Newly-observed alerting: diff findings against last run
- [ ] Pivot recommendations: suggest the next query from the graph

## Remaining migrations
- [x] Moved modules from raw urllib to `http_client()` / explicit scope checks:
      dns_recon, email_security, rdap_domain, intel x4, http_headers,
      http_extra x3, tls_cert, port_probe (subdomain_enum was already migrated)

## Forensics rigor
- [ ] Benjamini-Hochberg FDR correction across batched statistical tests
- [ ] Effect sizes (Cramér's V), not just p-values
- [ ] Structured input schemas with validation — reject bad rows loudly
      instead of silently skipping them
- [ ] Deterministic, seedable outputs for statistical tools

## Delivery
- [x] Report templates consuming the findings store: recon_report emits
      evidence-chained findings; every graded claim footnoted to a module
- [x] JSONL export with a stable schema — export_json includes findings per run
      (JSONL variant still open)
- [ ] Single run command: target → concurrent tools → dedupe → graph → report

## Hygiene
- [ ] Tests with recorded fixtures (no live-service hammering in CI)
- [ ] `--json` flag on every module (human-readable as secondary mode)
- [ ] Logging instead of stderr prints
