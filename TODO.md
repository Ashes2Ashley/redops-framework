# Framework TODO

## Commit 2 — Finding type (the turning point)
- [ ] `Finding` dataclass: entity_type, value, source_tool, confidence,
      first_seen, last_seen, raw_ref, evidence_url
- [ ] Findings table in SQLite with full provenance (exact URL + retrieval
      timestamp + response hash) per finding
- [ ] Migrate one module as the worked example — findings alongside the
      existing `data` dict, not replacing it, so nothing breaks mid-flight

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
- [ ] Move the remaining 18 modules from raw urllib to `http_client()`
      (subdomain_enum already migrated as the worked example)

## Forensics rigor
- [ ] Benjamini-Hochberg FDR correction across batched statistical tests
- [ ] Effect sizes (Cramér's V), not just p-values
- [ ] Structured input schemas with validation — reject bad rows loudly
      instead of silently skipping them
- [ ] Deterministic, seedable outputs for statistical tools

## Delivery
- [ ] Report templates consuming the findings store, every claim footnoted
      to a provenance record
- [ ] JSONL export with a stable schema
- [ ] Single run command: target → concurrent tools → dedupe → graph → report

## Hygiene
- [ ] Tests with recorded fixtures (no live-service hammering in CI)
- [ ] `--json` flag on every module (human-readable as secondary mode)
- [ ] Logging instead of stderr prints
