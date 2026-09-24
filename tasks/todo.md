# tokenreplay — task log

## v0.1 — analysis engine (built 2026-09-23)
- [x] signins.py: Graph signIn + directoryAudit parsing ({"value":[]}
      envelope or bare array), typed records, haversine
- [x] baselines.py: per-user country/IP/client-app/device-code history,
      build/save/load
- [x] evidence.py: session-replay (same sessionId, 2+ countries),
      impossible-travel, hosting-asn (asnmap-driven, unavailable without
      map — not silent), device-code-flow (no history or new country),
      rare-country, mfa-method-add, persistence-correlated (72h window)
- [x] score.py: weights + caps + forced COMPROMISED (replay/correlated)
- [x] collect.py: client-creds Graph poll — FUNCTIONAL, UNVERIFIED on a
      live tenant (needs app reg + AuditLog.Read.All)
- [x] cli: analyze / baselines build / report / poll
- [x] 20 tests green, all synthetic fixtures

## Next
- [ ] Verify poll against a real tenant (app reg + consent)
- [ ] asnmap downloader (AWS/GCP/Azure published prefix JSONs)
- [ ] Sentinel/Defender export shapes if they differ from Graph
- [ ] Non-interactive sign-in analytics (service-principal replay)
- [ ] git remote + push (repo exists locally; needs gh repo create)

## Review
Picked `analyze`-first per design fork: engine provable offline, Graph
collection deferred as phase 2. Verdict semantics mirror tokenwatch
(observed-attack classes force COMPROMISED). Correlation rule is the
differentiator: device-code-flow alone = HIGH RISK, device-code +
security-info add within 72h = COMPROMISED.

## Round 2 — user-directed fixes (2026-09-23)
- [x] session-replay keyed on NETWORK change (ASN), not country — the
      common case is same-country replay (US victim -> US VPS) which a
      country-keyed rule misses entirely. Country is a booster. ALSO:
      caught and fixed a bug where a single sign-in from a hosting ASN
      fired "replay" — replay requires >=2 networks.
- [x] autonomousSystemNumber parsed from records; bundled HOSTING_ASNS
      number list (~25 ASNs, stable). --asnmap stays as CIDR-label
      override; unavailable reported when neither source exists.
- [x] coverage_warnings(): interactive-only exports WARN loudly —
      Entra portal exports interactive/non-interactive separately and
      replayed tokens mostly land on the non-interactive side. Missing
      ASN data warns too (degraded to IP+country).
- [x] device-code tenant layer: tenant has NO device-code history ->
      device-code-tenant (65); tenant uses it -> per-user baseline.
- [x] report RECOMMENDATIONS: CA policy to block device-code flow;
      token protection/session binding after session-replay.
- [x] 25 tests green.

## Noted, not built
- [ ] inbox rules / mailbox forwarding post-flag (BEC follow-up) —
      needs Exchange unified audit log, separate API from Graph sign-ins
- [ ] live poll proof needs an Entra P1 tenant (Business Premium trial)

## Review addendum
session_replay logic bug found by the live fixture run, not unit tests:
`or hosting` made single-record sessions "replayed". Fixed: replay
requires >=2 distinct networks; single hosting sign-in belongs to
hosting_asn.

## Round 3 — real-tenant FP gates (2026-09-23)
- [x] session-replay FP gate: the new sighting must be hosting OR
      never-seen-for-user (baseline.asns). Carrier roaming between
      known ASNs -> session-network-drift (10, info). No baseline ->
      only hosting forces replay; conservative.
- [x] tenant-egress gate: ASN in >=3 users' baselines = shared egress
      (SASE/WARP/VDI), suppresses hosting-asn tenant-wide.
      --allow-asn manual override on analyze + poll.
- [x] baselines learned asns per user (needed by both gates).
- [x] 29 tests green; fixture verdicts unchanged.

## Review addendum
Both gates reuse the baselines file — no new state. The mobile-roam
case is why the ASN-keyed replay needed the second clause: "network
changed" alone would flag every phone user hourly.

## Round 4 — baseline anti-poisoning (2026-09-23)
- [x] Finding.rows: every sign-in rule records the implicated records.
- [x] implicated_rows(findings, min_weight=20) -> id() set; SUSPICIOUS+
      traffic is excluded from learning (drift=10 still learns —
      mobile roaming legitimately produces new ASNs).
- [x] baselines.build evaluates first, skips implicated rows;
      --include-flagged escape hatch for known-clean windows.
- [x] baselines.update + poll wiring: poll now learns each cycle under
      the same exclusion (evaluate BEFORE update, so a replay row in
      this window can't teach itself known).
- [x] baselines confirm --user U --asn N: explicit safe-mark, lands in
      asns + confirmed_asns audit trail.
- [x] egress scaled threshold: hosting ASNs need max(3, 20% of tenant
      users); flat 3 for ordinary ASNs. Small tenants (<15) still floor
      at 3 -> --allow-asn is the reliable declaration there.
- [x] 35 tests green.

## Review addendum
The poisoning path was: attacker VPS sign-ins -> learned into baselines
-> 3 victims sharing it -> promoted to "egress" -> suppressed for the
whole tenant, covering the NEXT victims. Both fixes break the chain at
different points: exclusion stops the ASN entering baselines at all;
the scaled threshold means even leaked hosting ASNs need ~20% coverage.
