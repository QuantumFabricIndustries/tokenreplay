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
