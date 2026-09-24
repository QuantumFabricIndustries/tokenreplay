# lessons

- ASCII-only CLI output — em-dash/ellipsis render as `?` on cp1252
  Windows consoles (carried over from tokenwatch; same fix applied).
- Audit `activityDisplayName` matching needs plain substring rules —
  result field must gate separately (`and/or` precedence bug caught in
  review, not by tests).
- "Evidence unavailable" must be distinguishable from "no findings" —
  hosting-asn without an asnmap returns [] AND the CLI prints a note;
  silently-off rules are how detectors lie.

## tokenreplay: defense systems learn from their inputs — gate it
Baselines built from sign-ins will absorb attacker traffic if it
survives to learning time. Any "learn from observed data" feature needs
a poison gate: evaluate-then-learn, exclude what scored, and provide an
explicit human override (confirm) rather than an auto-expiry. Also:
shared-infrastructure thresholds should scale with population — a flat
"3 users = egress" is trivially satisfiable by an attacker at SMB size.
