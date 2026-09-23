# lessons

- ASCII-only CLI output — em-dash/ellipsis render as `?` on cp1252
  Windows consoles (carried over from tokenwatch; same fix applied).
- Audit `activityDisplayName` matching needs plain substring rules —
  result field must gate separately (`and/or` precedence bug caught in
  review, not by tests).
- "Evidence unavailable" must be distinguishable from "no findings" —
  hosting-asn without an asnmap returns [] AND the CLI prints a note;
  silently-off rules are how detectors lie.
