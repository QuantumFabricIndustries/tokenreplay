# tokenreplay

Detection engine for **AiTM session-token theft and token replay** — the
half of the token-theft problem that never touches the endpoint.
Reverse-proxy phishing kits (EvilProxy/Evilginx class) and OAuth
device-code phishing (EvilTokens class) mint/capture session tokens at
the IdP; the replay shows up in **sign-in telemetry**, not on disk.

Sibling tools in the QuantumFabricIndustries stack: **tokenwatch**
(guards the stores at rest on the endpoint), gitguard, phantom-snare,
iron-gates-xdr. tokenreplay guards what tokenwatch structurally cannot:
tokens captured server-side.

Pure Python 3.9+ stdlib, zero dependencies. The analysis engine runs on
exported Graph JSON — no API access needed to develop, test, or triage.

## What it reads

- `analyze --file signins.json` — Entra `/auditLogs/signIns` export
  (`{"value": [...]}` envelope or bare array)
- `--audits audits.json` — `/auditLogs/directoryAudits` export
  (security-info registrations, the persistence half)
- `--baselines baselines.json` — per-user history built from an earlier
  export (`baselines build`), powering "first-seen" evidence
- `--asnmap asnmap.json` — `{"prefixes": {"<cidr>": "<label>"}}` map
  powering hosting-ASN evidence
- `poll` — pulls the same data from Graph directly (phase 2; needs an
  app registration, see below)

## Evidence rules

| rule | weight | what it catches |
|---|---|---|
| `session-replay` | 80, forces COMPROMISED | same `sessionId` from 2+ **networks** — keyed on `autonomousSystemNumber` change, not country, because the common case is same-country replay (US victim, US VPS). FP gate: the new sighting must be hosting *or* never-seen-for-the-user — ASN hops between baseline-known networks (phone roaming wifi↔cellular) downgrade to `session-network-drift`. Country change is a booster; falls back to IP+country when ASN data is absent |
| `session-network-drift` | 10, info | session moved networks but all of them are known-for-user or unverifiable — mobile-roaming shape, not replay |
| `persistence-correlated` | 90, forces COMPROMISED | security-info/MFA-method registration within 72h of any other flag for that user — the capture-then-persist chain (ShinyHunters/Helix play) |
| `device-code-tenant` | 65 | device-code auth when the TENANT has no device-code history — the flow isn't legitimate here at all |
| `hosting-asn` | 55 | interactive auth from a hosting ASN — matched on the record's own `autonomousSystemNumber` vs a bundled list (DO/Hetzner/OVH/AWS/GCP/Azure/…), `--asnmap` CIDR labels as override. Tenant-egress gate: an ASN shared by enough users' baselines is shared egress (Zscaler/WARP/VDI/Private Relay) and suppressed — flat 3 users for ordinary ASNs, `max(3, 20% of tenant)` for hosting-listed ones (an attacker VPS only covers a handful of victims; real SASE covers most of the tenant). `--allow-asn` suppresses manually |
| `device-code-flow` | 55 | device-code auth with no user history, or from an unseen country |
| `impossible-travel` | 45 | consecutive sign-ins faster than physics |
| `mfa-method-add` | 35 | security-info registration, uncorrelated |
| `rare-country` | 20 | first-seen country vs baseline — weak alone |

The report ends with **RECOMMENDATIONS** — the actual fix per attack
class (e.g. Conditional Access blocking device-code flow for users who
don't need it; token protection / session binding after a replay).

Verdicts per user: `CLEAN` <20 · `SUSPICIOUS` 20-49 · `HIGH RISK` 50-79 ·
`COMPROMISED` 80+ (or forced). Per-rule caps prevent stacking; the
report prints `raw -> effective` when a cap binds. `analyze` exits 1
when the overall verdict is HIGH RISK or COMPROMISED — usable as a CI
gate over exported logs.

## Commands

```text
python -m tokenreplay analyze --file signins.json [--audits a.json]
    [--baselines b.json] [--asnmap m.json] [--allow-asn 13335,16509]
    [--json] [-o out]
python -m tokenreplay baselines build --file history.json [-o b.json]
    [--asnmap m.json] [--allow-asn ...] [--include-flagged]
python -m tokenreplay baselines confirm --baselines b.json
    --user alice@corp.com --asn 14061
python -m tokenreplay report [--json]
python -m tokenreplay poll [--hours N]          # phase 2
```

## poll (phase 2 — functional, unverified on a live tenant)

`collect.py` implements the client-credentials daemon flow against
Microsoft Graph (`/auditLogs/signIns`, `/auditLogs/directoryAudits`,
watermarked, paged). Config at `~/.tokenreplay/graph.json` holds
`tenant` + `client_id` plus ONE credential, resolved strongest-first:

| source | how | on disk |
|---|---|---|
| **certificate** (recommended) | `tokenreplay cert new` - RSA-2048, private key **non-exportable** in `Cert:\CurrentUser\My`; signs a JWT client assertion in place | thumbprint only |
| env var | `TOKENREPLAY_CLIENT_SECRET` | nothing |
| DPAPI | `tokenreplay secret protect` - user-scope DPAPI blob (+ app entropy) | `client_secret_dpapi` |

```json
{"tenant": "<tenant-id>", "client_id": "<app-id>",
 "cert_thumbprint": "<40 hex>", "cert_store": "CurrentUser"}
```

A plaintext `client_secret` is **refused** — that secret reads every
sign-in in the tenant, and for an MSP a directory of those files is
exactly the infostealer target tokenwatch catches. `secret protect`
migrates an existing one in place (then rotate it in Entra — the old
plaintext may survive in backups). `cert new` writes the public `.cer`
to upload under *Certificates & secrets* and strips any secret from
`graph.json`. tokenwatch watches `~/.tokenreplay/graph.json` as the
`tokenreplay-graph` store and flags Entra client secrets (`Q~` format)
anywhere as `plaintext-token`.

Boundary: DPAPI and a non-exportable key stop file-grab stealers, not
code running *as the user* — that can still call CryptUnprotectData or
ask the key to sign. The cert keeps the key off-disk-in-the-clear and
un-copyable to another machine, which is the realistic bar.

Cert lifecycle: `poll` reads `NotAfter` on the configured thumbprint
every cycle — under 30 days left is a WARN in the report; **an expired
cert raises and refuses to report a quiet tenant** (an empty poll on a
broken credential is not a clean poll). Rotate with `cert new`.

The app registration needs `AuditLog.Read.All` **application**
permission + admin consent. Honest status: written against the Graph
contract, not exercised against a real tenant yet — treat `poll` as
alpha; `analyze` on exported JSON is the proven path. A live proof
needs Entra ID P1 (sign-in log retention + detail fields); a Business
Premium trial tenant is the simplest way to get one.

## Honest coverage boundaries

- **Detection latency = collection interval.** This is polling, not
  real-time streaming — a replay that lives and dies between polls is
  invisible.
- **The Entra portal exports interactive and non-interactive sign-ins
  separately**, and replayed tokens mostly surface on the
  non-interactive side. `analyze` inspects `signInEventTypes`/
  `isInteractive` and prints a WARN when the input has no
  non-interactive records — a clean interactive-only scan is not clean.
- **`sessionId` presence varies.** Free-tier/basic sign-in records often
  lack it; `session-replay` can't fire without it (the other rules still
  work, and the missing-ASN case degrades to IP+country with a warning).
- **No ASN *database* is bundled** — the record's own
  `autonomousSystemNumber` is matched against a small bundled list of
  hosting ASNs; `--asnmap` (CIDR->label) is the override for networks we
  don't carry. With neither source the rule reports unavailable.
- **Next rule, noted not built**: inbox rules / mailbox forwarding
  created after a flag — the classic BEC follow-up, natural pair for
  `correlate()`'s 72h window. Needs the Exchange side of the unified
  audit log (separate API surface from Graph sign-ins).
- **Residential-proxy AiTM evades `hosting-asn`.** Kits relaying through
  residential IPs don't trip ASN evidence — `session-replay` /
  `impossible-travel` are the fallback signals. Relatedly, the replay
  FP gate is conservative **without baselines**: an ASN change between
  two non-hosting networks downgrades to `session-network-drift` when
  there's no per-user history to prove the new network is new — a
  residential-proxy replay can land there. Build baselines from
  `baselines build` over history to restore the strict path.
- **Non-Microsoft IdPs are invisible.** Okta/Google/AWS sign-in
  telemetry is a different API surface entirely.
- **Baselines are only as old as the history export.** A brand-new
  account or thin history makes "first-seen" evidence noisy — cap rules
  exist for that reason.
- **Baselines refuse to learn flagged traffic.** `build` and `poll`
  evaluate sign-ins *before* learning them: any record implicated in a
  SUSPICIOUS+ finding stays out of `asns`/`countries`/etc. — otherwise
  an attacker's VPS in 30 days of history would launder itself into
  "known" per-user networks and eventually "shared egress". Flagged
  networks only enter via `baselines confirm` (recorded in
  `confirmed_asns` as an audit trail). `--include-flagged` is the
  escape hatch for known-clean windows. `poll` updates
  `baselines.json` each cycle under the same exclusion.
- **Passkey/FIDO-bound tokens shrink the replay window but don't close
  it** — AiTM still captures what the proxy completes.

## Tests

```bash
python -m unittest discover tests   # all synthetic fixtures — no real
                                    # tenant data or secrets
```
