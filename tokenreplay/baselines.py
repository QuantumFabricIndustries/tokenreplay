"""Per-user behavior baselines.

Evidence rules that say "new" or "first" need history: countries the
user has signed in from, whether they've ever used device-code flow,
which client apps are routine. Built from a prior sign-in export —
`tokenreplay baselines build --file history.json`.
"""
import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Baseline:
    countries: set = field(default_factory=set)
    ips: set = field(default_factory=set)
    asns: set = field(default_factory=set)   # networks the user roams on
    client_apps: set = field(default_factory=set)
    apps: set = field(default_factory=set)
    device_code_used: bool = False
    confirmed_asns: set = field(default_factory=set)  # admin-approved
    first_ts: float = 0.0
    last_ts: float = 0.0

    def to_json(self):
        return {
            "countries": sorted(self.countries),
            "ips": sorted(self.ips),
            "asns": sorted(self.asns),
            "client_apps": sorted(self.client_apps),
            "apps": sorted(self.apps),
            "device_code_used": self.device_code_used,
            "confirmed_asns": sorted(self.confirmed_asns),
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
        }

    @staticmethod
    def from_json(d):
        return Baseline(
            countries=set(d.get("countries") or []),
            ips=set(d.get("ips") or []),
            asns=set(d.get("asns") or []),
            client_apps=set(d.get("client_apps") or []),
            apps=set(d.get("apps") or []),
            device_code_used=bool(d.get("device_code_used")),
            confirmed_asns=set(d.get("confirmed_asns") or []),
            first_ts=float(d.get("first_ts") or 0.0),
            last_ts=float(d.get("last_ts") or 0.0))


def _learn(b, s):
    if s.country:
        b.countries.add(s.country)
    if s.ip:
        b.ips.add(s.ip)
    if s.asn:
        b.asns.add(s.asn)
    if s.client_app:
        b.client_apps.add(s.client_app)
    if s.app:
        b.apps.add(s.app)
    if s.protocol == "devicecode":
        b.device_code_used = True
    b.first_ts = s.ts if not b.first_ts else min(b.first_ts, s.ts)
    b.last_ts = max(b.last_ts, s.ts)


def build(signins, audits=(), asnmap=None, allow_asn=(),
          exclude_flagged=True):
    """upn -> Baseline from a sign-in history export.

    Anti-poisoning: with exclude_flagged the export is evaluated first
    and sign-ins implicated in SUSPICIOUS+ findings are NOT learned —
    otherwise an attacker's VPS in history lands in baselines and
    launders itself into "known" / tenant-egress status. Flagged rows
    only enter via `baselines confirm` (explicit admin approval).
    --include-flagged restores naive learning for known-clean windows.
    """
    flagged = set()
    if exclude_flagged:
        from . import evidence
        flagged = evidence.implicated_rows(evidence.evaluate(
            signins, audits, baselines={}, asnmap=asnmap,
            allow_asn=allow_asn))
    out = {}
    for s in signins:
        if not s.upn or id(s) in flagged:
            continue
        _learn(out.setdefault(s.upn, Baseline()), s)
    return out


def update(base, signins, flagged=None):
    """Learn new rows into existing baselines. `flagged` is the id()
    set from evidence.implicated_rows — evaluated BEFORE updating so a
    replay row in this window can't teach itself known."""
    flagged = flagged or set()
    for s in signins:
        if not s.upn or id(s) in flagged:
            continue
        _learn(base.setdefault(s.upn, Baseline()), s)
    return base


def confirm(base, upn, asn):
    """Explicit admin safe-mark: the flagged network is legitimate for
    this user — learned into asns AND recorded in confirmed_asns as an
    audit trail (it counts toward tenant egress like learned history)."""
    b = base.setdefault(upn, Baseline())
    b.asns.add(asn)
    b.confirmed_asns.add(asn)
    return b


def save(path, baselines):
    Path(path).write_text(
        json.dumps({u: b.to_json() for u, b in baselines.items()},
                   indent=2, sort_keys=True),
        encoding="utf-8")


def load(path):
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return {u: Baseline.from_json(b) for u, b in raw.items()}
