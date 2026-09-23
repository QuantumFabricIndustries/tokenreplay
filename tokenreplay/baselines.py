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
    client_apps: set = field(default_factory=set)
    apps: set = field(default_factory=set)
    device_code_used: bool = False
    first_ts: float = 0.0
    last_ts: float = 0.0

    def to_json(self):
        return {
            "countries": sorted(self.countries),
            "ips": sorted(self.ips),
            "client_apps": sorted(self.client_apps),
            "apps": sorted(self.apps),
            "device_code_used": self.device_code_used,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
        }

    @staticmethod
    def from_json(d):
        return Baseline(
            countries=set(d.get("countries") or []),
            ips=set(d.get("ips") or []),
            client_apps=set(d.get("client_apps") or []),
            apps=set(d.get("apps") or []),
            device_code_used=bool(d.get("device_code_used")),
            first_ts=float(d.get("first_ts") or 0.0),
            last_ts=float(d.get("last_ts") or 0.0))


def build(signins):
    """upn -> Baseline from a sign-in history export."""
    out = {}
    for s in signins:
        if not s.upn:
            continue
        b = out.setdefault(s.upn, Baseline())
        if s.country:
            b.countries.add(s.country)
        if s.ip:
            b.ips.add(s.ip)
        if s.client_app:
            b.client_apps.add(s.client_app)
        if s.app:
            b.apps.add(s.app)
        if s.protocol == "devicecode":
            b.device_code_used = True
        b.first_ts = s.ts if not b.first_ts else min(b.first_ts, s.ts)
        b.last_ts = max(b.last_ts, s.ts)
    return out


def save(path, baselines):
    Path(path).write_text(
        json.dumps({u: b.to_json() for u, b in baselines.items()},
                   indent=2, sort_keys=True),
        encoding="utf-8")


def load(path):
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return {u: Baseline.from_json(b) for u, b in raw.items()}
