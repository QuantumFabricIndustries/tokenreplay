"""Evidence rules — each emits Findings; scoring lives in score.py.

The AiTM/replay signature is never one event, it's the *shape*:
a token minted at the proxy, replayed from elsewhere. Rules are ordered
strongest-first; `correlate()` runs last and promotes combinations.
"""
import ipaddress
from dataclasses import dataclass

from .signins import haversine_km


@dataclass
class Finding:
    rule: str
    user: str
    ts: float
    detail: str


# substring match on the ASN/prefix label — covers the VPS fleets the
# AiTM kits actually deploy to; residential proxies evade this rule
HOSTING_HINTS = (
    "digitalocean", "hetzner", "ovh", "vultr", "linode", "contabo",
    "choopa", "m247", "datacamp", "kamatera", "ionos", "interserver",
    "amazon", "aws", "google cloud", "gcp", "microsoft azure", "azure",
    "oracle cloud", "alibaba", "tencent", "leaseweb", "servers.com",
    "changi", "hostwinds", "vps", "hosting",
)

# activityDisplayName substrings — security-info registration is the
# persistence move after a captured session (ShinyHunters/Helix play)
_MFA_ACTS = (
    "registered security info", "security info",
    "strong authentication method", "authentication method",
    "registered authentication", "default security info",
)

CORRELATE_WINDOW_S = 72 * 3600     # persistence within 72h of a flag


def _users(signins):
    by = {}
    for s in signins:
        if s.upn:
            by.setdefault(s.upn, []).append(s)
    for rows in by.values():
        rows.sort(key=lambda s: s.ts)
    return by


def session_replay(signins):
    """Same sessionId observed from 2+ distinct IPs or countries — the
    literal token-replay signature. Skipped silently when the export
    doesn't carry sessionId (free-tier logs often don't)."""
    by_sess = {}
    for s in signins:
        if s.session_id and s.ok:
            by_sess.setdefault((s.upn, s.session_id), []).append(s)
    out = []
    for (upn, sess), rows in by_sess.items():
        ips = {r.ip for r in rows if r.ip}
        countries = {r.country for r in rows if r.country}
        if len(ips) >= 2 and len(countries) >= 2:
            rows.sort(key=lambda r: r.ts)
            out.append(Finding(
                "session-replay", upn, rows[0].ts,
                f"session {sess[:8]}... seen from {len(ips)} IPs across "
                f"{sorted(countries)} (replay)"))
    return out


def impossible_travel(signins, max_kmh=900, min_km=500):
    """Consecutive sign-ins faster than physics allows."""
    out = []
    for upn, rows in _users(signins).items():
        prev = None
        for s in rows:
            if (prev and s.lat and s.lon and prev.lat and prev.lon
                    and s.ts > prev.ts):
                km = haversine_km(prev.lat, prev.lon, s.lat, s.lon)
                kmh = km / max((s.ts - prev.ts) / 3600, 0.01)
                if km >= min_km and kmh > max_kmh:
                    out.append(Finding(
                        "impossible-travel", upn, s.ts,
                        f"{prev.country}->{s.country} "
                        f"{km:.0f}km in {(s.ts-prev.ts)/60:.0f}min "
                        f"({kmh:.0f}km/h)"))
            prev = s
    return out


def load_asnmap(obj):
    """{"prefixes": {"<cidr>": "<label>", ...}} -> [(network, label)]."""
    nets = []
    for cidr, label in (obj.get("prefixes") or {}).items():
        try:
            nets.append((ipaddress.ip_network(cidr, strict=False),
                         str(label).lower()))
        except ValueError:
            continue
    return nets


def _asn_label(ip, nets):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    for net, label in nets:
        if addr in net:
            return label
    return ""


def hosting_asn(signins, asnmap):
    """Interactive+success sign-in from a hosting-provider prefix — AiTM
    kits run on VPS; humans rarely auth from a datacenter. Needs an
    --asnmap file; without it this rule is unavailable, not silent."""
    if not asnmap:
        return []
    out = []
    for s in signins:
        if not (s.interactive and s.ok):
            continue
        label = _asn_label(s.ip, asnmap)
        if label and any(h in label for h in HOSTING_HINTS):
            out.append(Finding(
                "hosting-asn", s.upn, s.ts,
                f"interactive auth from hosting ASN '{label}' "
                f"({s.ip})"))
    return out


def device_code(signins, baselines):
    """Device-code flow abuse: flagged when the user has no device-code
    history, or it arrives from a country outside their baseline."""
    out = []
    for s in signins:
        if s.protocol != "devicecode" or not s.ok:
            continue
        b = baselines.get(s.upn)
        if b is None or not b.device_code_used:
            out.append(Finding(
                "device-code-flow", s.upn, s.ts,
                "device-code auth with NO prior device-code usage for "
                "this account (EvilTokens pattern)"))
        elif s.country and s.country not in b.countries:
            out.append(Finding(
                "device-code-flow", s.upn, s.ts,
                f"device-code auth from unseen country {s.country}"))
    return out


def mfa_method_add(audits):
    """Security-info/MFA-method registration events from directoryAudits."""
    out = []
    for a in audits:
        act = a.activity.lower()
        if any(k in act for k in _MFA_ACTS) and a.result in ("", "success"):
            out.append(Finding(
                "mfa-method-add", a.target_upn or a.actor, a.ts,
                f"'{a.activity}' by {a.actor or '?'}"))
    return out


def rare_country(signins, baselines):
    """Interactive sign-in from a country the user has never used —
    weak alone, meaningful stacked."""
    out = []
    for s in signins:
        if not s.interactive or not s.ok or not s.country:
            continue
        b = baselines.get(s.upn)
        if b and b.countries and s.country not in b.countries:
            out.append(Finding(
                "rare-country", s.upn, s.ts,
                f"interactive auth from first-seen country "
                f"{s.country} (baseline: {len(b.countries)} known)"))
    return out


def correlate(findings):
    """Persistence registration inside the window after a suspicious
    sign-in -> the ShinyHunters chain, promoted to its own finding."""
    flagged = {}
    adds = []
    for f in findings:
        if f.rule == "mfa-method-add":
            adds.append(f)
        else:
            flagged.setdefault(f.user, []).append(f)
    out = []
    for a in adds:
        for f in flagged.get(a.user, []):
            if 0 <= a.ts - f.ts <= CORRELATE_WINDOW_S:
                out.append(Finding(
                    "persistence-correlated", a.user, a.ts,
                    f"'{a.detail}' within "
                    f"{(a.ts-f.ts)/3600:.1f}h of {f.rule} "
                    f"- capture-then-persist chain"))
                break
    return findings + out


def evaluate(signins, audits=(), baselines=None, asnmap=None):
    """All rules + correlation -> finding list."""
    baselines = baselines or {}
    out = []
    out += session_replay(signins)
    out += impossible_travel(signins)
    out += hosting_asn(signins, asnmap)
    out += device_code(signins, baselines)
    out += rare_country(signins, baselines)
    out += mfa_method_add(audits)
    return correlate(out)
