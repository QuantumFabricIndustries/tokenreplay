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

# ASN numbers of the same fleets — stable, small, bundled. Graph's
# signIn record carries autonomousSystemNumber; matching on numbers is
# what makes same-country replay (US victim -> US VPS) visible.
HOSTING_ASNS = {
    14061,                    # DigitalOcean
    24940, 21502,             # Hetzner
    16276, 35540,             # OVH
    20473,                    # Vultr/Choopa
    63949,                    # Linode / Akamai Connected Cloud
    51167,                    # Contabo
    9009,                     # M247
    16509, 14618, 8987,       # AWS
    15169, 396982, 19527,     # Google / GCP
    8075, 8068, 8069, 12076,  # Microsoft / Azure
    31898,                    # Oracle Cloud
    45102,                    # Alibaba
    132203,                   # Tencent
    30633, 395954,            # Leaseweb
    36007,                    # Kamatera
    54290,                    # Hostwinds
}

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


def session_replay(signins, asnmap=None):
    """Same sessionId observed from a DIFFERENT NETWORK — keyed on ASN
    change, not country: the common case is a victim and the replaying
    host in the same country (US user, US-hosted VPS). Country change is
    a booster on top, not the trigger. Falls back to IP+country when
    records lack autonomousSystemNumber."""
    by_sess = {}
    for s in signins:
        if s.session_id and s.ok:
            by_sess.setdefault((s.upn, s.session_id), []).append(s)
    out = []
    for (upn, sess), rows in by_sess.items():
        asns = {r.asn for r in rows if r.asn}
        ips = {r.ip for r in rows if r.ip}
        countries = {r.country for r in rows if r.country}
        hosting = [r.asn for r in rows if r.asn in HOSTING_ASNS]
        labels = {_asn_label(r.ip, asnmap) for r in rows} - {""} \
            if asnmap else set()
        hosting_lbl = [l for l in labels
                       if any(h in l for h in HOSTING_HINTS)]
        # replay needs the session on 2+ networks: >=2 distinct ASNs,
        # or (when ASN data is thin) the old IP+country heuristic.
        # A single sign-in from a hosting ASN is hosting_asn's job,
        # not proof of replay.
        net_changed = len(rows) >= 2 and (
            len(asns) >= 2 or
            (len(ips) >= 2 and len(countries) >= 2))
        if not net_changed:
            continue
        rows.sort(key=lambda r: r.ts)
        bits = [f"ASNs {sorted(asns)}" if len(asns) >= 2
                else f"{len(ips)} IPs"]
        if len(countries) >= 2:
            bits.append(f"across {sorted(countries)}")
        if hosting:
            bits.append(f"hosting AS{hosting[0]} involved")
        if hosting_lbl:
            bits.append(f"hosting '{hosting_lbl[0]}' involved")
        out.append(Finding(
            "session-replay", upn, rows[0].ts,
            f"session {sess[:8]}... replayed from a different network: "
            + "; ".join(bits)))
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
    """Interactive+success sign-in from a hosting provider — AiTM kits
    run on VPS; humans rarely auth from a datacenter. Primary source is
    the record's own autonomousSystemNumber vs the bundled HOSTING_ASNS
    list; --asnmap labels are the override. With neither ASN data nor a
    map the rule is unavailable, not silent."""
    out = []
    for s in signins:
        if not (s.interactive and s.ok):
            continue
        if s.asn and s.asn in HOSTING_ASNS:
            out.append(Finding(
                "hosting-asn", s.upn, s.ts,
                f"interactive auth from hosting ASN{s.asn} ({s.ip})"))
            continue
        if asnmap:
            label = _asn_label(s.ip, asnmap)
            if label and any(h in label for h in HOSTING_HINTS):
                out.append(Finding(
                    "hosting-asn", s.upn, s.ts,
                    f"interactive auth from hosting '{label}' "
                    f"({s.ip})"))
    return out


def device_code(signins, baselines):
    """Device-code flow abuse, three layers:

    - tenant baselines exist and NOBODY has device-code history -> the
      tenant doesn't use the flow; any use is high severity
      (`device-code-tenant`)
    - tenant does use it -> fall back to the per-user baseline: no
      history or unseen country flags (`device-code-flow`)
    - no baselines at all -> can't prove tenant history; flag per-user
      as before
    """
    out = []
    tenant_uses_dc = any(b.device_code_used
                         for b in baselines.values())
    for s in signins:
        if s.protocol != "devicecode" or not s.ok:
            continue
        b = baselines.get(s.upn)
        if baselines and not tenant_uses_dc:
            out.append(Finding(
                "device-code-tenant", s.upn, s.ts,
                "device-code auth but the TENANT has no device-code "
                "history - the flow isn't legitimate here "
                "(EvilTokens pattern)"))
        elif b is None or not b.device_code_used:
            out.append(Finding(
                "device-code-flow", s.upn, s.ts,
                "device-code auth with NO prior device-code usage for "
                "this account (EvilTokens pattern)"))
        elif s.country and s.country not in b.countries:
            out.append(Finding(
                "device-code-flow", s.upn, s.ts,
                f"device-code auth from unseen country {s.country}"))
    return out


def coverage_warnings(signins):
    """What the input can't see. The Entra portal exports interactive
    and non-interactive sign-ins SEPARATELY, and replayed tokens mostly
    surface on the non-interactive side — an interactive-only export
    means session-replay quietly finds almost nothing."""
    if not signins:
        return []
    types = set()
    for s in signins:
        if s.event_types:
            types |= s.event_types
        else:
            types.add("interactiveuser" if s.interactive
                      else "noninteractiveuser")
    if not any("noninteractive" in t for t in types):
        return ["input has NO non-interactive sign-ins - replayed "
                "tokens mostly surface there; the Entra portal exports "
                "interactive and non-interactive sign-ins separately"]
    if not any(s.asn for s in signins):
        return ["records carry no autonomousSystemNumber - session "
                "replay degrades to IP+country; same-country replay "
                "(US victim -> US VPS) may be missed"]
    return []


def recommendations(findings):
    """The actual fix for each attack class — findings say what
    happened, these say what to do about it."""
    rules = {f.rule for f in findings}
    recs = []
    if rules & {"device-code-flow", "device-code-tenant"}:
        recs.append("Conditional Access: block device-code flow "
                    "(authentication flows condition) for users who "
                    "don't need it - device-code phishing can't land")
    if "session-replay" in rules:
        recs.append("Conditional Access: enable token protection / "
                    "session binding on cloud apps - a captured token "
                    "fails to replay off the original device")
    return recs


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
    out += session_replay(signins, asnmap)
    out += impossible_travel(signins)
    out += hosting_asn(signins, asnmap)
    out += device_code(signins, baselines)
    out += rare_country(signins, baselines)
    out += mfa_method_add(audits)
    return correlate(out)
