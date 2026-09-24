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
    rows: tuple = ()   # implicated SignIn records — excluded from
                       # baseline learning so flagged traffic can't
                       # poison history


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


def _tenant_egress(baselines, min_users=3):
    """ASNs shared by enough different tenant users are shared egress —
    Zscaler/WARP/Netskope/corporate VPN/VDI all put real users on
    AWS/Azure/GCP/Cloudflare ASNs.

    Hosting-listed ASNs are harder to promote: real SASE egress covers
    most of the tenant while an attacker VPS covers a handful of
    victims, so they need max(min_users, 20% of tenant users) instead
    of the flat floor. On very small tenants the floor still binds —
    `--allow-asn` is the reliable declaration there."""
    import math
    users_per_asn = {}
    for b in baselines.values():
        for a in b.asns:
            users_per_asn[a] = users_per_asn.get(a, 0) + 1
    hosting_min = max(min_users, math.ceil(0.2 * len(baselines)))
    out = set()
    for a, n in users_per_asn.items():
        need = hosting_min if a in HOSTING_ASNS else min_users
        if n >= need:
            out.add(a)
    return out


def _hosting_tag(row, asnmap):
    """-> hosting descriptor or "" — the record's own ASN number first,
    then the --asnmap label override."""
    if row.asn and row.asn in HOSTING_ASNS:
        return f"hosting AS{row.asn}"
    if asnmap:
        label = _asn_label(row.ip, asnmap)
        if label and any(h in label for h in HOSTING_HINTS):
            return f"hosting '{label}'"
    return ""


def session_replay(signins, baselines=None, asnmap=None, allow_asn=()):
    """Same sessionId observed from a DIFFERENT NETWORK — keyed on ASN
    change, not country (US victim -> US VPS is the common case).

    FP gate: the NEW sighting only counts as replay when its network is
    hosting or never-seen-for-this-user. A phone roaming home wifi <->
    cellular changes ASN all day on networks it has history on — that's
    `session-network-drift` info, not replay."""
    baselines = baselines or {}
    allow = {int(a) for a in allow_asn}
    egress = _tenant_egress(baselines)
    by_sess = {}
    for s in signins:
        if s.session_id and s.ok:
            by_sess.setdefault((s.upn, s.session_id), []).append(s)
    out = []
    for (upn, sess), rows in by_sess.items():
        rows.sort(key=lambda r: r.ts)
        asns = {r.asn for r in rows if r.asn}
        ips = {r.ip for r in rows if r.ip}
        countries = {r.country for r in rows if r.country}
        # replay needs the session on 2+ networks — a single sighting is
        # hosting_asn's job, not proof of replay
        net_changed = len(rows) >= 2 and (
            len(asns) >= 2 or
            (len(ips) >= 2 and len(countries) >= 2))
        if not net_changed:
            continue
        b = baselines.get(upn)
        base_asns = (b.asns if b else set()) | egress | allow

        def suspicious(r):
            if r.asn in allow:
                return ""
            tag = _hosting_tag(r, asnmap)
            if tag:
                return tag
            if r.asn and b and r.asn not in base_asns:
                return f"AS{r.asn} never seen for this user"
            if not r.asn and r.country and b \
                    and r.country not in b.countries:
                return f"first-seen country {r.country}"
            return ""

        hits = [(r, tag) for r in rows[1:] if (tag := suspicious(r))]
        if hits:
            out.append(Finding(
                "session-replay", upn, rows[0].ts,
                f"session {sess[:8]}... replayed from a different "
                f"network: ASNs {sorted(asns) or ips}; "
                f"{'; '.join(sorted({t for _, t in hits}))}"
                + (f" across {sorted(countries)}"
                   if len(countries) >= 2 else ""),
                rows=tuple(r for r, _ in hits)))
        else:
            out.append(Finding(
                "session-network-drift", upn, rows[0].ts,
                f"session {sess[:8]}... seen from ASNs "
                f"{sorted(asns) or ips} - all known-for-user or "
                f"unverifiable networks (mobile roaming shape)"))
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
                        f"({kmh:.0f}km/h)", rows=(prev, s)))
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


def hosting_asn(signins, asnmap, baselines=None, allow_asn=()):
    """Interactive+success sign-in from a hosting provider — AiTM kits
    run on VPS; humans rarely auth from a datacenter. Primary source is
    the record's own autonomousSystemNumber vs the bundled HOSTING_ASNS
    list; --asnmap labels are the override; --allow-asn suppresses.

    Tenant-egress gate: an ASN already in >=3 users' baselines is shared
    corporate egress (SASE/WARP/VDI), not an attacker's VPS."""
    allow = {int(a) for a in allow_asn}
    egress = _tenant_egress(baselines or {})
    out = []
    for s in signins:
        if not (s.interactive and s.ok):
            continue
        if s.asn in allow or s.asn in egress:
            continue
        tag = _hosting_tag(s, asnmap)
        if tag:
            out.append(Finding(
                "hosting-asn", s.upn, s.ts,
                f"interactive auth from {tag} ({s.ip})", rows=(s,)))
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
                "(EvilTokens pattern)", rows=(s,)))
        elif b is None or not b.device_code_used:
            out.append(Finding(
                "device-code-flow", s.upn, s.ts,
                "device-code auth with NO prior device-code usage for "
                "this account (EvilTokens pattern)", rows=(s,)))
        elif s.country and s.country not in b.countries:
            out.append(Finding(
                "device-code-flow", s.upn, s.ts,
                f"device-code auth from unseen country {s.country}",
                rows=(s,)))
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
                f"{s.country} (baseline: {len(b.countries)} known)",
                rows=(s,)))
    return out


def implicated(findings, min_weight=20):
    """-> {id(row): (row, [rules])} — sign-in records behind findings
    >=min_weight, mapped to the rules that flagged them. The review
    surface for `baselines build` output."""
    from .score import WEIGHTS
    out = {}
    for f in findings:
        if WEIGHTS.get(f.rule, 0) >= min_weight:
            for r in f.rows:
                ent = out.setdefault(id(r), (r, []))
                if f.rule not in ent[1]:
                    ent[1].append(f.rule)
    return out


def implicated_rows(findings, min_weight=20):
    """id()s of sign-in records behind findings >=min_weight — the set
    baseline learning must skip. SUSPICIOUS+ traffic stays out of
    history until an admin confirms it (baselines confirm); info-level
    findings like session-network-drift still learn (mobile roaming is
    legitimately new)."""
    return set(implicated(findings, min_weight))


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


def evaluate(signins, audits=(), baselines=None, asnmap=None,
             allow_asn=()):
    """All rules + correlation -> finding list."""
    baselines = baselines or {}
    out = []
    out += session_replay(signins, baselines, asnmap, allow_asn)
    out += impossible_travel(signins)
    out += hosting_asn(signins, asnmap, baselines, allow_asn)
    out += device_code(signins, baselines)
    out += rare_country(signins, baselines)
    out += mfa_method_add(audits)
    return correlate(out)
