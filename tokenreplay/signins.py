"""Parsing — Graph signIn + directoryAudit JSON -> typed records.

Accepts both shapes: {"value": [...]} (paged API/export envelope) and
bare [...] arrays, so `analyze` works on Graph responses, Sentinel
exports, and test fixtures alike.
"""
import math
from dataclasses import dataclass, field
from datetime import datetime


def _epoch(s):
    if not s:
        return 0.0
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")) \
            .timestamp()
    except ValueError:
        return 0.0


@dataclass
class SignIn:
    id: str
    ts: float
    upn: str
    ip: str
    country: str
    lat: float
    lon: float
    app: str
    client_app: str
    os: str
    browser: str
    interactive: bool
    mfa: bool               # auth requirement satisfied via MFA
    protocol: str           # "deviceCode" etc (lowercased)
    session_id: str
    ok: bool                # status.errorCode == 0
    risk: str
    network_type: str       # trustednamedlocation / namedlocation / ""
    raw: dict = field(default_factory=dict, repr=False)


def parse_signins(obj):
    rows = obj.get("value", obj) if isinstance(obj, dict) else obj
    out = []
    for r in rows or []:
        loc = r.get("location") or {}
        geo = loc.get("geoCoordinates") or {}
        dev = r.get("deviceDetail") or {}
        net = r.get("networkLocationDetails") or {}
        req = (r.get("authenticationRequirement") or "")
        out.append(SignIn(
            id=r.get("id", ""),
            ts=_epoch(r.get("createdDateTime")),
            upn=(r.get("userPrincipalName") or "").lower(),
            ip=r.get("ipAddress") or "",
            country=(loc.get("countryOrRegion") or "").upper(),
            lat=float(geo.get("latitude") or 0.0),
            lon=float(geo.get("longitude") or 0.0),
            app=r.get("appDisplayName") or "",
            client_app=r.get("clientAppUsed") or "",
            os=dev.get("operatingSystem") or "",
            browser=dev.get("browser") or "",
            interactive=bool(r.get("isInteractive")),
            mfa="multifactor" in req.replace(" ", "").lower()
                or "mfa" in req.lower(),
            protocol=(r.get("authenticationProtocol") or "").lower(),
            session_id=r.get("sessionId") or "",
            ok=(r.get("status") or {}).get("errorCode", 1) == 0,
            risk=(r.get("riskLevelAggregated") or "").lower(),
            network_type=(net.get("networkType") or "").lower(),
            raw=r))
    return out


@dataclass
class AuditEvent:
    ts: float
    activity: str
    actor: str
    target_upn: str
    result: str


def parse_audits(obj):
    rows = obj.get("value", obj) if isinstance(obj, dict) else obj
    out = []
    for r in rows or []:
        tupn = ""
        for t in r.get("targetResources") or []:
            cand = (t.get("userPrincipalName") or
                    t.get("displayName") or "").lower()
            if "@" in cand:
                tupn = cand
                break
        init = r.get("initiatedBy") or {}
        actor = ((init.get("user") or {}).get("userPrincipalName")
                 or (init.get("app") or {}).get("displayName")
                 or "").lower()
        out.append(AuditEvent(
            ts=_epoch(r.get("activityDateTime")),
            activity=r.get("activityDisplayName") or "",
            actor=actor,
            target_upn=tupn,
            result=(r.get("result") or "").lower()))
    return out


def haversine_km(lat1, lon1, lat2, lon2):
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = (math.sin(dp / 2) ** 2
         + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2)
    return 2 * r * math.asin(math.sqrt(a))
