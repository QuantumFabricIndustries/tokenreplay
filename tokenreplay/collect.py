"""Graph collection — phase 2, functional but UNVERIFIED on a live tenant.

Client-credentials (daemon) flow: POST a token request, GET paged
/auditLogs/signIns + /auditLogs/directoryAudits since a watermark.
Stdlib urllib; the injectable opener keeps tests offline.

Config at ~/.tokenreplay/graph.json:
  {"tenant": "<tenant-id>", "client_id": "<app-id>",
   "client_secret": "<secret>"}

The app registration needs AuditLog.Read.All + admin consent. Store the
secret out of band — tokenwatch can watch the config file.
"""
import json
import time
import urllib.parse
import urllib.request
from pathlib import Path

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"


def state_dir(env=None):
    import os
    env = env if env is not None else os.environ
    return Path(env.get("TOKENREPLAY_HOME")
                or (Path(env.get("USERPROFILE") or env.get("HOME", "."))
                    / ".tokenreplay"))


def _post(url, data, opener=urllib.request.urlopen):
    req = urllib.request.Request(
        url, data=urllib.parse.urlencode(data).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    with opener(req, timeout=30) as r:
        return json.loads(r.read())


def _get(url, token, opener=urllib.request.urlopen):
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {token}"})
    with opener(req, timeout=60) as r:
        return json.loads(r.read())


def get_token(cfg, opener=urllib.request.urlopen):
    resp = _post(
        f"{LOGIN}/{cfg['tenant']}/oauth2/v2.0/token",
        {"client_id": cfg["client_id"],
         "client_secret": cfg["client_secret"],
         "scope": "https://graph.microsoft.com/.default",
         "grant_type": "client_credentials"},
        opener=opener)
    return resp["access_token"]


def _paged(url, token, opener=urllib.request.urlopen, max_pages=50):
    rows = []
    for _ in range(max_pages):
        page = _get(url, token, opener=opener)
        rows += page.get("value") or []
        url = page.get("@odata.nextLink")
        if not url:
            break
    return rows


def fetch_signins(token, since_ts, opener=urllib.request.urlopen):
    iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(since_ts))
    q = urllib.parse.quote(f"createdDateTime ge {iso}")
    return _paged(f"{GRAPH}/auditLogs/signIns?$filter={q}&$top=999",
                  token, opener)


def fetch_audits(token, since_ts, opener=urllib.request.urlopen):
    iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(since_ts))
    q = urllib.parse.quote(f"activityDateTime ge {iso}")
    return _paged(f"{GRAPH}/auditLogs/directoryAudits?$filter={q}"
                  f"&$top=999", token, opener)


def poll(env=None, opener=urllib.request.urlopen, lookback_s=3600):
    """One collection cycle -> (signins, audits) rows since watermark."""
    sd = state_dir(env)
    cfg = json.loads((sd / "graph.json").read_text(encoding="utf-8"))
    mark = sd / "watermark.json"
    try:
        since = json.loads(mark.read_text())["ts"]
    except (OSError, json.JSONDecodeError, KeyError):
        since = time.time() - lookback_s
    token = get_token(cfg, opener=opener)
    signins = fetch_signins(token, since, opener=opener)
    audits = fetch_audits(token, since, opener=opener)
    mark.write_text(json.dumps({"ts": time.time()}))
    return signins, audits
