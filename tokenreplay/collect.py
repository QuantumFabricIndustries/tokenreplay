"""Graph collection — phase 2, functional but UNVERIFIED on a live tenant.

Client-credentials (daemon) flow: POST a token request, GET paged
/auditLogs/signIns + /auditLogs/directoryAudits since a watermark.
Stdlib urllib; the injectable opener/runner keeps tests offline.

Config at ~/.tokenreplay/graph.json — {"tenant", "client_id"} plus ONE
credential, resolved strongest-first:

  1. "cert_thumbprint" (+ optional "cert_store": CurrentUser|LocalMachine)
     certificate credential; the private key lives NON-EXPORTABLE in the
     Windows cert store and signs a JWT client assertion. No secret file.
     `tokenreplay cert new` creates one.
  2. env TOKENREPLAY_CLIENT_SECRET
  3. "client_secret_dpapi" — secret encrypted with DPAPI (user scope).
     `tokenreplay secret protect` migrates a plaintext secret.

A plaintext "client_secret" is REFUSED: it reads every sign-in in the
tenant, and a directory of those files is exactly the infostealer
target tokenwatch exists to catch.
"""
import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"
SECRET_ENV = "TOKENREPLAY_CLIENT_SECRET"
_DPAPI_ENTROPY = b"tokenreplay/graph-client-secret"
_THUMB_RE = re.compile(r"^[0-9A-Fa-f]{40}$")
_STORES = ("CurrentUser", "LocalMachine")


class CredentialError(Exception):
    pass


def state_dir(env=None):
    env = env if env is not None else os.environ
    return Path(env.get("TOKENREPLAY_HOME")
                or (Path(env.get("USERPROFILE") or env.get("HOME", "."))
                    / ".tokenreplay"))


def _run(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=60)
    return p.returncode, p.stdout, p.stderr


def _ps(script, runner):
    return runner(["powershell", "-NoProfile", "-NonInteractive",
                   "-Command", script])


def _b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# --- DPAPI (user scope) ----------------------------------------------------

def _dpapi(data, protect):
    if sys.platform != "win32":
        raise CredentialError(
            f"DPAPI is Windows-only - use {SECRET_ENV} or a certificate")
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    def blob(b):
        buf = ctypes.create_string_buffer(b, len(b))
        return BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    src, _k1 = blob(data)
    ent, _k2 = blob(_DPAPI_ENTROPY)
    out = BLOB()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    # CRYPTPROTECT_UI_FORBIDDEN = 0x1
    if not fn(ctypes.byref(src), None, ctypes.byref(ent), None, None,
              0x1, ctypes.byref(out)):
        raise CredentialError(
            f"DPAPI {'protect' if protect else 'unprotect'} failed "
            f"(winerror {ctypes.GetLastError()}) - blobs only decrypt "
            f"as the user who created them")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def dpapi_protect(secret):
    return base64.b64encode(_dpapi(secret.encode(), True)).decode()


def dpapi_unprotect(b64):
    return _dpapi(base64.b64decode(b64), False).decode()


# --- certificate client assertion -----------------------------------------

def _cert_ref(cfg):
    thumb = str(cfg.get("cert_thumbprint", "")).replace(" ", "")
    store = cfg.get("cert_store", "CurrentUser")
    if not _THUMB_RE.match(thumb) or store not in _STORES:
        raise CredentialError(
            "cert_thumbprint must be 40 hex chars and cert_store "
            f"one of {_STORES}")
    return thumb.upper(), store


def client_assertion(cfg, runner=_run, now=None):
    """RS256 JWT signed by the cert's private key IN the Windows store —
    the key is never read into this process, so NonExportable works."""
    thumb, store = _cert_ref(cfg)
    now = int(now or time.time())
    header = {"alg": "RS256", "typ": "JWT",
              "x5t": _b64url(bytes.fromhex(thumb))}
    claims = {"aud": f"{LOGIN}/{cfg['tenant']}/oauth2/v2.0/token",
              "iss": cfg["client_id"], "sub": cfg["client_id"],
              "jti": str(uuid.uuid4()), "nbf": now, "iat": now,
              "exp": now + 600}
    signing = (_b64url(json.dumps(header, separators=(",", ":")).encode())
               + "." +
               _b64url(json.dumps(claims, separators=(",", ":")).encode()))
    data_b64 = base64.b64encode(signing.encode()).decode()
    rc, out, err = _ps(
        "$ErrorActionPreference='Stop';"
        f"$c=Get-Item 'Cert:\\{store}\\My\\{thumb}';"
        "$k=[System.Security.Cryptography.X509Certificates."
        "RSACertificateExtensions]::GetRSAPrivateKey($c);"
        "if(-not $k){throw 'certificate has no RSA private key'};"
        f"$d=[Convert]::FromBase64String('{data_b64}');"
        "$s=$k.SignData($d,[System.Security.Cryptography.HashAlgorithmName]"
        "::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1);"
        "[Convert]::ToBase64String($s)", runner)
    if rc != 0 or not out.strip():
        raise CredentialError(
            f"signing with cert {thumb} in {store}\\My failed: "
            f"{(err or out).strip()[:300]}")
    return signing + "." + _b64url(base64.b64decode(out.strip()))


def new_cert(out_path, store="CurrentUser", runner=_run):
    """Self-signed RSA-2048 cert, private key NON-EXPORTABLE in the store;
    public .cer written for upload to the app registration. -> thumbprint"""
    if store not in _STORES:
        raise CredentialError(f"store must be one of {_STORES}")
    dest = str(Path(out_path).resolve()).replace("'", "''")
    rc, out, err = _ps(
        "$ErrorActionPreference='Stop';"
        "$c=New-SelfSignedCertificate -Subject 'CN=tokenreplay-graph' "
        f"-CertStoreLocation 'Cert:\\{store}\\My' "
        "-KeyExportPolicy NonExportable -KeySpec Signature "
        "-KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 "
        "-NotAfter (Get-Date).AddYears(1);"
        f"Export-Certificate -Cert $c -FilePath '{dest}' | Out-Null;"
        "$c.Thumbprint", runner)
    thumb = out.strip().splitlines()[-1].strip() if out.strip() else ""
    if rc != 0 or not _THUMB_RE.match(thumb):
        raise CredentialError(f"cert creation failed: "
                              f"{(err or out).strip()[:300]}")
    return thumb


CERT_WARN_S = 30 * 86400       # warn this far ahead of NotAfter


def cert_status(cfg, runner=_run):
    """-> seconds until the configured cert's NotAfter (can be <=0), or
    None when the config uses a secret instead of a cert. Raises
    CredentialError when the thumbprint isn't in the store."""
    if not cfg.get("cert_thumbprint"):
        return None
    thumb, store = _cert_ref(cfg)
    rc, out, err = _ps(
        "$ErrorActionPreference='Stop';"
        f"$c=Get-Item 'Cert:\\{store}\\My\\{thumb}' -ErrorAction Stop;"
        "[int]([DateTimeOffset]$c.NotAfter).ToUnixTimeSeconds()",
        runner)
    txt = out.strip().splitlines()[-1].strip() if out.strip() else ""
    if rc != 0 or not re.fullmatch(r"-?\d+", txt):
        raise CredentialError(
            f"cannot read cert {thumb} in {store}\\My: "
            f"{(err or out).strip()[:300]}")
    return int(txt) - int(time.time())


# --- credential resolution ------------------------------------------------

def auth_params(cfg, env=None, runner=_run):
    """-> token-request credential fields, strongest source first."""
    env = env if env is not None else os.environ
    if cfg.get("cert_thumbprint"):
        return {"client_assertion_type":
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion(cfg, runner)}
    if env.get(SECRET_ENV):
        return {"client_secret": env[SECRET_ENV]}
    if cfg.get("client_secret_dpapi"):
        return {"client_secret": dpapi_unprotect(cfg["client_secret_dpapi"])}
    if cfg.get("client_secret"):
        raise CredentialError(
            "plaintext client_secret in graph.json refused - it can read "
            "every sign-in in the tenant. Run `tokenreplay cert new` "
            "(best) or `tokenreplay secret protect` (DPAPI), or set "
            f"{SECRET_ENV}")
    raise CredentialError(
        "graph.json has no credential: cert_thumbprint, "
        f"client_secret_dpapi, or env {SECRET_ENV}")


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


def get_token(cfg, opener=urllib.request.urlopen, env=None, runner=_run):
    resp = _post(
        f"{LOGIN}/{cfg['tenant']}/oauth2/v2.0/token",
        {"client_id": cfg["client_id"],
         "scope": "https://graph.microsoft.com/.default",
         "grant_type": "client_credentials",
         **auth_params(cfg, env, runner)},
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


def load_config(env=None):
    return json.loads((state_dir(env) / "graph.json")
                      .read_text(encoding="utf-8"))


def save_config(cfg, env=None):
    sd = state_dir(env)
    sd.mkdir(parents=True, exist_ok=True)
    tmp = sd / "graph.json.tmp"
    tmp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    os.replace(tmp, sd / "graph.json")


def poll(env=None, opener=urllib.request.urlopen, lookback_s=3600,
         runner=_run):
    """One collection cycle -> (signins, audits, warnings).

    Cert expiry is checked BEFORE collecting: an expired cert makes the
    token request fail, and "poll ran, no findings" on a broken
    credential reads exactly like a quiet tenant - so expiry raises,
    and <30 days left is a warning, never silent."""
    sd = state_dir(env)
    cfg = load_config(env)
    warnings = []
    days_left = cert_status(cfg, runner)
    if days_left is not None:
        if days_left <= 0:
            raise CredentialError(
                f"cert {cfg['cert_thumbprint']} is EXPIRED - token "
                "requests fail; refusing to report an empty poll as "
                "clean. Run `tokenreplay cert new` and upload the .cer.")
        if days_left < CERT_WARN_S:
            warnings.append(
                f"cert {cfg['cert_thumbprint']} expires in "
                f"{days_left // 86400}d - run `tokenreplay cert new` "
                "and upload the .cer")
    mark = sd / "watermark.json"
    try:
        since = json.loads(mark.read_text())["ts"]
    except (OSError, json.JSONDecodeError, KeyError):
        since = time.time() - lookback_s
    token = get_token(cfg, opener=opener, env=env, runner=runner)
    signins = fetch_signins(token, since, opener=opener)
    audits = fetch_audits(token, since, opener=opener)
    mark.write_text(json.dumps({"ts": time.time()}))
    return signins, audits, warnings
