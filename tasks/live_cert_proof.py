"""Live proof: non-exportable cert -> JWT client assertion -> verifiable.

Creates a throwaway cert in Cert:\\CurrentUser\\My, signs via
collect.client_assertion (the real PowerShell path), verifies the RS256
signature with the public key, proves the private key refuses export,
then removes the cert.
"""
import base64
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tokenreplay import collect  # noqa: E402

td = tempfile.mkdtemp()
cer = os.path.join(td, "proof.cer")
thumb = collect.new_cert(cer)
print(f"created cert {thumb}; .cer exists={os.path.exists(cer)}")
try:
    cfg = {"tenant": "proof-tenant", "client_id": "proof-app",
           "cert_thumbprint": thumb}
    jwt = collect.client_assertion(cfg)
    h, c, s = jwt.split(".")
    print(f"jwt parts: header={len(h)} claims={len(c)} sig={len(s)}")
    pad = lambda x: x + "=" * (-len(x) % 4)
    signing_b64 = base64.b64encode(f"{h}.{c}".encode()).decode()
    sig_b64 = base64.b64encode(base64.urlsafe_b64decode(pad(s))).decode()
    rc, out, err = collect._run([
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        f"$c=New-Object System.Security.Cryptography.X509Certificates."
        f"X509Certificate2('{cer}');"
        "$k=[System.Security.Cryptography.X509Certificates."
        "RSACertificateExtensions]::GetRSAPublicKey($c);"
        f"$k.VerifyData([Convert]::FromBase64String('{signing_b64}'),"
        f"[Convert]::FromBase64String('{sig_b64}'),"
        "[System.Security.Cryptography.HashAlgorithmName]::SHA256,"
        "[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)"])
    print(f"signature verifies with public .cer: {out.strip()} {err.strip()}")
    rc, out, err = collect._run([
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "$p=ConvertTo-SecureString 'x' -AsPlainText -Force;"
        f"try{{Export-PfxCertificate -Cert 'Cert:\\CurrentUser\\My\\{thumb}'"
        f" -FilePath '{td}\\k.pfx' -Password $p -ErrorAction Stop|Out-Null;"
        "'EXPORTED'}catch{'REFUSED: '+$_.Exception.Message}"])
    print(f"private key export: {out.strip()}")
finally:
    rc, out, err = collect._run([
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        f"Remove-Item 'Cert:\\CurrentUser\\My\\{thumb}' -DeleteKey;"
        f"Test-Path 'Cert:\\CurrentUser\\My\\{thumb}'"])
    print(f"teardown: cert still present = {out.strip()}")
