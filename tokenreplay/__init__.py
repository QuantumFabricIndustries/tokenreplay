"""tokenreplay — AiTM / token-replay detection on Entra sign-in telemetry.

Sits where tokenwatch can't reach: tokens captured server-side by
reverse-proxy phishing kits and OAuth device-code flows are minted at
the IdP, then replayed from attacker infrastructure. Detection means
reading sign-in/audit telemetry, not the endpoint.

Stdlib only. The analysis engine runs on exported Graph JSON — no API
access required; `poll` (client-credentials collection) is phase 2.
"""
__version__ = "0.1.0"
