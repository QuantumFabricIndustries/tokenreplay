"""Verdict scoring — per-user findings -> per-user verdict + overall.

Same philosophy as tokenwatch: observed-attack classes force the
verdict; posture/weak signals accumulate under caps.
"""

WEIGHTS = {
    "session-replay":          80,   # same session, 2+ countries — literal
                                   # token replay, near-zero FP
    "persistence-correlated":  90,   # MFA-method add within 72h of a flag —
                                   # the capture-then-persist chain
    "hosting-asn":             55,   # interactive auth from a VPS ASN
    "device-code-tenant":      65,   # tenant has NO device-code history —
                                     # the flow isn't legitimate here
    "device-code-flow":        55,   # device-code w/ no history or new geo
    "impossible-travel":       45,   # physics violation between sign-ins
    "mfa-method-add":          35,   # security-info registration, uncorrelated
    "rare-country":            20,   # first-seen country — weak alone
    "session-network-drift":   10,   # session moved networks but all
                                     # known-for-user — mobile roaming
                                     # shape, info only
}

FORCE_COMPROMISED = {"session-replay", "persistence-correlated"}

RULE_CAPS = {
    "rare-country": 40,        # travel-heavy users stack these fast
    "mfa-method-add": 50,
    "impossible-travel": 60,
}

VERDICTS = [(80, "COMPROMISED"), (50, "HIGH RISK"), (20, "SUSPICIOUS"),
            (0, "CLEAN")]


def _verdict(score, forced):
    if forced or score >= 80:
        return "COMPROMISED"
    for bound, name in VERDICTS:
        if score >= bound:
            return name
    return "CLEAN"


def score(findings):
    """-> {user: {"score": n, "verdict": str, "findings": [...]}} +
    {"_overall": verdict}."""
    by_user = {}
    for f in findings:
        u = by_user.setdefault(f.user or "(unknown)",
                               {"score": 0, "forced": False,
                                "findings": [], "per_rule": {}})
        u["findings"].append(f)
        per = u["per_rule"]
        per[f.rule] = per.get(f.rule, 0) + WEIGHTS.get(f.rule, 10)
    for u in by_user.values():
        raw = sum(u["per_rule"].values())
        eff = sum(min(w, RULE_CAPS.get(r, w))
                  for r, w in u["per_rule"].items())
        u["score"] = eff
        u["raw"] = raw
        u["forced"] = any(f.rule in FORCE_COMPROMISED
                          for f in u["findings"])
        u["verdict"] = _verdict(eff, u["forced"])
    order = {"COMPROMISED": 3, "HIGH RISK": 2, "SUSPICIOUS": 1,
             "CLEAN": 0}
    overall = max((u["verdict"] for u in by_user.values()),
                  key=lambda v: order[v], default="CLEAN")
    by_user["_overall"] = {"verdict": overall}
    return by_user
