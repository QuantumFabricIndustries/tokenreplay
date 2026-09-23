"""Reporting — per-user evidence rollup, text or JSON."""
import json
import time


def render(result, as_json=False):
    if as_json:
        doc = {"overall": result["_overall"]["verdict"], "users": {}}
        for user, u in result.items():
            if user == "_overall":
                continue
            doc["users"][user] = {
                "verdict": u["verdict"], "score": u["score"],
                "raw": u["raw"], "forced": u["forced"],
                "findings": [
                    {"rule": f.rule, "ts": f.ts, "detail": f.detail}
                    for f in u["findings"]],
            }
        return json.dumps(doc, indent=2)

    lines = []
    order = {"COMPROMISED": 3, "HIGH RISK": 2, "SUSPICIOUS": 1,
             "CLEAN": 0}
    users = sorted(
        ((u, d) for u, d in result.items() if u != "_overall"),
        key=lambda kv: -order[kv[1]["verdict"]])
    for user, u in users:
        mark = {"COMPROMISED": "!!!", "HIGH RISK": "!!",
                "SUSPICIOUS": "!"}.get(u["verdict"], " ")
        cap = (f" (raw {u['raw']})" if u["raw"] != u["score"] else "")
        lines.append(f"[{u['verdict']:>11}] {mark} {user} "
                     f"score={u['score']}{cap}")
        for f in sorted(u["findings"], key=lambda f: f.ts):
            when = time.strftime("%Y-%m-%d %H:%M", time.gmtime(f.ts))
            lines.append(f"    {f.rule:<24} {when}Z  {f.detail}")
    lines.append("")
    lines.append(f"OVERALL: {result['_overall']['verdict']}")
    return "\n".join(lines)
