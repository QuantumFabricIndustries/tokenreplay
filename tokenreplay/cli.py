"""tokenreplay analyze|baselines|report|poll"""
import argparse
import json
import os
import sys
from pathlib import Path

from . import baselines as bl
from . import collect
from . import evidence
from . import report
from . import score
from . import signins as si


def _load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _state_dir():
    return collect.state_dir()


def cmd_analyze(a):
    signins = si.parse_signins(_load_json(a.file))
    audits = si.parse_audits(_load_json(a.audits)) if a.audits else []
    base = bl.load(a.baselines) if a.baselines else {}
    asnmap = evidence.load_asnmap(_load_json(a.asnmap)) \
        if a.asnmap else None
    if a.asnmap is None:
        print("note: no --asnmap; hosting-ASN evidence unavailable",
              file=sys.stderr)
    findings = evidence.evaluate(signins, audits, baselines=base,
                                 asnmap=asnmap)
    result = score.score(findings)
    out = report.render(result, as_json=a.json)
    if a.output:
        Path(a.output).write_text(out, encoding="utf-8")
    print(out)
    _state_dir().mkdir(parents=True, exist_ok=True)
    (_state_dir() / "last_report.json").write_text(
        report.render(result, as_json=True), encoding="utf-8")
    return 0 if result["_overall"]["verdict"] in ("CLEAN", "SUSPICIOUS") \
        else 1


def cmd_baselines(a):
    signins = si.parse_signins(_load_json(a.file))
    built = bl.build(signins)
    dest = a.output or str(_state_dir() / "baselines.json")
    _state_dir().mkdir(parents=True, exist_ok=True)
    bl.save(dest, built)
    print(f"baselines for {len(built)} user(s) -> {dest}")
    return 0


def cmd_report(a):
    p = _state_dir() / "last_report.json"
    if not p.exists():
        print("no report — run analyze first", file=sys.stderr)
        return 2
    doc = json.loads(p.read_text(encoding="utf-8"))
    if a.json:
        print(json.dumps(doc, indent=2))
    else:
        print(f"OVERALL: {doc['overall']}")
        for user, u in doc["users"].items():
            print(f"[{u['verdict']:>11}] {user} score={u['score']}")
            for f in u["findings"]:
                print(f"    {f['rule']:<24} {f['detail']}")
    return 0


def cmd_poll(a):
    try:
        signins, audits = collect.poll(lookback_s=a.hours * 3600)
    except (OSError, json.JSONDecodeError, KeyError) as e:
        print(f"poll needs ~/.tokenreplay/graph.json "
              f"(tenant/client_id/client_secret): {e}", file=sys.stderr)
        return 2
    parsed_s = si.parse_signins({"value": signins})
    parsed_a = si.parse_audits({"value": audits})
    base = bl.load(_state_dir() / "baselines.json") \
        if (_state_dir() / "baselines.json").exists() else {}
    findings = evidence.evaluate(parsed_s, parsed_a, baselines=base)
    result = score.score(findings)
    print(report.render(result, as_json=a.json))
    _state_dir().mkdir(parents=True, exist_ok=True)
    (_state_dir() / "last_report.json").write_text(
        report.render(result, as_json=True), encoding="utf-8")
    return 0 if result["_overall"]["verdict"] in ("CLEAN", "SUSPICIOUS") \
        else 1


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="tokenreplay",
        description="AiTM/token-replay detection on Entra sign-in "
                    "telemetry (analysis engine; Graph poll is phase 2)")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="score an exported sign-in file")
    a.add_argument("--file", required=True, help="signIns JSON export")
    a.add_argument("--audits", help="directoryAudits JSON export")
    a.add_argument("--baselines", help="per-user baselines JSON")
    a.add_argument("--asnmap", help='{"prefixes": {"cidr": "label"}}')
    a.add_argument("--json", action="store_true")
    a.add_argument("-o", "--output")
    a.set_defaults(fn=cmd_analyze)

    b = sub.add_parser("baselines",
                       help="build per-user baselines from history")
    b.add_argument("verb", choices=["build"])
    b.add_argument("--file", required=True)
    b.add_argument("-o", "--output")
    b.set_defaults(fn=cmd_baselines)

    r = sub.add_parser("report", help="reprint the last report")
    r.add_argument("--json", action="store_true")
    r.set_defaults(fn=cmd_report)

    w = sub.add_parser("poll", help="collect via Graph (needs config)")
    w.add_argument("--hours", type=int, default=1,
                   help="initial lookback when no watermark (default 1)")
    w.add_argument("--json", action="store_true")
    w.set_defaults(fn=cmd_poll)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
