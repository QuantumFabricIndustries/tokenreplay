import json
import tempfile
import unittest
from pathlib import Path

from tokenreplay import (baselines as bl, cli, evidence, score,
                         signins as si)

FIX = Path(__file__).parent / "fixtures"
SIGNINS = json.loads((FIX / "signins.json").read_text())
AUDITS = json.loads((FIX / "audits.json").read_text())
ASNMAP = json.loads((FIX / "asnmap.json").read_text())


def _signins():
    return si.parse_signins(SIGNINS)


def _audits():
    return si.parse_audits(AUDITS)


def _baseline(upn, **kw):
    return {upn: bl.Baseline(**kw)}


class TestParsing(unittest.TestCase):
    def test_envelope_and_bare_array(self):
        env = si.parse_signins(SIGNINS)
        bare = si.parse_signins(SIGNINS["value"])
        self.assertEqual(len(env), len(bare))
        self.assertEqual(len(env), 8)

    def test_field_extraction(self):
        s = {x.id: x for x in _signins()}
        self.assertEqual(s["s6"].protocol, "devicecode")
        self.assertTrue(s["s6"].mfa)
        self.assertEqual(s["s1"].country, "US")
        self.assertEqual(s["s1"].network_type, "trustednamedlocation")
        self.assertTrue(s["s1"].ok)

    def test_audit_extraction(self):
        evs = _audits()
        self.assertEqual(evs[0].target_upn, "dave@corp.com")
        self.assertEqual(evs[0].actor, "dave@corp.com")


class TestEvidence(unittest.TestCase):
    def test_session_replay(self):
        out = evidence.session_replay(_signins())
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].user, "bob@corp.com")
        self.assertIn("DE", out[0].detail)

    def test_session_replay_same_country_no_fire(self):
        rows = [s for s in _signins() if s.upn == "alice@corp.com"]
        self.assertEqual(evidence.session_replay(rows), [])

    def test_impossible_travel(self):
        out = evidence.impossible_travel(_signins())
        users = {f.user for f in out}
        self.assertIn("carol@corp.com", users)     # NYC -> SG in 30min
        self.assertIn("bob@corp.com", users)       # Chicago -> DE in 15min
        self.assertNotIn("alice@corp.com", users)

    def test_hosting_asn(self):
        nets = evidence.load_asnmap(ASNMAP)
        out = evidence.hosting_asn(_signins(), nets)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].user, "erin@corp.com")
        self.assertIn("digitalocean", out[0].detail)

    def test_hosting_asn_no_map_is_empty_not_silent(self):
        self.assertEqual(evidence.hosting_asn(_signins(), None), [])

    def test_device_code_no_history(self):
        out = evidence.device_code(_signins(), baselines={})
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].user, "dave@corp.com")

    def test_device_code_with_history_same_country_quiet(self):
        base = _baseline("dave@corp.com",
                         countries={"NL"}, device_code_used=True)
        self.assertEqual(evidence.device_code(_signins(), base), [])

    def test_device_code_history_new_country_fires(self):
        base = _baseline("dave@corp.com",
                         countries={"US"}, device_code_used=True)
        out = evidence.device_code(_signins(), base)
        self.assertEqual(len(out), 1)
        self.assertIn("unseen country", out[0].detail)

    def test_rare_country(self):
        base = _baseline("carol@corp.com", countries={"US"})
        out = evidence.rare_country(_signins(), base)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].user, "carol@corp.com")

    def test_mfa_method_add(self):
        out = evidence.mfa_method_add(_audits())
        self.assertEqual({f.user for f in out},
                         {"dave@corp.com", "frank@corp.com"})

    def test_correlate_promotes_chain(self):
        findings = evidence.evaluate(_signins(), _audits())
        corr = [f for f in findings
                if f.rule == "persistence-correlated"]
        # dave: device-code 18:00 -> security-info add 20:00 = 2h window
        self.assertEqual(len(corr), 1)
        self.assertEqual(corr[0].user, "dave@corp.com")
        # frank's add has no preceding flag -> stays uncorrelated
        self.assertFalse(any(f.user == "frank@corp.com" for f in corr))


class TestScoring(unittest.TestCase):
    def test_verdicts(self):
        res = score.score(evidence.evaluate(_signins(), _audits(),
                                            asnmap=evidence.load_asnmap(
                                                ASNMAP)))
        self.assertEqual(res["bob@corp.com"]["verdict"], "COMPROMISED")
        self.assertEqual(res["dave@corp.com"]["verdict"], "COMPROMISED")
        self.assertEqual(res["carol@corp.com"]["verdict"], "SUSPICIOUS")
        self.assertEqual(res["erin@corp.com"]["verdict"], "HIGH RISK")
        self.assertEqual(res["frank@corp.com"]["verdict"], "SUSPICIOUS")
        self.assertEqual(res["_overall"]["verdict"], "COMPROMISED")
        self.assertNotIn("alice@corp.com", res)      # clean -> absent

    def test_caps(self):
        fs = [evidence.Finding("rare-country", "u", 0, str(i))
              for i in range(5)]
        res = score.score(fs)
        self.assertEqual(res["u"]["raw"], 100)
        self.assertEqual(res["u"]["score"], 40)      # capped

    def test_forced_ignores_weight(self):
        res = score.score([evidence.Finding("session-replay", "u", 0, "x")])
        self.assertEqual(res["u"]["verdict"], "COMPROMISED")


class TestBaselines(unittest.TestCase):
    def test_build_and_roundtrip(self):
        built = bl.build(_signins())
        self.assertIn("dave@corp.com", built)
        self.assertTrue(built["dave@corp.com"].device_code_used)
        self.assertIn("SG", built["carol@corp.com"].countries)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "b.json"
            bl.save(p, built)
            loaded = bl.load(p)
            self.assertEqual(
                loaded["carol@corp.com"].countries,
                built["carol@corp.com"].countries)


class TestCli(unittest.TestCase):
    def test_analyze_end_to_end(self):
        with tempfile.TemporaryDirectory() as td:
            b = Path(td) / "base.json"
            built = bl.build([s for s in _signins()
                              if s.upn == "alice@corp.com"])
            bl.save(b, built)
            rc = cli.main([
                "analyze", "--file", str(FIX / "signins.json"),
                "--audits", str(FIX / "audits.json"),
                "--baselines", str(b),
                "--asnmap", str(FIX / "asnmap.json")])
            self.assertEqual(rc, 1)                  # COMPROMISED -> 1

    def test_baselines_build_cmd(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "o.json"
            rc = cli.main(["baselines", "build",
                           "--file", str(FIX / "signins.json"),
                           "-o", str(out)])
            self.assertEqual(rc, 0)
            self.assertTrue(out.exists())


if __name__ == "__main__":
    unittest.main()
