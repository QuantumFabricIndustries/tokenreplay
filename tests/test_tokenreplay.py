import base64
import json
import os
import sys
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

from tokenreplay import (baselines as bl, cli, collect, evidence, score,
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


def _mk(upn="u@x", ip="1.2.3.4", country="US", asn=7018,
        session="sess-1", ts=1000.0, interactive=True, ok=True,
        protocol=""):
    return si.SignIn(id="x", ts=ts, upn=upn, ip=ip, country=country,
                     lat=40.0, lon=-74.0, app="a", client_app="",
                     os="", browser="", interactive=interactive,
                     mfa=True, protocol=protocol, session_id=session,
                     asn=asn, event_types=set(), ok=ok, risk="",
                     network_type="")


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
    def test_session_replay_same_country_cross_asn(self):
        """The common case: US victim, US-hosted VPS. Country is a
        booster, not the trigger — network (ASN) change fires it."""
        out = evidence.session_replay(_signins())
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].user, "bob@corp.com")
        self.assertIn("different network", out[0].detail)
        self.assertIn("14061", out[0].detail)      # hosting ASN named

    def test_session_replay_same_network_no_fire(self):
        rows = [s for s in _signins() if s.upn == "alice@corp.com"]
        self.assertEqual(evidence.session_replay(rows), [])

    def test_impossible_travel(self):
        out = evidence.impossible_travel(_signins())
        users = {f.user for f in out}
        self.assertIn("carol@corp.com", users)     # NYC -> SG in 30min
        self.assertIn("bob@corp.com", users)       # Chicago -> NYC in
                                                   # 15min still too fast
        self.assertNotIn("alice@corp.com", users)

    def test_hosting_asn_via_asn_number(self):
        """No map needed — the record's own autonomousSystemNumber is
        matched against the bundled hosting list."""
        out = evidence.hosting_asn(_signins(), asnmap=None)
        users = {f.user for f in out}
        self.assertEqual(users, {"erin@corp.com", "dave@corp.com"})
        by_user = {f.user: f for f in out}
        self.assertIn("14061", by_user["erin@corp.com"].detail)
        self.assertIn("16276", by_user["dave@corp.com"].detail)

    def test_replay_mobile_roaming_is_drift_not_replay(self):
        """Phone moving home-wifi <-> cellular: ASN change on networks
        the user already has history on = info, not COMPROMISED."""
        rows = [_mk(upn="mob@x", asn=7018, ip="1.1.1.1", ts=100),
                _mk(upn="mob@x", asn=7922, ip="2.2.2.2", ts=200)]
        base = _baseline("mob@x", countries={"US"},
                         asns={7018, 7922})
        out = evidence.session_replay(rows, baselines=base)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].rule, "session-network-drift")

    def test_replay_new_asn_for_user_fires(self):
        rows = [_mk(upn="mob@x", asn=7018, ts=100),
                _mk(upn="mob@x", asn=44444, ip="9.9.9.9", ts=200)]
        base = _baseline("mob@x", countries={"US"}, asns={7018, 7922})
        out = evidence.session_replay(rows, baselines=base)
        self.assertEqual(out[0].rule, "session-replay")
        self.assertIn("never seen", out[0].detail)

    def test_replay_no_baseline_nonhosting_is_drift(self):
        """No baseline -> can't prove the new network is new; only
        hosting still forces the real finding."""
        rows = [_mk(asn=7018, ts=100), _mk(asn=7922, ip="9.9.9.9",
                                          ts=200)]
        out = evidence.session_replay(rows, baselines={})
        self.assertEqual(out[0].rule, "session-network-drift")
        rows[1].asn = 14061
        out = evidence.session_replay(rows, baselines={})
        self.assertEqual(out[0].rule, "session-replay")

    def test_hosting_asn_tenant_egress_suppresses(self):
        """AS14061 in >=3 users' baselines = shared SASE egress, not a
        VPS — hosting_asn must not flag the whole tenant."""
        base = {u: bl.Baseline(asns={14061})
                for u in ("a@x", "b@x", "c@x")}
        rows = [_mk(upn="d@x", asn=14061, ip="203.0.113.9")]
        self.assertEqual(
            evidence.hosting_asn(rows, None, baselines=base), [])
        # allow-asn manual override also suppresses
        self.assertEqual(
            evidence.hosting_asn(rows, None, allow_asn={14061}), [])

    def test_hosting_asn_map_override(self):
        """--asnmap labels stay an override for numbers we don't carry."""
        class Fake(si.SignIn):
            pass
        s = si.SignIn(id="x", ts=1, upn="u@x", ip="203.0.113.9",
                      country="US", lat=0, lon=0, app="a", client_app="",
                      os="", browser="", interactive=True, mfa=True,
                      protocol="", session_id="", asn=99999,
                      event_types=set(), ok=True, risk="",
                      network_type="")
        out = evidence.hosting_asn(
            [s], evidence.load_asnmap(ASNMAP))
        self.assertEqual(len(out), 1)
        self.assertIn("digitalocean", out[0].detail)

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

    def test_device_code_tenant_layer(self):
        """Baselines exist, nobody uses device code -> ANY use is the
        high-severity tenant finding, not the per-user one."""
        base = _baseline("alice@corp.com",
                         countries={"US"}, device_code_used=False)
        out = evidence.device_code(_signins(), base)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].rule, "device-code-tenant")

    def test_coverage_warnings_interactive_only(self):
        """An interactive-only export must not look like a clean scan."""
        interactive_only = [s for s in _signins() if s.interactive]
        w = evidence.coverage_warnings(interactive_only)
        self.assertTrue(any("non-interactive" in x for x in w))

    def test_coverage_warnings_mixed_export_quiet(self):
        self.assertFalse(
            any("non-interactive" in x
                for x in evidence.coverage_warnings(_signins())))

    def test_coverage_warnings_no_asn(self):
        rows = _signins()
        for s in rows:
            s.asn = 0
        w = evidence.coverage_warnings(rows)
        self.assertTrue(any("autonomousSystemNumber" in x for x in w))

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

    def test_recommendations(self):
        findings = evidence.evaluate(_signins(), _audits())
        recs = evidence.recommendations(findings)
        self.assertTrue(any("device-code" in r for r in recs))
        self.assertTrue(any("token protection" in r for r in recs))

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
        self.assertIn("alice@corp.com", built)   # unflagged -> learned
        self.assertIn("US", built["alice@corp.com"].countries)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "b.json"
            bl.save(p, built)
            loaded = bl.load(p)
            self.assertEqual(
                loaded["alice@corp.com"].countries,
                built["alice@corp.com"].countries)

    def test_build_excludes_flagged(self):
        """Anti-poisoning: sign-ins behind SUSPICIOUS+ findings are not
        learned — an attacker VPS in history can't launder itself into
        per-user baselines or tenant egress."""
        built = bl.build(_signins())
        # bob/carol/dave/erin rows are all implicated (replay, travel,
        # hosting, device-code) -> not learned
        self.assertNotIn("bob@corp.com", built)
        self.assertNotIn("dave@corp.com", built)
        self.assertNotIn("erin@corp.com", built)
        self.assertNotIn("carol@corp.com", built)

    def test_build_include_flagged_escape_hatch(self):
        built = bl.build(_signins(), exclude_flagged=False)
        self.assertIn("dave@corp.com", built)
        self.assertTrue(built["dave@corp.com"].device_code_used)
        self.assertIn("SG", built["carol@corp.com"].countries)

    def test_update_skips_flagged(self):
        base = {}
        bad = _mk(upn="v@x", asn=14061, ip="203.0.113.9")
        good = _mk(upn="v@x", asn=7018, ip="1.1.1.1", session="s2")
        bl.update(base, [bad, good], flagged={id(bad)})
        self.assertEqual(base["v@x"].asns, {7018})

    def test_confirm_learns_asn(self):
        base = {}
        bl.confirm(base, "v@x", 14061)
        self.assertEqual(base["v@x"].asns, {14061})
        self.assertEqual(base["v@x"].confirmed_asns, {14061})
        # survives save/load
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "b.json"
            bl.save(p, base)
            self.assertEqual(bl.load(p)["v@x"].confirmed_asns,
                             {14061})

    def test_egress_scaled_threshold_for_hosting(self):
        """Hosting ASNs need max(3, 20% of tenant users) to promote to
        egress; non-hosting keep the flat 3."""
        # 30-user tenant -> hosting needs 6; 4 sharers is an attacker
        # VPS covering victims, not egress
        base = {f"u{i}@x": bl.Baseline(
                    asns={14061} if i < 4 else {7018})
                for i in range(30)}
        self.assertNotIn(14061, evidence._tenant_egress(base))
        self.assertIn(7018, evidence._tenant_egress(base))
        for i in range(4, 6):
            base[f"u{i}@x"].asns.add(14061)   # 6 sharers -> egress
        self.assertIn(14061, evidence._tenant_egress(base))


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

    def test_baselines_build_exclusion_report(self):
        """build prints the excluded sign-ins with the exact confirm
        command - reviewing exclusions is copy-paste, not
        cross-referencing."""
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "o.json"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.main(["baselines", "build",
                               "--file", str(FIX / "signins.json"),
                               "-o", str(out)])
            self.assertEqual(rc, 0)
            txt = buf.getvalue()
            self.assertIn("excluded from learning", txt)
            self.assertIn("bob@corp.com", txt)
            self.assertIn("session-replay", txt)
            self.assertIn("baselines confirm", txt)
            self.assertIn("--asn 14061", txt)

    def test_baselines_confirm_cmd(self):
        with tempfile.TemporaryDirectory() as td:
            b = Path(td) / "b.json"
            bl.save(b, {"v@x": bl.Baseline()})
            rc = cli.main(["baselines", "confirm",
                           "--baselines", str(b),
                           "--user", "v@x", "--asn", "14061"])
            self.assertEqual(rc, 0)
            self.assertEqual(bl.load(b)["v@x"].asns, {14061})
            # missing args -> usage error
            self.assertEqual(
                cli.main(["baselines", "confirm",
                          "--baselines", str(b)]), 2)


class TestCredentials(unittest.TestCase):
    CFG = {"tenant": "t-1", "client_id": "app-1"}
    THUMB = "AB" * 20

    def _capture_opener(self):
        sent = {}

        class Resp:
            def __init__(self, body):
                self.body = body

            def read(self):
                return self.body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def opener(req, timeout=0):
            sent["url"] = req.full_url
            sent["data"] = dict(urllib.parse.parse_qsl(req.data.decode()))
            return Resp(b'{"access_token": "tok"}')
        return opener, sent

    def test_plaintext_secret_refused(self):
        cfg = dict(self.CFG, client_secret="abc123Q~plaintext")
        with self.assertRaises(collect.CredentialError) as cm:
            collect.auth_params(cfg, env={})
        self.assertIn("secret protect", str(cm.exception))
        self.assertIn("cert new", str(cm.exception))

    def test_no_credential_errors(self):
        with self.assertRaises(collect.CredentialError):
            collect.auth_params(dict(self.CFG), env={})

    def test_env_secret_beats_dpapi_blob(self):
        cfg = dict(self.CFG, client_secret_dpapi="not-a-real-blob")
        p = collect.auth_params(cfg, env={collect.SECRET_ENV: "from-env"})
        self.assertEqual(p, {"client_secret": "from-env"})

    def test_cert_assertion_no_secret_sent(self):
        """Cert path posts a signed JWT assertion and never a
        client_secret, even if a stale one is still in the config."""
        calls = []

        def runner(args):
            calls.append(args[-1])
            return 0, base64.b64encode(b"sig-bytes").decode() + "\n", ""
        cfg = dict(self.CFG, cert_thumbprint=self.THUMB,
                   client_secret="stale")
        opener, sent = self._capture_opener()
        tok = collect.get_token(cfg, opener=opener, env={}, runner=runner)
        self.assertEqual(tok, "tok")
        self.assertNotIn("client_secret", sent["data"])
        self.assertEqual(sent["data"]["client_assertion_type"],
                         "urn:ietf:params:oauth:client-assertion-type:"
                         "jwt-bearer")
        h, c, s = sent["data"]["client_assertion"].split(".")
        pad = lambda x: x + "=" * (-len(x) % 4)
        header = json.loads(base64.urlsafe_b64decode(pad(h)))
        claims = json.loads(base64.urlsafe_b64decode(pad(c)))
        self.assertEqual(header["alg"], "RS256")
        self.assertEqual(base64.urlsafe_b64decode(pad(header["x5t"])),
                         bytes.fromhex(self.THUMB))
        self.assertEqual(claims["aud"], "https://login.microsoftonline.com"
                         "/t-1/oauth2/v2.0/token")
        self.assertEqual(claims["iss"], "app-1")
        self.assertEqual(claims["sub"], "app-1")
        self.assertLessEqual(claims["exp"] - claims["iat"], 600)
        self.assertEqual(base64.urlsafe_b64decode(pad(s)), b"sig-bytes")
        self.assertIn(f"Cert:\\CurrentUser\\My\\{self.THUMB}", calls[0])

    def test_cert_thumbprint_validated(self):
        """Thumbprint/store are interpolated into PowerShell - reject
        anything that isn't 40 hex chars / a known store."""
        for bad in ({"cert_thumbprint": "AB';calc;'"},
                    {"cert_thumbprint": self.THUMB,
                     "cert_store": "CurrentUser';calc"}):
            with self.assertRaises(collect.CredentialError):
                collect.client_assertion(dict(self.CFG, **bad),
                                         runner=lambda a: (0, "", ""))

    def test_cert_sign_failure_surfaces(self):
        cfg = dict(self.CFG, cert_thumbprint=self.THUMB)
        with self.assertRaises(collect.CredentialError) as cm:
            collect.client_assertion(
                cfg, runner=lambda a: (1, "", "Cannot find path"))
        self.assertIn("Cannot find path", str(cm.exception))

    def _poll_env(self, cfg, expiry_s=None):
        """Fake runner answering cert_status + signing; fake opener
        answering the token POST and empty paged GETs."""
        td = tempfile.TemporaryDirectory()
        (Path(td.name) / "graph.json").write_text(json.dumps(cfg))

        def runner(args):
            script = args[-1]
            if "ToUnixTimeSeconds" in script:
                if expiry_s is None:
                    return 1, "", "Cannot find path"
                return 0, str(int(time.time()) + expiry_s) + "\n", ""
            return 0, base64.b64encode(b"sig").decode() + "\n", ""

        class Resp:
            def __init__(self, b):
                self.b = b

            def read(self):
                return self.b

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def opener(req, timeout=0):
            if req.data:
                return Resp(b'{"access_token": "t"}')
            return Resp(b'{"value": []}')
        env = {"TOKENREPLAY_HOME": td.name}
        return td, env, runner, opener

    def test_poll_expired_cert_refuses_empty(self):
        """Expired cert -> poll raises instead of reporting a quiet
        tenant on a broken credential."""
        cfg = dict(self.CFG, cert_thumbprint=self.THUMB)
        td, env, runner, opener = self._poll_env(cfg, expiry_s=-60)
        with td:
            with self.assertRaises(collect.CredentialError) as cm:
                collect.poll(env=env, opener=opener, runner=runner)
            self.assertIn("EXPIRED", str(cm.exception))
            # and the watermark was never written - nothing pretends ran
            self.assertFalse((Path(td.name) / "watermark.json").exists())

    def test_poll_cert_expiry_warns_30d(self):
        cfg = dict(self.CFG, cert_thumbprint=self.THUMB)
        td, env, runner, opener = self._poll_env(cfg,
                                                 expiry_s=10 * 86400)
        with td:
            s, a, warns = collect.poll(env=env, opener=opener,
                                       runner=runner)
        self.assertIn("expires in 10d", warns[0])
        td2, env2, runner2, opener2 = self._poll_env(
            cfg, expiry_s=200 * 86400)
        with td2:
            _, _, warns2 = collect.poll(env=env2, opener=opener2,
                                        runner=runner2)
        self.assertEqual(warns2, [])

    def test_poll_missing_cert_errors(self):
        cfg = dict(self.CFG, cert_thumbprint=self.THUMB)
        td, env, runner, opener = self._poll_env(cfg, expiry_s=None)
        with td:
            with self.assertRaises(collect.CredentialError):
                collect.poll(env=env, opener=opener, runner=runner)

    def test_poll_secret_config_skips_cert_check(self):
        cfg = dict(self.CFG)
        td, env, runner, opener = self._poll_env(cfg)
        env[collect.SECRET_ENV] = "s3"
        with td:
            s, a, warns = collect.poll(env=env, opener=opener,
                                       runner=runner)
        self.assertEqual(warns, [])

    @unittest.skipUnless(sys.platform == "win32", "DPAPI is Windows-only")
    def test_dpapi_roundtrip_and_migration(self):
        blob = collect.dpapi_protect("s3cret-Q~value")
        self.assertNotIn("s3cret", base64.b64decode(blob).decode(
            "latin-1"))
        self.assertEqual(collect.dpapi_unprotect(blob), "s3cret-Q~value")
        with tempfile.TemporaryDirectory() as td:
            env = {"TOKENREPLAY_HOME": td}
            (Path(td) / "graph.json").write_text(json.dumps(
                dict(self.CFG, client_secret="s3cret-Q~value")))
            with mock.patch.dict(os.environ, env):
                self.assertEqual(cli.main(["secret", "protect"]), 0)
            cfg = json.loads((Path(td) / "graph.json").read_text())
            self.assertNotIn("client_secret", cfg)
            self.assertNotIn("s3cret", (Path(td) / "graph.json")
                             .read_text())
            self.assertEqual(collect.auth_params(cfg, env={}),
                             {"client_secret": "s3cret-Q~value"})


if __name__ == "__main__":
    unittest.main()
