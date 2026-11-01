import json
import subprocess
import sys
import unittest

import cap_token as ct

KEY = b"test-secret-key"
T0 = 1_700_000_000


def root(**kw):
    args = dict(key=KEY, issuer="orchestrator", scopes=["calendar:*", "email:read"],
                token_id="tok-1", issued_at=T0)
    args.update(kw)
    return ct.mint(**args)


class MintVerifyTests(unittest.TestCase):
    def test_roundtrip(self):
        info = ct.verify(KEY, root(), at=T0 + 10)
        self.assertEqual(info["issuer"], "orchestrator")
        self.assertEqual(info["scopes"], ["calendar:*", "email:read"])
        self.assertEqual(info["audience"], "*")

    def test_deterministic_serialization(self):
        self.assertEqual(root(), root())

    def test_distinct_ids_when_unspecified(self):
        a = ct.mint(KEY, "orchestrator", ["x"], issued_at=T0)
        b = ct.mint(KEY, "orchestrator", ["x"], issued_at=T0)
        self.assertNotEqual(a, b)

    def test_mint_rejects_empty_key(self):
        with self.assertRaises(ValueError):
            ct.mint(b"", "orchestrator", ["x"])

    def test_mint_rejects_empty_scopes(self):
        with self.assertRaises(ValueError):
            ct.mint(KEY, "orchestrator", [])

    def test_wrong_key_rejected(self):
        with self.assertRaises(ct.InvalidSignature):
            ct.verify(b"other-key", root(), at=T0)

    def test_tampered_payload_rejected(self):
        tok = root()
        head, payload, sig = tok.split(".")
        data = json.loads(ct._b64d(payload))
        data["scopes"] = ["*"]
        tampered = "%s.%s.%s" % (head, ct._b64e(ct._canonical(data)), sig)
        with self.assertRaises(ct.InvalidSignature):
            ct.verify(KEY, tampered, at=T0)

    def test_tampered_signature_rejected(self):
        tok = root()
        head, payload, sig = tok.split(".")
        bad = "%s.%s.%s" % (head, payload, ct._b64e(b"\x00" * 32))
        with self.assertRaises(ct.InvalidSignature):
            ct.verify(KEY, bad, at=T0)

    def test_caveat_reordering_rejected(self):
        tok = ct.attenuate(root(), scopes=["calendar:read"], expires_at=T0 + 600)
        head, payload, sig = tok.split(".")
        data = json.loads(ct._b64d(payload))
        data["caveats"] = list(reversed(data["caveats"]))
        reordered = "%s.%s.%s" % (head, ct._b64e(ct._canonical(data)), sig)
        with self.assertRaises(ct.InvalidSignature):
            ct.verify(KEY, reordered, at=T0)


class TimeTests(unittest.TestCase):
    def test_expired_rejected(self):
        tok = root(expires_at=T0 + 100)
        with self.assertRaises(ct.CaveatError):
            ct.verify(KEY, tok, at=T0 + 100)

    def test_valid_just_before_expiry(self):
        tok = root(expires_at=T0 + 100)
        ct.verify(KEY, tok, at=T0 + 99)

    def test_not_before_future_rejected(self):
        tok = root(not_before=T0 + 500)
        with self.assertRaises(ct.CaveatError):
            ct.verify(KEY, tok, at=T0)

    def test_not_before_reached_ok(self):
        tok = root(not_before=T0 + 500)
        ct.verify(KEY, tok, at=T0 + 500)


class ScopeTests(unittest.TestCase):
    def test_required_scope_covered(self):
        ct.verify(KEY, root(), at=T0, required_scope="calendar:write")

    def test_required_scope_missing_rejected(self):
        with self.assertRaises(ct.CaveatError):
            ct.verify(KEY, root(), at=T0, required_scope="email:write")

    def test_wildcard_covers(self):
        self.assertTrue(ct.scope_covers("docs:*", "docs:read"))

    def test_wildcard_does_not_cover_other_prefix(self):
        self.assertFalse(ct.scope_covers("docs:*", "email:read"))
        self.assertFalse(ct.scope_covers("docs:*", "docs"))

    def test_star_covers_everything(self):
        self.assertTrue(ct.scope_covers("*", "anything:at:all"))

    def test_scope_subset(self):
        self.assertTrue(ct.scope_subset(["calendar:read"], ["calendar:*"]))
        self.assertFalse(ct.scope_subset(["calendar:*"], ["calendar:read"]))


class AttenuationTests(unittest.TestCase):
    def test_narrow_scopes_ok(self):
        tok = ct.attenuate(root(), scopes=["calendar:read"])
        info = ct.verify(KEY, tok, at=T0, required_scope="calendar:read")
        self.assertEqual(info["scopes"], ["calendar:read"])

    def test_narrowed_token_loses_other_scope(self):
        tok = ct.attenuate(root(), scopes=["calendar:read"])
        with self.assertRaises(ct.CaveatError):
            ct.verify(KEY, tok, at=T0, required_scope="email:read")

    def test_widening_scopes_rejected(self):
        tok = ct.attenuate(root(scopes=["calendar:read"]),
                           scopes=["calendar:*", "email:read"])
        with self.assertRaises(ct.CaveatError):
            ct.verify(KEY, tok, at=T0)

    def test_earlier_expiry_ok(self):
        tok = ct.attenuate(root(expires_at=T0 + 600), expires_at=T0 + 300)
        ct.verify(KEY, tok, at=T0 + 299)
        with self.assertRaises(ct.CaveatError):
            ct.verify(KEY, tok, at=T0 + 300)

    def test_later_expiry_rejected(self):
        tok = ct.attenuate(root(expires_at=T0 + 300), expires_at=T0 + 600)
        with self.assertRaises(ct.CaveatError):
            ct.verify(KEY, tok, at=T0)

    def test_earlier_not_before_rejected(self):
        tok = ct.attenuate(root(not_before=T0 + 500), not_before=T0 + 100)
        with self.assertRaises(ct.CaveatError):
            ct.verify(KEY, tok, at=T0 + 400)

    def test_audience_narrowing_ok(self):
        tok = ct.attenuate(root(), audience="worker-1")
        ct.verify(KEY, tok, at=T0, audience="worker-1")
        with self.assertRaises(ct.CaveatError):
            ct.verify(KEY, tok, at=T0, audience="worker-2")

    def test_conflicting_audience_rejected(self):
        tok = ct.attenuate(root(audience="worker-1"), audience="worker-2")
        with self.assertRaises(ct.CaveatError):
            ct.verify(KEY, tok, at=T0)

    def test_double_attenuation_chain(self):
        tok = ct.attenuate(root(expires_at=T0 + 900),
                           scopes=["calendar:read"], audience="w-1")
        tok2 = ct.attenuate(tok, expires_at=T0 + 60)
        info = ct.verify(KEY, tok2, at=T0 + 30, required_scope="calendar:read",
                         audience="w-1")
        self.assertEqual(info["expires_at"], T0 + 60)

    def test_attenuate_needs_a_caveat(self):
        with self.assertRaises(ValueError):
            ct.attenuate(root())


class ParseTests(unittest.TestCase):
    def _bad(self, tok):
        with self.assertRaises(ct.MalformedToken):
            ct.parse(tok)

    def test_bad_prefix(self):
        self._bad("zzzz." + root().split(".", 1)[1])

    def test_wrong_segment_count(self):
        self._bad("agct1.onlyone")

    def test_bad_base64(self):
        self._bad("agct1.%%%.sig")

    def test_non_json_payload(self):
        self._bad("agct1." + ct._b64e(b"not json") + ".sig")

    def test_wrong_version(self):
        payload = json.loads(ct._b64d(root().split(".")[1]))
        payload["v"] = 99
        self._bad("agct1." + ct._b64e(ct._canonical(payload)) + ".sig")

    def test_missing_field(self):
        payload = json.loads(ct._b64d(root().split(".")[1]))
        del payload["issuer"]
        self._bad("agct1." + ct._b64e(ct._canonical(payload)) + ".sig")

    def test_empty_scopes(self):
        payload = json.loads(ct._b64d(root().split(".")[1]))
        payload["scopes"] = []
        self._bad("agct1." + ct._b64e(ct._canonical(payload)) + ".sig")

    def test_unknown_caveat_type(self):
        payload = json.loads(ct._b64d(root().split(".")[1]))
        payload["caveats"].append({"type": "magic", "value": True})
        self._bad("agct1." + ct._b64e(ct._canonical(payload)) + ".sig")


class CliTests(unittest.TestCase):
    def run_cli(self, *args, stdin=None):
        return subprocess.run([sys.executable, "cap_token.py", *args],
                              capture_output=True, text=True, input=stdin)

    def test_mint_verify_roundtrip(self):
        mint = self.run_cli("mint", "--key", "k", "--issuer", "orch",
                            "--scope", "calendar:*", "--id", "c1")
        self.assertEqual(mint.returncode, 0, mint.stderr)
        tok = mint.stdout.strip()
        ver = self.run_cli("verify", "--key", "k", "--token", tok,
                           "--scope", "calendar:read")
        self.assertEqual(ver.returncode, 0, ver.stderr)
        self.assertIn("VALID", ver.stdout)

    def test_verify_wrong_key_exit_1(self):
        mint = self.run_cli("mint", "--key", "k", "--issuer", "orch",
                            "--scope", "x")
        ver = self.run_cli("verify", "--key", "nope",
                           "--token", mint.stdout.strip())
        self.assertEqual(ver.returncode, 1)
        self.assertIn("INVALID", ver.stderr)

    def test_attenuate_via_stdin(self):
        mint = self.run_cli("mint", "--key", "k", "--issuer", "orch",
                            "--scope", "calendar:*", "--id", "c2")
        att = self.run_cli("attenuate", "--token", "-",
                           "--scope", "calendar:read",
                           stdin=mint.stdout.strip())
        self.assertEqual(att.returncode, 0, att.stderr)
        ver = self.run_cli("verify", "--key", "k",
                           "--token", att.stdout.strip(),
                           "--scope", "calendar:read")
        self.assertEqual(ver.returncode, 0, ver.stderr)

    def test_inspect_prints_payload_and_warning(self):
        mint = self.run_cli("mint", "--key", "k", "--issuer", "orch",
                            "--scope", "x", "--id", "c3")
        ins = self.run_cli("inspect", "--token", mint.stdout.strip())
        self.assertEqual(ins.returncode, 0, ins.stderr)
        self.assertIn('"issuer": "orch"', ins.stdout)
        self.assertIn("unverified", ins.stderr)


if __name__ == "__main__":
    unittest.main()
