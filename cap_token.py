#!/usr/bin/env python3
"""cap_token - macaroon-style capability tokens for agent-to-agent authorization.

Issue, attenuate, and verify scoped bearer tokens between agents. A token is a
JSON payload plus an HMAC-SHA256 signature chain. Anyone holding a token can
attenuate it (add caveats that only narrow it) without the issuer's key; only
the issuer's key verifies the final chain.

Wire format: agct1.<base64url payload>.<base64url signature>

Library usage:
    import cap_token
    tok = cap_token.mint(key=b"k", issuer="orchestrator",
                         scopes=["calendar:*"], expires_at=1893456000)
    tok2 = cap_token.attenuate(tok, scopes=["calendar:read"])
    cap_token.verify(b"k", tok2, required_scope="calendar:read")
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time

VERSION = 1
PREFIX = "agct1"

CAVEAT_EXPIRES_AT = "expires_at"
CAVEAT_NOT_BEFORE = "not_before"
CAVEAT_SCOPES = "scopes"
CAVEAT_AUDIENCE = "audience"


class TokenError(Exception):
    """Base class for token failures."""


class MalformedToken(TokenError):
    """Token cannot be parsed or has invalid structure."""


class InvalidSignature(TokenError):
    """Signature chain does not match the key and payload."""


class CaveatError(TokenError):
    """A caveat fails, or a caveat chain is not monotonically narrowing."""


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    try:
        pad = "=" * (-len(text) % 4)
        return base64.urlsafe_b64decode(text + pad)
    except Exception as exc:
        raise MalformedToken("invalid base64url segment") from exc


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def scope_covers(granted: str, required: str) -> bool:
    """True if granted scope covers required scope.

    Exact match, "*" covers everything, and a trailing ":*" prefix wildcard
    covers any scope under that prefix ("docs:*" covers "docs:read").
    """
    if granted == "*" or granted == required:
        return True
    if granted.endswith(":*"):
        return required.startswith(granted[:-1]) and required != granted[:-1].rstrip(":")
    return False


def scope_subset(narrower, broader) -> bool:
    """True if every scope in narrower is covered by some scope in broader."""
    return all(any(scope_covers(b, n) for b in broader) for n in narrower)


def _check_caveat(cav) -> dict:
    if not isinstance(cav, dict) or "type" not in cav or "value" not in cav:
        raise MalformedToken("caveat must be an object with type and value")
    ctype = cav["type"]
    if ctype in (CAVEAT_EXPIRES_AT, CAVEAT_NOT_BEFORE):
        if not isinstance(cav["value"], (int, float)):
            raise MalformedToken("time caveat value must be a unix timestamp")
    elif ctype == CAVEAT_SCOPES:
        if (not isinstance(cav["value"], list)
                or not all(isinstance(s, str) for s in cav["value"])):
            raise MalformedToken("scopes caveat value must be a list of strings")
    elif ctype == CAVEAT_AUDIENCE:
        if not isinstance(cav["value"], str):
            raise MalformedToken("audience caveat value must be a string")
    else:
        raise MalformedToken("unknown caveat type: %r" % ctype)
    return {"type": ctype, "value": cav["value"]}


def mint(key: bytes, issuer: str, scopes, token_id: str = None,
         audience: str = "*", issued_at: int = None,
         expires_at: int = None, not_before: int = None) -> str:
    """Mint a root token. Key must be the issuer's secret."""
    if not key:
        raise ValueError("key must be non-empty")
    if not issuer or not isinstance(issuer, str):
        raise ValueError("issuer must be a non-empty string")
    if not scopes or not all(isinstance(s, str) and s for s in scopes):
        raise ValueError("scopes must be a non-empty list of non-empty strings")
    issued_at = int(time.time()) if issued_at is None else int(issued_at)
    token_id = token_id or _b64e(hashlib.sha256(
        _canonical([issuer, scopes, issued_at, time.time_ns()])).digest()[:12])
    caveats = []
    if not_before is not None:
        caveats.append({"type": CAVEAT_NOT_BEFORE, "value": int(not_before)})
    if expires_at is not None:
        caveats.append({"type": CAVEAT_EXPIRES_AT, "value": int(expires_at)})
    payload = {
        "v": VERSION,
        "id": token_id,
        "issuer": issuer,
        "audience": audience,
        "scopes": list(scopes),
        "issued_at": issued_at,
        "caveats": caveats,
    }
    return _seal(key, payload, len(caveats))


def _seal(key: bytes, payload: dict, caveats_signed: int) -> str:
    """Serialize payload and sign: base over head, then one link per caveat."""
    head = {k: v for k, v in payload.items() if k != "caveats"}
    sig = _hmac(key, _canonical(head))
    for cav in payload["caveats"]:
        sig = _hmac(sig, _canonical(cav))
    return "%s.%s.%s" % (PREFIX, _b64e(_canonical(payload)), _b64e(sig))


def parse(token: str) -> dict:
    """Parse without verifying. Raises MalformedToken on bad structure."""
    if not isinstance(token, str):
        raise MalformedToken("token must be a string")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != PREFIX:
        raise MalformedToken("token must have form %s.<payload>.<signature>" % PREFIX)
    try:
        payload = json.loads(_b64d(parts[1]))
    except MalformedToken:
        raise
    except Exception as exc:
        raise MalformedToken("payload is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise MalformedToken("payload must be a JSON object")
    if payload.get("v") != VERSION:
        raise MalformedToken("unsupported token version: %r" % payload.get("v"))
    for field in ("id", "issuer", "audience", "scopes", "issued_at", "caveats"):
        if field not in payload:
            raise MalformedToken("payload missing field: %s" % field)
    if not isinstance(payload["scopes"], list) or not payload["scopes"]:
        raise MalformedToken("payload scopes must be a non-empty list")
    if not isinstance(payload["caveats"], list):
        raise MalformedToken("payload caveats must be a list")
    payload["caveats"] = [_check_caveat(c) for c in payload["caveats"]]
    payload["_sig"] = parts[2]
    return payload


def _expected_sig(key: bytes, payload: dict) -> bytes:
    head = {k: v for k, v in payload.items()
            if k not in ("caveats", "_sig")}
    sig = _hmac(key, _canonical(head))
    for cav in payload["caveats"]:
        sig = _hmac(sig, _canonical(cav))
    return sig


def effective_constraints(payload: dict):
    """Fold caveats into effective (not_before, expires_at, scopes, audience).

    Enforces monotonic narrowing: each time caveat can only tighten the
    window, each scopes caveat must be a subset of the currently effective
    scopes, each audience caveat must match or narrow the current audience.
    Raises CaveatError when a caveat widens the token.
    """
    not_before = None
    expires_at = None
    scopes = list(payload["scopes"])
    audience = payload["audience"]
    for cav in payload["caveats"]:
        ctype, value = cav["type"], cav["value"]
        if ctype == CAVEAT_NOT_BEFORE:
            if not_before is not None and value < not_before:
                raise CaveatError("not_before caveat moves validity earlier")
            not_before = value if not_before is None else max(not_before, value)
        elif ctype == CAVEAT_EXPIRES_AT:
            if expires_at is not None and value > expires_at:
                raise CaveatError("expires_at caveat extends validity")
            expires_at = value if expires_at is None else min(expires_at, value)
        elif ctype == CAVEAT_SCOPES:
            if not scope_subset(value, scopes):
                raise CaveatError("scopes caveat is not a subset of current scopes")
            scopes = list(value)
        elif ctype == CAVEAT_AUDIENCE:
            if audience != "*" and value != audience:
                raise CaveatError("audience caveat does not narrow current audience")
            audience = value
    return not_before, expires_at, scopes, audience


def verify(key: bytes, token: str, at: int = None,
           required_scope: str = None, audience: str = None) -> dict:
    """Verify a token. Returns effective constraints on success.

    Raises MalformedToken, InvalidSignature, or CaveatError on failure.
    """
    at = int(time.time()) if at is None else int(at)
    payload = parse(token)
    expected = _expected_sig(key, payload)
    if not hmac.compare_digest(expected, _b64d(payload["_sig"])):
        raise InvalidSignature("signature chain does not match key and payload")
    not_before, expires_at, scopes, eff_aud = effective_constraints(payload)
    if expires_at is not None and at >= expires_at:
        raise CaveatError("token expired")
    if not_before is not None and at < not_before:
        raise CaveatError("token not yet valid")
    if required_scope is not None and not any(
            scope_covers(s, required_scope) for s in scopes):
        raise CaveatError("required scope %r not covered by effective scopes"
                          % required_scope)
    if audience is not None and eff_aud not in ("*", audience):
        raise CaveatError("token audience %r does not match %r"
                          % (eff_aud, audience))
    return {
        "id": payload["id"],
        "issuer": payload["issuer"],
        "audience": eff_aud,
        "scopes": scopes,
        "issued_at": payload["issued_at"],
        "not_before": not_before,
        "expires_at": expires_at,
    }


def attenuate(token: str, scopes=None, expires_at: int = None,
              not_before: int = None, audience: str = None) -> str:
    """Return a new token with extra caveats. No key required.

    Caveats can only narrow the token; verification rejects any widening,
    and the signature chain commits to every caveat ever added. The chain is
    extended by hashing the previous full signature, so the holder never
    needs the issuer key.
    """
    payload = parse(token)
    old_caveats = payload["caveats"]
    new_caveats = list(old_caveats)
    if scopes is not None:
        new_caveats.append({"type": CAVEAT_SCOPES, "value": list(scopes)})
    if audience is not None:
        new_caveats.append({"type": CAVEAT_AUDIENCE, "value": audience})
    if not_before is not None:
        new_caveats.append({"type": CAVEAT_NOT_BEFORE, "value": int(not_before)})
    if expires_at is not None:
        new_caveats.append({"type": CAVEAT_EXPIRES_AT, "value": int(expires_at)})
    if len(new_caveats) == len(old_caveats):
        raise ValueError("attenuate needs at least one new caveat")
    payload["caveats"] = new_caveats
    prev_sig = _b64d(payload["_sig"])
    sig = prev_sig
    for cav in new_caveats[len(old_caveats):]:
        sig = _hmac(sig, _canonical(cav))
    del payload["_sig"]
    return "%s.%s.%s" % (PREFIX, _b64e(_canonical(payload)), _b64e(sig))


def _read_token_arg(args) -> str:
    if args.token == "-":
        return sys.stdin.read().strip()
    return args.token


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="cap_token",
        description="Issue, attenuate, and verify agent capability tokens.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_mint = sub.add_parser("mint", help="issue a root token")
    p_mint.add_argument("--key", required=True, help="issuer secret key")
    p_mint.add_argument("--issuer", required=True)
    p_mint.add_argument("--id", dest="token_id", default=None)
    p_mint.add_argument("--scope", dest="scopes", action="append",
                        required=True, help="granted scope; repeatable")
    p_mint.add_argument("--audience", default="*")
    p_mint.add_argument("--expires-at", type=int, default=None,
                        help="unix timestamp")
    p_mint.add_argument("--expires-in", type=int, default=None,
                        help="seconds from now")
    p_mint.add_argument("--not-before", type=int, default=None,
                        help="unix timestamp")

    p_att = sub.add_parser("attenuate",
                           help="narrow a token; no key needed")
    p_att.add_argument("--token", required=True, help="token, or - for stdin")
    p_att.add_argument("--scope", dest="scopes", action="append",
                       default=None, help="narrowed scopes; repeatable")
    p_att.add_argument("--audience", default=None)
    p_att.add_argument("--expires-at", type=int, default=None)
    p_att.add_argument("--not-before", type=int, default=None)

    p_ver = sub.add_parser("verify", help="verify a token with the key")
    p_ver.add_argument("--key", required=True)
    p_ver.add_argument("--token", required=True, help="token, or - for stdin")
    p_ver.add_argument("--scope", dest="required_scope", default=None,
                       help="scope the caller intends to exercise")
    p_ver.add_argument("--audience", default=None,
                       help="audience the caller expects")
    p_ver.add_argument("--at", type=int, default=None,
                       help="unix timestamp to verify against (default: now)")

    p_ins = sub.add_parser("inspect", help="print payload WITHOUT verifying")
    p_ins.add_argument("--token", required=True, help="token, or - for stdin")

    args = parser.parse_args(argv)

    if args.command == "mint":
        expires_at = args.expires_at
        if expires_at is None and args.expires_in is not None:
            expires_at = int(time.time()) + args.expires_in
        token = mint(args.key.encode("utf-8"), args.issuer, args.scopes,
                     token_id=args.token_id, audience=args.audience,
                     expires_at=expires_at, not_before=args.not_before)
        print(token)
        return 0

    if args.command == "attenuate":
        try:
            print(attenuate(_read_token_arg(args), scopes=args.scopes,
                            expires_at=args.expires_at,
                            not_before=args.not_before,
                            audience=args.audience))
            return 0
        except (TokenError, ValueError) as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 2

    if args.command == "verify":
        try:
            info = verify(args.key.encode("utf-8"), _read_token_arg(args),
                          at=args.at, required_scope=args.required_scope,
                          audience=args.audience)
        except TokenError as exc:
            print("INVALID: %s" % exc, file=sys.stderr)
            return 1
        print("VALID " + json.dumps(info, sort_keys=True))
        return 0

    if args.command == "inspect":
        try:
            payload = parse(_read_token_arg(args))
        except TokenError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 2
        payload.pop("_sig", None)
        print(json.dumps(payload, indent=2, sort_keys=True))
        print("(unverified: inspect does not check the signature)",
              file=sys.stderr)
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
