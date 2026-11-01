#!/usr/bin/env python3
"""Synthetic end-to-end demo: an orchestrator delegates narrowed authority
to a worker agent, the worker exercises it, and a tampered token is rejected.
All keys and agents are fictional."""

import cap_token as ct

DEMO_KEY = b"demo-only-not-a-real-secret"
NOW = 1_700_000_000

print("1. Orchestrator mints a root token (calendar:* and email:read, 1 hour)")
root = ct.mint(DEMO_KEY, "orchestrator", ["calendar:*", "email:read"],
               token_id="demo-1", issued_at=NOW, expires_at=NOW + 3600)
print("   " + root[:64] + "...")

print("2. Orchestrator attenuates it for worker-1: read-only calendar, 5 min")
worker = ct.attenuate(root, scopes=["calendar:read"], audience="worker-1",
                      expires_at=NOW + 300)
print("   " + worker[:64] + "...")

print("3. Worker-1 presents it to read the calendar")
info = ct.verify(DEMO_KEY, worker, at=NOW + 60,
                 required_scope="calendar:read", audience="worker-1")
print("   VALID:", info["scopes"], "for", info["audience"],
      "until", info["expires_at"])

print("4. Same token used to read email: rejected (scope was narrowed away)")
try:
    ct.verify(DEMO_KEY, worker, at=NOW + 60, required_scope="email:read")
    print("   BUG: accepted")
except ct.CaveatError as exc:
    print("   REJECTED:", exc)

print("5. Attacker swaps in broader scopes and reuses the signature")
head, payload, sig = worker.split(".")
data = __import__("json").loads(ct._b64d(payload))
data["scopes"] = ["*"]
forgery = "%s.%s.%s" % (head, ct._b64e(ct._canonical(data)), sig)
try:
    ct.verify(DEMO_KEY, forgery, at=NOW + 60)
    print("   BUG: accepted")
except ct.InvalidSignature as exc:
    print("   REJECTED:", exc)

print("6. Right key but wrong agent (worker-2): rejected")
try:
    ct.verify(DEMO_KEY, worker, at=NOW + 60, audience="worker-2")
    print("   BUG: accepted")
except ct.CaveatError as exc:
    print("   REJECTED:", exc)

print("\nDemo complete: valid token accepted, all three attacks rejected.")
