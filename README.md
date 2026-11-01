# agent-cap-token

Macaroon-style capability tokens for agent-to-agent authorization, in
dependency-free Python.

When one AI agent delegates work to another, the sub-agent should get less
authority than the orchestrator holds, not a copy of it. `agent-cap-token`
gives you bearer tokens that an issuer mints with a shared secret and any
holder can *attenuate* (narrow) before passing on, without knowing the
secret. Verification needs only the secret and the token, fully offline.

## How it works

A token is a JSON payload plus an HMAC-SHA256 signature chain:

```
agct1.<base64url payload>.<base64url signature>
```

- The issuer signs the token head (id, issuer, audience, scopes, issued_at)
  with its secret key.
- Each caveat (an added restriction) extends the chain:
  `sig = HMAC(prev_sig, caveat)`. Anyone can add caveats; nobody can remove,
  reorder, or rewrite them without the key.
- Caveat types: `expires_at`, `not_before`, `scopes` (must be a subset of
  the currently effective scopes), and `audience` (must narrow, not change).
- Scope matching is simple: exact strings, `*` covers everything, and a
  trailing `:*` wildcard covers its prefix (`calendar:*` covers
  `calendar:read`).

## Quick start

```bash
# Orchestrator mints a root token
python3 cap_token.py mint --key "$SHARED_SECRET" --issuer orchestrator \
  --scope 'calendar:*' --scope 'email:read' --expires-in 3600 > root.tok

# Narrow it for a worker: read-only calendar, 5 minutes, worker-1 only.
# No key needed to attenuate.
python3 cap_token.py attenuate --token "$(cat root.tok)" \
  --scope 'calendar:read' --audience worker-1 --expires-at 1893456300 > worker.tok

# The service verifies with the shared secret
python3 cap_token.py verify --key "$SHARED_SECRET" --token "$(cat worker.tok)" \
  --scope calendar:read --audience worker-1
# VALID {"audience": "worker-1", "scopes": ["calendar:read"], ...}
```

Exit codes: `0` valid, `1` invalid token, `2` usage error.

Library use:

```python
import cap_token
tok = cap_token.mint(b"secret", "orchestrator", ["calendar:*"], expires_at=1893456000)
tok2 = cap_token.attenuate(tok, scopes=["calendar:read"], audience="worker-1")
info = cap_token.verify(b"secret", tok2, required_scope="calendar:read")
```

`python3 demo.py` runs a synthetic scenario: mint, attenuate, verify, and
three rejected attacks (scope widening, payload forgery, wrong audience).

## Limits

This is a small building block, not an identity system. Know what it does
not give you:

- **Symmetric keys.** Verification needs the issuer's secret, so any service
  that can verify a token can also mint one. There is no public-key
  signature and no third-party verification.
- **Bearer tokens.** Anyone holding a valid token can use it until it
  expires. There is no replay protection and no binding to a channel or
  sender.
- **No revocation.** A minted token stays valid until its expiry. Revoking
  one early needs a denylist your verifier checks, which this does not
  provide.
- **Proof of key possession, not identity.** A valid token shows the issuer
  knew the secret when minting. It says nothing about who operates the
  agent, and it is not decentralized or anchored anywhere external.
- **Coarse scopes.** Scope patterns are string prefixes, not a policy
  engine. There are no roles, conditions, or per-resource rules beyond the
  strings you choose.
- Unknown caveat types are rejected at parse time rather than skipped, so
  tokens from a newer version fail closed here.

## Tests

```bash
python3 -m unittest test_cap_token -v
```

41 tests cover mint/verify round trips, tamper and forgery rejection, time
windows, scope narrowing and widening, audience narrowing, multi-step
attenuation chains, malformed input, and the CLI.

## License

MIT
