# OpenID4VCI_Deferred-Issuance-Flow_FormalSecurityAnalysis
Tamarin formal analysis of the OpenID4VCI 1.0 deferred-issuance flow. Verifies a credential-binding substitution attack against the published spec under device-compromise, evaluates two failed fix attempts, and verifies a third fix (RFC 7800 cnf-bound holder key in the access token) that closes the attack.


## Configurations evaluated

We evaluate four configurations of the deferred-issuance flow,
labeled both by version (matching the `#ifdef` macro) and by the
mechanism each one introduces:

| Config | `#ifdef` macro | Mechanism |
|---|---|---|
| **V0 / baseline** | `-DVULNERABLE` | the published spec, no fix |
| **V1 / bindSig-only** | `-DFIXED` | Wallet commits to a binding key `pkB` at credential-request time; signs `(tid, h(pkE_new))` with `skB` at deferred time |
| **V2 / pkB-in-keyProof** | `-DFIXED_V2` | V1 plus binding `h(pkB)` into the keyProof under `skH` |
| **V3 / AT-bound-pkH** | `-DFIXED_V3` | AS issues access token carrying `pk(skH)` as an [RFC 7800] `cnf` claim; CI verifies request `pkH` against AT-bound `pkH` |

[RFC 7800]: https://datatracker.ietf.org/doc/html/rfc7800

The verdicts:

- **V0 / baseline** — credential-binding substitution is witnessed in
  Tamarin (attack exists).
- **V1 / bindSig-only** — closes the simpler deferred-time
  encryption-key substitution but the cuckoo escalation still
  succeeds.
- **V2 / pkB-in-keyProof** — also fails: the added binding is anchored
  at `skH`, which is leaked under the cuckoo threat model.
- **V3 / AT-bound-pkH** — both attacks closed structurally; the
  no-attack lemma discharges in 10 proof steps because the cuckoo
  trace is unrepresentable in the V3 model. Credential secrecy
  verifies under the strictest formulation in 94 steps of exhaustive
  forgery refutation.
