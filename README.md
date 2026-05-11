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

---

## How the model differs from the spec

The model is a faithful but compact abstraction of the deferred-issuance
flow. The simplifications are:

1. **The Authorization Server's role is collapsed into a single
   action `Wallet_Get_AT`.** The full token-request/PAR/authorization-code
   handshake is not modeled because none of it interacts with the
   binding chain we are analyzing. The AT is treated as a signed
   token issued by the AS, which is sufficient for the threat model.
2. **The credential is represented as a single signed object
   `credentialSig(CI, pkH, ltkCI)`.** The format-specific Credential
   Format Profiles (SD-JWT VC, mDL, W3C VCDM, etc., per Appendix B)
   are not distinguished: the binding-integrity property holds at the
   level above the format profile.
3. **Single-credential-per-AT.** The `proofs[]` array (§8.2 of the
   spec) is modeled as one proof per request. Batch issuance
   compatibility for V3 is discussed in the disclosure issue under
   "Limitations of V3" and is left as future work.
4. **Network is fully Dolev–Yao.** TLS and HTTPS protections at the
   transport layer are abstracted away; the application-layer
   request encryption (per §10) is modeled with `penc/3` symbolic
   public-key encryption.

These abstractions are *conservative for the attacker*: any attack
findable in the abstract model is realizable against the concrete
protocol, and any verified property in the abstract model carries
to the concrete protocol modulo the abstractions noted.

---

## Citation

If you use this artifact in academic work, please cite:

```
[Author]. OID4VCI Deferred-Issuance Flow: A Tamarin Formal Analysis.
[Year]. [URL of this repository].
```
