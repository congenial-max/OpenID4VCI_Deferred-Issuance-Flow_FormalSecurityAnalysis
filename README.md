# OpenID4VCI Deferred-Issuance Flow — Formal Security Analysis

Tamarin formal analysis of the [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) deferred-issuance flow (Final, 16 Sept 2025). Verifies a credential-binding substitution attack against the published spec under the threat model documented in §13.4 (Split-Architecture Wallets), evaluates two natural fix attempts that fail and verifies a third fix — binding the Wallet's holder key into the access token via an [RFC 7800](https://datatracker.ietf.org/doc/html/rfc7800) `cnf` claim — that closes the attack structurally.

---

## Threat model

The adversary is a Dolev–Yao adversary (Web Attacker + Network Attacker per §6.1 of the companion document *Security and Trust in the OpenID4VC Ecosystem*) with three additional capabilities:

1. `Reveal_StoredAT(WidA, CI, AT)` — obtains the Wallet's stored access token.
2. `Reveal_DPoPKey(WidA, pkDPoP)` — obtains the Wallet's DPoP private key.
3. `Reveal_TxId(WidA, CI, tid)` — obtains the Wallet's deferred-issuance transaction ID.

These three leaks are jointly explained by **a single attack assumption**: compromise of the Wallet's server-tier authorization state, which §13.4 of the spec already acknowledges as a realistic risk in split-architecture wallet deployments (the standard production pattern in the EUDIW ecosystem and major commercial wallets).

Additionally, the adversary controls a separate Wallet WidB (or has compromised an unrelated wallet) and therefore holds WidB's holder key `(skH_B, pkH_B)` with `WidA ≠ WidB`. This models the cuckoo escalation discussed below.

The adversary does **not** compromise: the Credential Issuer's signing or request-encryption key, the Authorization Server's signing key, or WidA's holder key, response-encryption key, or binding keys.

---

## Configurations evaluated

Four configurations of the deferred-issuance flow are evaluated, labeled both by version (matching the `#ifdef` macro) and by the mechanism each one introduces:

| Config | `#ifdef` macro | Mechanism |
|---|---|---|
| **V0 / baseline** | `-DVULNERABLE` | the published spec, no fix |
| **V1 / bindSig-only** | `-DFIXED` | Wallet commits to a binding key `pkB` at credential-request time; signs `(tid, h(pkE_new))` with `skB` at deferred time |
| **V2 / pkB-in-keyProof** | `-DFIXED_V2` | V1 plus binding `h(pkB)` into the keyProof under `skH` |
| **V3 / AT-bound-pkH** | `-DFIXED_V3` | AS issues access token carrying `pk(skH)` as an [RFC 7800](https://datatracker.ietf.org/doc/html/rfc7800) `cnf` claim; CI verifies request `pkH` against AT-bound `pkH` |

### Verdicts

| Config | C2 (def-time enc swap) | C2′ (cuckoo) | Credential secrecy | Runtime |
|---|---|---|---|---|
| **V0 / baseline** | attack witnessed (26 steps) | (subsumed) | falsified (27 steps) | ~19 s |
| **V1 / bindSig-only** | closed | attack witnessed (43 steps) | falsified¹ | ~32 s |
| **V2 / pkB-in-keyProof** | closed | attack witnessed (47 steps) | falsified (39 steps) | ~64 s |
| **V3 / AT-bound-pkH** | closed (10 steps) | closed (10 steps) | verified (94 steps) | ~13 s |

¹ V1's credential-secrecy lemma `P10_credential_secrecy_fixed` verifies in 113 steps **only** under a same-wallet scoping precondition `WalletGen_HolderKey(Wid, sid, pkH)`. Under the strict unscoped formulation it falsifies analogously to V2.

### What the verdicts mean

- **V0 / baseline** — credential-binding substitution attack is witnessed *and* credential confidentiality (P-10) is falsified. The Dolev–Yao adversary constructs the attack directly from the leaked tokens without any creative reasoning.

- **V1 / bindSig-only** — closes the simpler deferred-time encryption-key substitution. Credential secrecy verifies under same-wallet scoping (113 steps), so V1 is a partial fix, not a total failure. But the cuckoo escalation against V1 succeeds: with `skH_B` available to the adversary, they construct the credential request as if they were a different wallet, commit to their own binding key, and follow through.

- **V2 / pkB-in-keyProof** — **principled negative result**. The added `h(pkB)` binding is anchored at `skH`, which is leaked under the cuckoo threat model. The adversary signs the V2 keyProof committing to their own choice of `pkB`, reducing the added binding to a self-statement under adversary control. This rules out **the entire family of "augment the keyProof payload" fixes**: no payload-level extension can constrain an adversary who holds the signing key. The fix must come from a token minted outside the wallet's signing-key space.

- **V3 / AT-bound-pkH** — both attacks closed structurally. The `c2prime_attack_blocked_v3` lemma discharges in 10 proof steps because the cuckoo trace is **structurally unrepresentable** in the V3 model — Tamarin's unification engine forces the credential request's `pkH` to equal the AT-bound `pkH`, and in the cuckoo trace those are different fresh names, yielding contradiction. Credential secrecy verifies under the strictest formulation (no same-wallet scoping) in 94 steps of exhaustive forgery refutation.

Note that V3's runtime is the **fastest** of all four configurations (~13 s vs ~19/32/64 s for V0/V1/V2). This is not coincidence: V3's structural fix reduces the proof search space dramatically because the constraint is unification-enforced rather than search-enforced.

---

## Reproducibility

### Used

- **Tamarin Prover** version 1.12.0 ([install instructions](https://tamarin-prover.com/manual/master/book/002_installation.html))
- **Maude** version 3.5.1
- POSIX shell

### Running the proofs

Each configuration is selected by the corresponding `#ifdef` macro flag:

Info about terminal commands, runtimes, RAM usage are all at the end of each log file within this repo. 

---

## How the model differs from the spec

The model is a faithful but compact abstraction of the deferred-issuance flow. The simplifications are:

1. **The Authorization Server's role is collapsed into a single action `Wallet_Get_AT`.** The full token-request / PAR / authorization-code handshake is not modeled because none of it interacts with the binding chain we are analyzing. The AT is treated as an unforgeable token issued by the AS, which is sufficient for the threat model.

2. **The credential is represented as a single signed object `credentialSig(CI, pkH, ltkCI)`.** The format-specific Credential Format Profiles (SD-JWT VC, mDL, W3C VCDM, etc., per Appendix B) are not distinguished: the binding-integrity property holds at the level above the format profile.

3. **Single-credential-per-AT.** The `proofs[]` array (§8.2 of the spec) is modeled as one proof per request. Batch issuance compatibility for V3 is discussed in the disclosure issue under "Limitations of V3" and is left as future work.

4. **Network is fully Dolev–Yao.** TLS and HTTPS protections at the transport layer are abstracted away; the application-layer request encryption (per §10) is modeled with `penc/3` symbolic public-key encryption.

### On the conservativeness of these abstractions

Abstractions 1–3 are conservative for the attacker: any attack findable in the abstract model is realizable against the concrete protocol, and any verified property in the abstract model carries to the concrete protocol modulo the abstractions noted.

Abstraction 4 (TLS removal) requires more care. Removing TLS strengthens the adversary, so attacks findable in the TLS-abstracted model are not automatically realizable against the concrete protocol — they would have to not rely on the absence of TLS. For the attacks documented here (C2 and C2′), the adversary's capabilities come from backend-state compromise per §13.4 rather than from network observation of TLS-protected payloads, so the TLS abstraction is conservative for these specific results. Verified properties in the abstract model carry to the concrete protocol unchanged (TLS only adds protection).

---

## Citation

If you use this artifact in academic work, please cite:

```
MURAT SEKMEN. OID4VCI Deferred-Issuance Flow: A Tamarin Formal Analysis.
2026. <https://github.com/congenial-max/OpenID4VCI_Deferred-Issuance-Flow_FormalSecurityAnalysis>
```

A peer-reviewed venue citation will be substituted when the corresponding paper is published.

---

## Contact

For questions about the model or the disclosed attack, please open a GitHub issue or contact sekmenmu20@itu.edu.tr
