# OpenID4VCI Deferred-Issuance Flow — Formal Security Analysis

Tamarin formal analysis of the [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) deferred-issuance flow (Final, 16 Sept 2025). Verifies two related credential-binding substitution attacks against the published spec under the threat model documented in §13.4 (Split-Architecture Wallets) — an encryption-key substitution (**C2**) and a holder-key substitution / "cuckoo" (**C2′**) — evaluates two intermediate configurations (one that closes C2 but not the cuckoo, and one whose attempt to close the cuckoo fails for a non-obvious reason), and verifies a configuration that closes both: a per-request transaction-ID binding signature (closing C2) together with an [RFC 7800](https://datatracker.ietf.org/doc/html/rfc7800) `cnf` claim binding the Wallet's holder key into the access token (closing C2′).

---

## Threat model

The adversary is a Dolev–Yao adversary (Web Attacker + Network Attacker per §6.1 of the companion document *Security and Trust in the OpenID4VC Ecosystem*) with three additional capabilities:

1. `Reveal_StoredAT(WidA, CI, AT)` — obtains the Wallet's stored access token.
2. `Reveal_DPoPKey(WidA, pkDPoP)` — obtains the Wallet's DPoP private key.
3. `Reveal_TxId(WidA, CI, tid)` — obtains the Wallet's deferred-issuance transaction ID.

These three leaks are jointly explained by **a single attack assumption**: compromise of the Wallet's server-tier authorization state, which §13.4 of the spec acknowledges as a realistic risk for split-architecture wallets (a native client plus a provider-operated backend). We model this trust boundary explicitly: authorization-tier state (the AT, DPoP private key, and pending transaction ID) resides in the backend and is assumed compromised; the holder signing key and the per-credential keys introduced by the fixes reside in the device's secure element or native client and are assumed **not** compromised. We do not assert how common this deployment pattern is — we rely only on §13.4 establishing that it is a recognized one.

Additionally, the adversary controls a separate Wallet WidB (or has compromised an unrelated wallet) and therefore holds WidB's holder key `(skH_B, pkH_B)` with `WidA ≠ WidB`. This models the cuckoo escalation (C2′) discussed below.

The adversary does **not** compromise: the Credential Issuer's signing or request-encryption key, the Authorization Server's signing key, or WidA's holder key, response-encryption key, or binding keys. (These last are the keys assumed to live in the device-side trust domain rather than the compromised backend; the fixes derive their effectiveness from this boundary.)

---

## Configurations evaluated

Four configurations of the deferred-issuance flow are evaluated, labeled both by version (matching the `#ifdef` macro) and by the mechanism each one introduces:

| Config | `#ifdef` macro | Mechanism |
|---|---|---|
| **V0 / baseline** | `-DVULNERABLE` | the published spec, no fix |
| **V1 / bindSig-only** | `-DFIXED` | Wallet commits to a binding key `pkB` at credential-request time; signs `(tid, h(pkE_new))` with `skB` at deferred time |
| **V2 / pkB-in-keyProof** | `-DFIXED_V2` | V1 plus binding `h(pkB)` into the keyProof under `skH` |
| **V3 / bindSig + AT-bound-pkH** | `-DFIXED_V3` | V1's binding signature, **plus** AS issues access token carrying `pk(skH)` as an [RFC 7800](https://datatracker.ietf.org/doc/html/rfc7800) `cnf` claim; CI verifies request `pkH` against AT-bound `pkH` |

### Verdicts

| Config | C2 (def-time enc swap) | C2′ (cuckoo) | Credential secrecy | Runtime |
|---|---|---|---|---|
| **V0 / baseline** | attack witnessed (26 steps) | (subsumed by C2) | falsified (27 steps) | ~19 s |
| **V1 / bindSig-only** | closed (scoped P‑10) | attack witnessed (43 steps) | falsified¹ | ~32 s |
| **V2 / pkB-in-keyProof** | closed | attack witnessed (47 steps) | falsified (39 steps) | ~64 s |
| **V3 / bindSig + AT-bound-pkH** | closed (binding signature; P‑10 holds) | closed (10 steps) | verified (94 steps) | ~13 s |

¹ V1's credential-secrecy lemma `P10_credential_secrecy_fixed` verifies in 113 steps **only** under a same-wallet scoping precondition `WalletGen_HolderKey(Wid, sid, pkH)`. Under the strict unscoped formulation it falsifies analogously to V2.

**The two fix mechanisms address orthogonal attack surfaces.** The binding signature (introduced in V1) closes C2, the deferred-time encryption-key substitution. The `cnf` binding (added in V3) closes C2′, the credential-request-time holder-key substitution. The V1 row shows the binding signature alone closes C2 but not C2′; only V3, combining both mechanisms, closes both. Neither mechanism alone is sufficient.

### What the verdicts mean

- **V0 / baseline** — credential-binding substitution attack is witnessed *and* credential confidentiality (P-10) is falsified. The Dolev–Yao adversary constructs the attack directly from the leaked tokens without any creative reasoning.

- **V1 / bindSig-only** — closes the deferred-time encryption-key substitution (C2). Credential secrecy verifies under same-wallet scoping (113 steps), so V1 is a partial fix, not a total failure. But the cuckoo escalation (C2′) succeeds: with `skH_B` available to the adversary, they construct the credential request as if they were a different wallet, commit to their own binding key, and follow through.

- **V2 / pkB-in-keyProof** — **principled negative result**. The added `h(pkB)` binding is anchored at `skH`, which is leaked under the cuckoo threat model. The adversary signs the V2 keyProof committing to their own choice of `pkB`, reducing the added binding to a self-statement under adversary control. The argument is general and deductive: any payload signed by `skH` can be re-signed by an adversary who holds `skH`, so **no payload-level extension of the keyProof can constrain such an adversary**. The fix must come from a token minted outside the wallet's signing-key space.

- **V3 / bindSig + AT-bound-pkH** — both attacks closed. **C2′ is closed structurally**: the `c2prime_attack_blocked_v3` lemma discharges in 10 proof steps because the cuckoo trace is *structurally unrepresentable* in the V3 model — Tamarin's unification engine forces the credential request's `pkH` to equal the AT-bound `pkH`, and in the cuckoo trace those are different fresh names, yielding contradiction. **C2 is closed by the binding signature** inherited from V1: credential secrecy (P-10) verifies under the strictest formulation (no same-wallet scoping) in 94 steps, and that proof discharges the transaction-ID-leak branch using the binding signature — confirming it is load-bearing for C2, and that removing it would readmit the encryption-key substitution.

Note that V3's overall runtime is the **fastest** of the four configurations (~13 s vs ~19/32/64 s for V0/V1/V2), despite carrying the larger 94-step P-10 proof. The structural `cnf` constraint lets the cuckoo lemma close in 10 steps by unification rather than by search, which dominates the saving.

---

## Reproducibility

### Requirements (verified with)

- **Tamarin Prover** version 1.12.0 ([install instructions](https://tamarin-prover.com/manual/master/book/002_installation.html))
- **Maude** version 3.5.1
- POSIX shell

### Running the proofs

Each configuration is selected by the corresponding `#ifdef` macro flag, e.g.:

```bash
tamarin-prover --prove -D=FIXED_V3 OID4VCI_C2_v3.spthy
```

(substitute `VULNERABLE`, `FIXED`, `FIXED_V2`, or `FIXED_V3`). Full terminal commands, runtimes, and RAM usage are recorded at the end of each log file in this repository.

---

## How the model differs from the spec

The model is a faithful but compact abstraction of the deferred-issuance flow. The simplifications are:

1. **The Authorization Server's role is collapsed into a single action `Wallet_Get_AT`.** The full token-request / PAR / authorization-code handshake is not modeled because none of it interacts with the binding chain we are analyzing. The AT is treated as an unforgeable token issued by the AS, which is sufficient for the threat model.

2. **The credential is represented as a single signed object `credentialSig(CI, pkH, ltkCI)`.** The format-specific Credential Format Profiles (SD-JWT VC, mDL, W3C VCDM, etc., per Appendix B) are not distinguished: the binding-integrity property holds at the level above the format profile.

3. **Single-credential-per-AT.** The `proofs[]` array (§8.2 of the spec) is modeled as one proof per request. Batch issuance compatibility is discussed in the disclosure issue under "Limitations of the fix" and is left as future work.

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

## License

<!-- TODO: choose a license. For a formal-methods artifact intended for reuse and citation,
     a permissive code license (MIT / Apache-2.0) or a research-artifact license (CC-BY-4.0)
     is typical. Without a license, default copyright applies and others cannot reuse the model. -->

---

## Contact

For questions about the model or the disclosed attack, please open a GitHub issue or contact sekmenmu20@itu.edu.tr.
