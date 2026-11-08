# Citations — primary sources

Every specification-derived or measured claim in this pack traces to one
of these sources. Copies of FIPS 203 and FIPS 204 are bundled as
`src/FIPS.203.pdf` and `src/FIPS.204.pdf` (SHA-256 verified at the start
of every run by `scripts/run_all.sh`).

## 1. FIPS 204, Module-Lattice-Based Digital Signature Standard

- **Source:** National Institute of Standards and Technology (NIST),
  FIPS 204, August 2024.
- **URL:** https://csrc.nist.gov/pubs/fips/204/final
- **PDF (bundled):** https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
  (SHA-256 `57239b9f84c03227eda3ca0991204dc7764c79af9ce2e6824eda774918d46b6b`)
- **Used for:**
  - Section 3.4 ("Hedged and Deterministic Signing"): hedged signing is
    the default; fresh randomness `rnd` is used at signing time; "the
    primary purpose of rnd is to facilitate countermeasures to
    side-channel attacks and fault attacks on deterministic signatures";
    the deterministic variant is permitted only "in case the signer has
    no access to a fresh source of randomness", and "the lack of
    randomness in the deterministic variant makes the risk of
    side-channel attacks (particularly fault attacks) more difficult to
    mitigate"; "Only implementing the hedged variant ... is sufficient
    to guarantee interoperability. The same verification algorithm will
    work to verify signatures produced by either variant."
  - Section 3.6.2 (Public-Key and Signature Length Checks): verification
    "shall return false whenever the lengths of either of these inputs
    differ from their lengths specified in this standard".
  - Algorithm 2 (ML-DSA.Sign): line 5 uses an approved RBG to generate
    the 32-byte `rnd` in the hedged variant, and substitutes
    `rnd <- {0}^32` in the deterministic variant.
  - Table 2 (Section 4): ML-DSA-44/65/87 sizes (pk 1312/1952/2592 B,
    sk 2560/4032/4896 B, sig 2420/3309/4627 B) — verified in
    `src/benchmark.py` against all three implementations.

## 2. FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard

- **Source:** National Institute of Standards and Technology (NIST),
  FIPS 203, August 2024.
- **URL:** https://csrc.nist.gov/pubs/fips/203/final
- **PDF (bundled):** https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
  (SHA-256 `fe1f12f32a7e44ec9fdebbf400cda843a40b506dee676725234dc6f7923b6cac`)
- **Used for:**
  - Table 2 / Section 8: ML-KEM-512/768/1024 sizes (ek 800/1184/1568 B,
    dk 1632/2400/3168 B, ct 768/1088/1568 B, ss 32 B) — verified in
    `src/benchmark.py` against liboqs and kyber-py.
  - Section 6.3, Algorithm 18 (ML-KEM.Decaps_internal): implicit
    rejection — a failing ciphertext returns the fallback secret
    `K_bar = J(z || c)` instead of signalling an error. This is the
    specified behaviour behind finding F-06; the implicit-rejection
    assessment itself was the subject of the earlier ML-KEM work and is
    not re-assessed here.

## 3. liboqs 0.16.0

- **Source:** Open Quantum Safe, liboqs 0.16.0 release.
- **URL:** https://github.com/open-quantum-safe/liboqs/releases/tag/0.16.0
- **Tarball (bundled):** `src/liboqs-0.16.0.tar.gz`, SHA-256
  `162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae`
- **Used for:** implementation A (C). ML-KEM via `OQS_KEM_*`
  (mlkem-native backend) and ML-DSA via `OQS_SIG_*` (ml-dsa-native
  backend). The API contract — bare pointers, no lengths, "Caller is
  responsible for allocating sufficient memory" — is verified in
  `src/kem/kem.h` and `src/sig/sig.h` (finding F-02). The hedged signing
  path is verified in the bundled source:
  `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/sign.c`,
  `mld_sign_signature()` calls `mld_randombytes(rnd, MLDSA_RNDBYTES)`
  with the comment "Randomized variant of ML-DSA. If you need the
  deterministic variant, call mld_sign_signature_internal directly
  with all-zero rnd", and `mld_prepare_domain_separation_prefix()`
  returns failure for `ctxlen > 255` (finding F-04).

## 4. kyber-py 1.2.0

- **Source:** Giacomo Pope, kyber-py — pure-Python CRYSTALS-Kyber /
  ML-KEM implementation.
- **URL:** https://pypi.org/project/kyber-py/1.2.0/
- **Wheel (bundled):** `src/kyber_py-1.2.0-py3-none-any.whl`, SHA-256
  `517f4c8f5009f5b4dfb8f4bfd0f6d631bf56e0cad3f709282e6450e5d8eda6aa`
- **Used for:** implementation B for ML-KEM (pure Python). `ML_KEM_512 /
  ML_KEM_768 / ML_KEM_1024` keygen/encaps/decaps, exercised in
  `src/benchmark.py` for throughput, adversarial cases and
  cross-implementation agreement with liboqs. The project documents
  itself as an educational implementation, not constant-time and not
  written for performance (finding F-05).

## 5. dilithium-py 1.5.1

- **Source:** Giacomo Pope, dilithium-py — pure-Python CRYSTALS-Dilithium
  / ML-DSA implementation (FIPS 204).
- **URL:** https://pypi.org/project/dilithium-py/1.5.1/
- **Wheel (bundled):** `src/dilithium_py-1.5.1-py3-none-any.whl`, SHA-256
  `21ab0cbd56e959d22b9dca59bd8af0e2a6f73703b14ad71d483ecf70438c73d7`
- **Used for:** implementation B for ML-DSA (pure Python). `ML_DSA_44 /
  ML_DSA_65 / ML_DSA_87` keygen/sign/verify, exercised in
  `src/benchmark.py` and in the F-01 reproduction. The deterministic
  switch is in `dilithium_py/ml_dsa/ml_dsa.py`, `ML_DSA.sign(...,
  deterministic=False)`: `if deterministic: rnd = bytes([0] * 32)` else
  `rnd = self.random_bytes(32)`. The project documents itself as an
  educational implementation ("This code is not constant time, or written
  to be performant"), and passes the NIST ML-DSA KAT vectors
  (finding F-05).

## 6. Hedged ECDSA and EdDSA Signatures (IETF draft)

- **Source:** Preuß Mattsson et al., draft-irtf-cfrg-det-sigs-with-noise.
- **URL:** https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-det-sigs-with-noise
- **Used for:** the general principle behind the remediation — hedged
  constructions (per-message secret derived from fresh randomness, the
  secret key and the message) "protect against key compromise due to
  weak random number generation, but still effectively prevent many
  side-channel and fault injection attacks that exploit determinism",
  and the statement that "The quantum-resistant ML-DSA [FIPS 204] ...
  uses hedged signing by default" and "The primary purpose of rnd is to
  facilitate countermeasures to side-channel attacks and fault attacks
  on deterministic signatures."
