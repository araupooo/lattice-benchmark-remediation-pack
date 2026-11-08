# Findings — Lattice Benchmark Remediation Pack

Severity-ranked findings from the benchmark and adversarial runs
(`outputs/run1/`, `outputs/run2-clean/`). Every finding is an actually
observed behaviour, with the trigger command and the evidence location
given. Where the implementations behave correctly, that is stated as a
verified-behaviour finding rather than a weakness. The ONE reproduced
core-protocol weakness is F-01; it is new and is not the implicit-rejection
assessment from the earlier ML-KEM work (that work tested FIPS 203
ML-KEM.Decaps implicit rejection in ML-KEM-768 only; ML-DSA and
deterministic signing were not part of it).

## F-01 — Medium: dilithium-py deterministic ML-DSA signing silently drops the FIPS 204 randomized-signing hedge

**Observed.** `ML_DSA.sign(sk, message, deterministic=True)` in
dilithium-py 1.5.1 returns byte-identical signatures every time the same
key signs the same message, while the default (hedged) path returns a
different signature on every signing. Both kinds of signature verify
under dilithium-py itself **and** under liboqs 0.16.0, and no verifier in
either implementation can tell a deterministic signature apart from a
hedged one.

Trigger:

```sh
python3 remediation/reproduce_weakness.py --driver src/pq_driver
```

Output (run1, `outputs/run1/remediation-before.log`): hedged signatures
differ (`identical: False`), deterministic signatures are identical
(`identical: True`), both verify under dilithium-py, and the deterministic
signature verifies `VALID` under liboqs 0.16.0. Exit code 0 =
reproduced. The same result holds for ML-DSA-44/65/87 in the benchmark
harness (`outputs/run1/benchmark-run.log`, `DET` lines:
`dilithium_deterministic_identical=True` for all three parameter sets,
while `liboqs_sign_twice_identical=no` and
`dilithium_hedged_identical=False`).

**Why it matters.** FIPS 204 §3.4 ("Hedged and Deterministic Signing")
specifies hedged signing as the default: fresh randomness `rnd` is used
at signing time, and "the primary purpose of rnd is to facilitate
countermeasures to side-channel attacks and fault attacks on
deterministic signatures". The deterministic variant is permitted only
"in case the signer has no access to a fresh source of randomness", and
"the lack of randomness in the deterministic variant makes the risk of
side-channel attacks (particularly fault attacks) more difficult to
mitigate". The same verification algorithm accepts signatures from
either variant, so a deployment that (mis)uses `deterministic=True` —
for example to get reproducible signatures for golden-file tests or
"stable" release artefacts, as in `remediation/vulnerable_caller.py` —
loses that protection with no observable signal anywhere in the system:
nothing fails, nothing warns, and every signature verifies.

**Remediation (tested).** `remediation/hedged_sign.py` wraps signing so
that the hedged path is the only path: `hedged_sign()` always calls the
library with `deterministic=False` and raises `RepeatedSignatureError`
if the library ever returns a signature identical to one already issued
for the same key and message; `deterministic_sign()` requires an
explicit `allow_deterministic=True` keyword plus a reason, and logs a
warning to stderr on every use. The patch
(`remediation/remediation.patch`) converts the vulnerable caller to the
wrapper. The regression test (`remediation/test_remediation.py`,
`outputs/run1/remediation-after.log`) reproduces the weakness in its
BEFORE section (identical deterministic signatures) and passes all
checks AFTER: hedged signatures differ, both verify under dilithium-py
and liboqs, deterministic mode without the opt-in raises, with the
opt-in it works and warns, the patch applies cleanly and the patched
caller produces differing signatures, and the repeat-signature tripwire
fires.

**Severity: Medium.** The weakness requires a caller to opt into
`deterministic=True`; the default path in both implementations is hedged,
and deterministic signing is permitted by the standard. But the drop is
completely silent and undetectable by any verifier, the opt-in is a
single boolean keyword away, and the protected property (fault-attack
resistance) is exactly the one the standard says the hedge exists for.
No key recovery was demonstrated — no fault injection was performed —
so this is not rated High.

## F-02 — Medium: liboqs signature/KEM functions take bare pointers with no lengths; callers must validate

**Observed.** `OQS_SIG_sign`, `OQS_SIG_verify`, `OQS_KEM_encaps` and
`OQS_KEM_decaps` take pointers and no lengths
(`src/sig/sig.h`, `src/kem/kem.h` in liboqs 0.16.0). The FIPS 204 §3.6.2
requirement that verification "shall return false whenever the lengths
of either of these inputs differ from their lengths specified in this
standard" therefore cannot be enforced by the library function itself.
In this pack the checks are enforced by the driver
(`src/pq_driver.c`) before any call: a truncated signature is refused
with `ERROR signature length check failed: expected 2420 bytes, got
2418`, a wrong-parameter-set public key with `ERROR public key length
check failed: expected 1952 bytes, got 1312`, and truncated/oversized
ciphertexts and wrong-parameter-set decapsulation keys with the
analogous messages, for all six parameter sets
(`outputs/run1/benchmark-run.log`, `ADV` lines:
`liboqs_truncated_ct = refused_length_check`,
`liboqs_oversized_ct = refused_length_check`,
`liboqs_wrong_param_dk = refused_length_check`,
`liboqs_truncated_sig = refused_length_check`,
`liboqs_cross_param = refused_length_check`).

**Why it matters.** A caller that passes a short buffer directly to the
library gets no refusal from the library — the fixed-size code would
read past the supplied buffer. This is the signature-side analogue of
the KEM API-shape observation from the earlier ML-KEM work, now
demonstrated for ML-DSA sign/verify as well as ML-KEM encaps/decaps
across all parameter sets. Mitigation: validate lengths against the
`length_*` members before calling, as the driver does.

**Severity: Medium.** The failure mode requires a caller mistake, and
the library documents the caller-responsibility contract — but the
missing length check is a real, standard-required check that the API
cannot express.

## F-03 — Low: error-signalling differs across implementations for the same invalid inputs

**Observed.** For truncated signatures, dilithium-py returns `False`
(the correct behaviour under FIPS 204 §3.6.2, which says verification
"shall return false" for wrong-length inputs), while for a
wrong-parameter-set public key it raises a Python `ValueError` (e.g.
`PK packed bytes is of the wrong length`) instead of returning `False`.
The liboqs path returns a bare status code (`ERROR sign failed status
-1` for a 300-byte context) or a driver-level refusal string for wrong
lengths. So the three failure channels are: return `False`, raise, and
return a status code — for the same class of invalid input
(`outputs/run1/benchmark-run.log`, `ADV` lines:
`dilithium_truncated_sig = returns_False`,
`dilithium_cross_param = refused_ValueError`,
`dilithium_ctx_300B = refused_ValueError`).

**Why it matters.** Integrators bridging the two APIs must handle two
different failure channels; a caller that only checks one channel can
mistake a refusal for a success — and a caller that does not catch the
exception gets a crash instead of a clean verification failure. Low
severity: both implementations refuse, and the difference is visible in
the logs rather than silent.

## F-04 — Low: liboqs reports a failed signing only as a bare status code, with no reason

**Observed.** Signing with a 300-byte context via
`OQS_SIG_sign_with_ctx_str` fails with `ERROR sign failed status -1`
and no further detail, although the underlying cause is a specific,
checkable condition: FIPS 204 limits the context string to 255 bytes,
and ml-dsa-native's `mld_prepare_domain_separation_prefix` returns
failure for `ctxlen > 255`. The caller cannot distinguish "context too
long" from any other signing failure without reading the library
source (`outputs/run1/benchmark-run.log`, `ADV` lines:
`liboqs_ctx_300B = refused_sign_failed`).

**Why it matters.** In a deployment, a bare failure code forces the
operator to guess which input was at fault; the correct behaviour
(rejecting the over-long context) is indistinguishable from a
malfunction. Low severity: the operation is correctly refused.

## F-05 — Low: pure-Python implementations are two to three orders of magnitude slower than liboqs

**Observed.** Median per-operation times (run1,
`outputs/run1/results.json`, `throughput_ms_median`): liboqs ML-KEM
keygen/encaps/decaps run 0.018–0.051 ms, while kyber-py takes 5.4–23.6 ms
(about 300–500x slower); liboqs ML-DSA sign runs 0.21–0.31 ms and verify
0.07–0.15 ms, while dilithium-py sign takes 84–204 ms and verify 21–49 ms
(about 400–700x slower on sign). Peak RSS (VmHWM): liboqs ~5.8–6.0 MB,
kyber-py ~19.2–19.4 MB, dilithium-py ~20.0–21.1 MB. Exact medians are in
`evidence.json`. The ratio, not the absolute value, is the finding: the
same algorithms, the same parameter sets, two to three orders of
magnitude apart.

**Why it matters.** The Python implementations state in their own
documentation that they are educational, not constant-time and not
written for performance. Quoting their timings as algorithm performance
would be wrong, and a Python-only deployment would need to budget for
these costs (for example, dilithium-py ML-DSA-87 signing at n=10 in
this harness). Low severity: a performance property, not a correctness
one; the implementations are correct, just slow.

## F-06 — Low (verified behaviour, no weakness): flipped or zero ML-KEM ciphertexts decapsulate to a different 32-byte secret

**Observed.** For every parameter set and both KEM implementations, a
ciphertext with one flipped byte, or an all-zero ciphertext,
decapsulates to a 32-byte secret that differs from the valid shared
secret — no error is signalled
(`outputs/run1/benchmark-run.log`, `ADV` lines:
`liboqs_flipped_ct = returns_32B_different_secret`,
`liboqs_zero_ct = returns_32B_different_secret`,
`kyber_flipped_ct = returns_32B_different_secret`,
`kyber_zero_ct = returns_32B_different_secret`).

**Why it matters.** This is FIPS 203 implicit rejection working as
specified: decapsulation never signals failure, it returns the
fallback secret. A caller must compare the resulting secret (or the
authenticated data it protects) and must never treat "decapsulation
returned 32 bytes" as proof the ciphertext was genuine. Recorded here
as a verified behaviour of the adversarial matrix, not as a weakness,
and not as a re-assessment of implicit rejection (which was the subject
of the earlier ML-KEM work).

## F-07 — Low (verified behaviour, no weakness): cross-implementation agreement holds for all six parameter sets

**Observed.** liboqs encapsulations decapsulate correctly under kyber-py
and vice versa for ML-KEM-512/768/1024; liboqs signatures verify under
dilithium-py and vice versa for ML-DSA-44/65/87 — including deterministic
dilithium-py signatures, which liboqs accepts as valid (see F-01 for
why that acceptance is a problem, not a reassurance)
(`outputs/run1/benchmark-run.log`, `XIMPL` lines; all `True`).

**Why it matters.** Interoperability between the C and Python
implementations is confirmed end to end, which is what makes the F-01
observation strong: the deterministic signature is not a quirk of one
library's verifier — it is a standard-conforming signature that every
verifier accepts.
