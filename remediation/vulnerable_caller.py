"""Vulnerable caller (BEFORE the remediation).

This is the pattern the finding is about: an application signs with
``deterministic=True`` so that signatures are reproducible across runs
(e.g. for golden-file tests or "stable" release artefacts). Nothing in
the call fails, nothing warns, and every signature it produces verifies
— while the FIPS 204 randomized-signing hedge against fault and
side-channel attacks is silently dropped. See remediation/reproduce_weakness.py
for the demonstration and remediation/hedged_sign.py for the fix.

Run: python3 remediation/vulnerable_caller.py
"""
import sys

sys.path.insert(0, "remediation")

from dilithium_py.ml_dsa import ML_DSA_44

MESSAGE = b"release artefact v1.2.3"


def sign_release(sk: bytes, message: bytes) -> bytes:
    # VULNERABLE: deterministic=True for "reproducible" signatures.
    return ML_DSA_44.sign(sk, message, deterministic=True)


def main() -> int:
    pk, sk = ML_DSA_44.keygen()
    sig1 = sign_release(sk, MESSAGE)
    sig2 = sign_release(sk, MESSAGE)
    print(f"signature 1 valid: {ML_DSA_44.verify(pk, MESSAGE, sig1)}")
    print(f"signature 2 valid: {ML_DSA_44.verify(pk, MESSAGE, sig2)}")
    print(f"signatures identical: {sig1 == sig2}")
    print("WARNING: deterministic signatures — the randomized-signing hedge is off.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
