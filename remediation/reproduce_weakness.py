#!/usr/bin/env python3
"""Reproduce the weakness (F-01): dilithium-py deterministic ML-DSA signing.

A caller that passes deterministic=True to dilithium-py's ML_DSA.sign
gets byte-identical signatures every time the same key signs the same
message. The signatures are fully valid: they verify under dilithium-py
itself AND under liboqs 0.16.0, and no verifier — in either
implementation — can tell a deterministic signature apart from a hedged
one. The fault-attack / side-channel hedge that FIPS 204 builds into
randomized signing (rnd drawn fresh per signature, hedged with the key
and message) is silently dropped, with no observable signal.

Trigger:
  python3 remediation/reproduce_weakness.py [--driver src/pq_driver]

Exit code 0 means the weakness reproduced (deterministic signatures
identical, both verify under both implementations). Exit code 1 means
it did NOT reproduce (the library behaviour changed).
"""
import argparse
import hashlib
import subprocess
import sys

sys.path.insert(0, "remediation")

MESSAGE = b"lattice benchmark remediation pack test message"


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--driver", default="src/pq_driver")
    a = ap.parse_args()

    from dilithium_py.ml_dsa import ML_DSA_44

    pk, sk = ML_DSA_44.keygen()
    print("implementation: dilithium-py 1.5.1, ML-DSA-44 (FIPS 204)")
    print(f"public key sha256:  {sha256(pk)}")
    print(f"message: {MESSAGE!r}")
    print()
    print("--- hedged (default) signing, same key + message, twice ---")
    h1 = ML_DSA_44.sign(sk, MESSAGE)
    h2 = ML_DSA_44.sign(sk, MESSAGE)
    print(f"signature 1 sha256: {sha256(h1)}")
    print(f"signature 2 sha256: {sha256(h2)}")
    print(f"identical: {h1 == h2}")
    print(f"verify sig1 (dilithium-py): {ML_DSA_44.verify(pk, MESSAGE, h1)}")
    print(f"verify sig2 (dilithium-py): {ML_DSA_44.verify(pk, MESSAGE, h2)}")
    print()
    print("--- deterministic signing (deterministic=True), same key + message, twice ---")
    d1 = ML_DSA_44.sign(sk, MESSAGE, deterministic=True)
    d2 = ML_DSA_44.sign(sk, MESSAGE, deterministic=True)
    print(f"signature 1 sha256: {sha256(d1)}")
    print(f"signature 2 sha256: {sha256(d2)}")
    print(f"identical: {d1 == d2}")
    print(f"verify sig1 (dilithium-py): {ML_DSA_44.verify(pk, MESSAGE, d1)}")
    print(f"verify sig2 (dilithium-py): {ML_DSA_44.verify(pk, MESSAGE, d2)}")
    # Cross-implementation: liboqs must also accept the deterministic
    # signature — proving a verifier cannot distinguish it from hedged.
    r = subprocess.run([a.driver, "sig-verify", "ML-DSA-44", pk.hex(),
                        MESSAGE.hex(), d1.hex()],
                       capture_output=True, text=True)
    liboqs_verdict = r.stdout.strip().split()[-1] if r.stdout.strip() else f"rc={r.returncode}"
    print(f"verify deterministic sig1 (liboqs 0.16.0): {liboqs_verdict}")
    r = subprocess.run([a.driver, "sig-verify", "ML-DSA-44", pk.hex(),
                        MESSAGE.hex(), h1.hex()],
                       capture_output=True, text=True)
    liboqs_hedged = r.stdout.strip().split()[-1] if r.stdout.strip() else f"rc={r.returncode}"
    print(f"verify hedged sig1 (liboqs 0.16.0): {liboqs_hedged}")
    print()
    reproduced = (
        d1 == d2
        and h1 != h2
        and ML_DSA_44.verify(pk, MESSAGE, d1)
        and liboqs_verdict == "VALID"
    )
    if reproduced:
        print("REPRODUCED: deterministic=True yields byte-identical, fully valid")
        print("signatures; a verifier cannot distinguish them from hedged ones.")
        print("The FIPS 204 randomized-signing hedge is silently dropped.")
        return 0
    print("NOT REPRODUCED: library behaviour differs from the finding.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
