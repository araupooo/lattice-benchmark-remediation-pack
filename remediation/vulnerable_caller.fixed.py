"""Fixed caller (AFTER the remediation) — the target of remediation.patch.

Identical to remediation/vulnerable_caller.py except that signing goes
through remediation/hedged_sign.py, so repeated signings of the same
message produce different, hedged signatures. The patch
(remediation/remediation.patch) is the diff between the two files.

Run: python3 remediation/vulnerable_caller.fixed.py
"""
import sys

sys.path.insert(0, "remediation")

from dilithium_py.ml_dsa import ML_DSA_44
from hedged_sign import hedged_sign

MESSAGE = b"release artefact v1.2.3"


def sign_release(sk: bytes, message: bytes) -> bytes:
    # FIXED: hedged signing via the wrapper — deterministic mode is
    # refused unless explicitly opted into with a reason.
    return hedged_sign(ML_DSA_44, sk, message)


def main() -> int:
    pk, sk = ML_DSA_44.keygen()
    sig1 = sign_release(sk, MESSAGE)
    sig2 = sign_release(sk, MESSAGE)
    print(f"signature 1 valid: {ML_DSA_44.verify(pk, MESSAGE, sig1)}")
    print(f"signature 2 valid: {ML_DSA_44.verify(pk, MESSAGE, sig2)}")
    print(f"signatures identical: {sig1 == sig2}")
    print("OK: hedged signatures — repeated signings differ.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
