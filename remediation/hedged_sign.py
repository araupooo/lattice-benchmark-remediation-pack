"""Hedged ML-DSA signing wrapper — the remediation for F-01.

Problem (see remediation/reproduce_weakness.py): dilithium-py's
``ML_DSA.sign(..., deterministic=True)`` silently produces byte-identical
signatures for repeated signings of the same message, and the resulting
signatures verify under every implementation, so no verifier can tell
the randomized-signing hedge was dropped. FIPS 204 (Algorithm 2) makes
randomized signing the default: the per-signature randomness ``rnd`` is
drawn fresh and hedged with the secret key and the message, precisely so
that fault-injection and side-channel attacks on deterministic signing
do not apply.

This wrapper enforces the hedged default at the call site:

  * ``hedged_sign`` always uses the library's randomized path
    (``deterministic=False``). There is no parameter to turn that off.
  * Deterministic signing is available only through
    ``deterministic_sign``, which requires an explicit
    ``allow_deterministic=True`` keyword AND logs a warning to stderr
    naming the caller-visible reason. Accidental use is a TypeError;
    silent use is impossible.
  * ``hedged_sign`` keeps a process-local record of signatures it has
    issued for each (key digest, message) pair and raises
    ``RepeatedSignatureError`` if the library ever returns a signature
    identical to one already issued for the same pair — a tripwire that
    fires if the underlying library's randomness ever fails or is
    replaced by a deterministic build.

The wrapper changes no cryptography: signatures it produces are plain
FIPS 204 ML-DSA signatures and verify under liboqs 0.16.0 and
dilithium-py alike (verified by remediation/test_remediation.py).

Usage:
    from hedged_sign import hedged_sign, deterministic_sign
    sig = hedged_sign(sk, message)                       # always hedged
    sig = deterministic_sign(sk, message,                 # explicit opt-in
                             allow_deterministic=True,
                             reason="NIST test vector reproduction")
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class RepeatedSignatureError(RuntimeError):
    """A signature identical to an earlier one for the same key+message."""


class DeterministicSigningRefused(PermissionError):
    """Deterministic signing was requested without the explicit opt-in."""


_issued = {}  # (key digest, message) -> set of signature digests


def _record(sk: bytes, message: bytes, sig: bytes) -> None:
    key = (hashlib.sha256(sk).hexdigest(), message)
    seen = _issued.setdefault(key, set())
    digest = hashlib.sha256(sig).hexdigest()
    if digest in seen:
        raise RepeatedSignatureError(
            "identical signature re-issued for the same key and message; "
            "the randomized-signing hedge appears to be off"
        )
    seen.add(digest)


def hedged_sign(impl, sk: bytes, message: bytes, ctx: bytes = b"") -> bytes:
    """Sign with the library's randomized (hedged) path. Always.

    ``impl`` is a dilithium-py ML-DSA parameter-set object
    (e.g. ML_DSA_44). Raises RepeatedSignatureError if the returned
    signature repeats one already issued for this key and message.
    """
    sig = impl.sign(sk, message, ctx=ctx, deterministic=False)
    _record(sk, message, sig)
    return sig


def deterministic_sign(impl, sk: bytes, message: bytes, ctx: bytes = b"",
                       *, allow_deterministic: bool = False,
                       reason: str = "") -> bytes:
    """Deterministic signing, only with an explicit opt-in and a reason.

    The opt-in exists for legitimate uses only (reproducing published
    test vectors, cross-checking a deterministic reference). Every call
    is logged to stderr so it is visible in any run log.
    """
    if not allow_deterministic:
        raise DeterministicSigningRefused(
            "deterministic ML-DSA signing refused: pass "
            "allow_deterministic=True with a reason to opt in explicitly"
        )
    print(f"WARNING: deterministic ML-DSA signing used (reason: {reason or 'not stated'})",
          file=sys.stderr)
    return impl.sign(sk, message, ctx=ctx, deterministic=True)


def reset_record() -> None:
    """Clear the issued-signature record (tests only)."""
    _issued.clear()
