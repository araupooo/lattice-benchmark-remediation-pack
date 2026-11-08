#!/usr/bin/env bash
# Reproduce the lattice benchmark + remediation pack end to end.
#
#   bash scripts/run_all.sh [run-name]      # default run-name: run1
#
# What it does:
#   1. Verifies the SHA-256 of every bundled source (liboqs tarball, both
#      Python wheels, both FIPS PDFs).
#   2. Builds liboqs 0.16.0 from the bundled tarball (ML-KEM + ML-DSA
#      only, Release) unless already built.
#   3. Compiles the liboqs driver (src/pq_driver.c).
#   4. Creates a Python venv and installs kyber-py 1.2.0 and
#      dilithium-py 1.5.1 from the bundled wheels (no network needed).
#   5. Runs the benchmark + adversarial harness (src/benchmark.py) into
#      outputs/<run-name>/, producing benchmark-run.log (unedited) and
#      results.json.
#   6. Runs the remediation reproduction + regression test into the same
#      output directory (remediation-before.log, remediation-after.log).
#   7. Regenerates docs/index.html from the run results and evidence.json
#      from the run results + remediation logs.
#   8. Regenerates SHA256SUMS over the shippable files.
#
# Requirements: gcc, cmake, make, python3 (>= 3.10), OpenSSL dev headers
# (libssl-dev) for -lcrypto, ~500 MB free disk for the liboqs build.
# No network access is needed: all sources are bundled under src/.
set -euo pipefail
cd "$(dirname "$0")/.."

RUN="${1:-run1}"
OUT="outputs/$RUN"
LIBOQS_TARBALL="src/liboqs-0.16.0.tar.gz"
LIBOQS_SHA256="162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae"
KYBER_WHEEL="src/kyber_py-1.2.0-py3-none-any.whl"
KYBER_SHA256="517f4c8f5009f5b4dfb8f4bfd0f6d631bf56e0cad3f709282e6450e5d8eda6aa"
DILITHIUM_WHEEL="src/dilithium_py-1.5.1-py3-none-any.whl"
DILITHIUM_SHA256="21ab0cbd56e959d22b9dca59bd8af0e2a6f73703b14ad71d483ecf70438c73d7"
FIPS203="src/FIPS.203.pdf"
FIPS203_SHA256="fe1f12f32a7e44ec9fdebbf400cda843a40b506dee676725234dc6f7923b6cac"
FIPS204="src/FIPS.204.pdf"
FIPS204_SHA256="57239b9f84c03227eda3ca0991204dc7764c79af9ce2e6824eda774918d46b6b"

echo "=== lattice benchmark + remediation pack: $RUN ==="
echo "date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- 1. verify bundled sources ---
echo "$LIBOQS_SHA256  $LIBOQS_TARBALL" | sha256sum -c -
echo "$KYBER_SHA256  $KYBER_WHEEL" | sha256sum -c -
echo "$DILITHIUM_SHA256  $DILITHIUM_WHEEL" | sha256sum -c -
echo "$FIPS203_SHA256  $FIPS203" | sha256sum -c -
echo "$FIPS204_SHA256  $FIPS204" | sha256sum -c -

# --- 2. liboqs (ML-KEM + ML-DSA only) ---
if [ ! -d src/liboqs-0.16.0 ]; then
  echo "extracting liboqs 0.16.0 ..."
  tar xzf "$LIBOQS_TARBALL" -C src
fi
if [ ! -f src/liboqs-build/lib/liboqs.a ]; then
  echo "configuring liboqs (ML-KEM + ML-DSA only) ..."
  mkdir -p src/liboqs-build
  (cd src/liboqs-build && cmake ../liboqs-0.16.0 -DCMAKE_BUILD_TYPE=Release \
    -DOQS_BUILD_ONLY_LIB=ON -DOQS_DIST_BUILD=OFF \
    -DOQS_ENABLE_KEM_BIKE=OFF -DOQS_ENABLE_KEM_FRODOKEM=OFF \
    -DOQS_ENABLE_KEM_NTRUPRIME=OFF -DOQS_ENABLE_KEM_NTRU=OFF \
    -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=OFF -DOQS_ENABLE_KEM_HQC=OFF \
    -DOQS_ENABLE_KEM_KYBER=OFF -DOQS_ENABLE_SIG_FALCON=OFF \
    -DOQS_ENABLE_SIG_MAYO=OFF -DOQS_ENABLE_SIG_CROSS=OFF \
    -DOQS_ENABLE_SIG_UOV=OFF -DOQS_ENABLE_SIG_SNOVA=OFF \
    -DOQS_ENABLE_SIG_MQOM=OFF -DOQS_ENABLE_SIG_SLH_DSA=OFF \
    > ../../outputs/build-liboqs-cmake.log 2>&1)
  echo "building liboqs ..."
  (cd src/liboqs-build && make -j"$(nproc)" > ../../outputs/build-liboqs-make.log 2>&1)
fi
# Scrub the absolute build path out of the build logs (cmake records it);
# the logs must not leak the local workspace path into the shipped pack.
sed -i "s|$PWD|.|g" outputs/build-liboqs-cmake.log outputs/build-liboqs-make.log 2>/dev/null || true
ls -la src/liboqs-build/lib/liboqs.a

# --- 3. driver ---
echo "compiling liboqs driver ..."
gcc -O2 -Wall -I src/liboqs-build/include -o src/pq_driver \
  src/pq_driver.c src/liboqs-build/lib/liboqs.a -lcrypto

# --- 4. Python venv ---
if [ ! -x venv/bin/python ]; then
  echo "creating venv and installing kyber-py + dilithium-py from bundled wheels ..."
  python3 -m venv venv
  venv/bin/pip install --quiet --no-index --find-links src kyber-py==1.2.0 dilithium-py==1.5.1
fi
venv/bin/python -c "import kyber_py, dilithium_py; from importlib.metadata import version; print('kyber-py', version('kyber-py'), '| dilithium-py', version('dilithium-py'))"

# --- 5. benchmark + adversarial harness ---
mkdir -p "$OUT"
echo "running benchmark harness -> $OUT ..."
venv/bin/python src/benchmark.py --driver src/pq_driver --outdir "$OUT" --python venv/bin/python

# --- 6. remediation: reproduce + regression test ---
echo "reproducing the weakness -> $OUT/remediation-before.log ..."
venv/bin/python remediation/reproduce_weakness.py --driver src/pq_driver | tee "$OUT/remediation-before.log"
echo "running remediation regression test -> $OUT/remediation-after.log ..."
venv/bin/python remediation/test_remediation.py --driver src/pq_driver | tee "$OUT/remediation-after.log"

# --- 7. rendered page + evidence summary ---
echo "generating docs/index.html ..."
mkdir -p docs
venv/bin/python src/generate_docs.py --results "$OUT/results.json" --out docs/index.html
echo "generating evidence.json ..."
venv/bin/python src/make_evidence.py --results "$OUT/results.json" \
  --before-log "$OUT/remediation-before.log" --after-log "$OUT/remediation-after.log"

# --- 8. digests ---
bash scripts/regen_digests.sh
echo "=== done: $RUN ==="
echo "log:      $OUT/benchmark-run.log"
echo "results:  $OUT/results.json"
echo "evidence: evidence.json"
