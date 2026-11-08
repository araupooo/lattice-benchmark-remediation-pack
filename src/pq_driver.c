/* pq_driver.c — minimal stdin/argv driver over liboqs 0.16.0.
 *
 * Covers ML-KEM-512/768/1024 and ML-DSA-44/65/87 through the generic
 * OQS_KEM / OQS_SIG API. All inputs and outputs are hex on stdout, one
 * labelled line each, so the Python harness can drive it without parsing
 * binary. The driver validates every buffer length against the
 * algorithm's published lengths BEFORE calling liboqs: liboqs itself
 * takes bare pointers and performs no length checks of its own
 * (see findings.md, F-02). A length violation is reported as
 * "ERROR <message>" on stdout and exit code 2; it never reaches liboqs.
 *
 * Usage:
 *   pq_driver info <alg>
 *   pq_driver kem-keygen <alg>
 *   pq_driver kem-encaps <alg> <ek-hex>
 *   pq_driver kem-decaps <alg> <dk-hex> <ct-hex>
 *   pq_driver kem-bench <alg> <n>
 *   pq_driver sig-keygen <alg>
 *   pq_driver sig-sign <alg> <sk-hex> <msg-hex> [ctx-hex]
 *   pq_driver sig-sign-twice <alg> <sk-hex> <msg-hex>
 *   pq_driver sig-verify <alg> <pk-hex> <msg-hex> <sig-hex> [ctx-hex]
 *   pq_driver sig-bench <alg> <n>
 *
 * Exit codes: 0 ok, 1 liboqs error, 2 driver input/length error.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <oqs/oqs.h>

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Returns byte count, or -1 on bad hex. */
static long unhex(const char *s, uint8_t *out, size_t cap) {
    size_t n = strlen(s);
    if (n % 2 != 0) return -1;
    if (n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval((unsigned char)s[2 * i]);
        int lo = hexval((unsigned char)s[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (long)(n / 2);
}

static void print_hex(const char *label, const uint8_t *b, size_t n) {
    printf("%s ", label);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static double median(double *v, size_t n) {
    qsort(v, n, sizeof(double), cmp_double);
    if (n % 2) return v[n / 2];
    return (v[n / 2 - 1] + v[n / 2]) / 2.0;
}

/* Peak RSS in kilobytes, read from /proc/self/status VmHWM.
 * NOTE: getrusage(RUSAGE_SELF).ru_maxrss is NOT per-process in this
 * environment — a child spawned from Python reports the parent Python
 * process's peak instead of its own (verified: a trivial test program
 * reports ~1 MB direct but ~11 MB when spawned from Python, exactly the
 * parent's value). VmHWM is the process's own high-water mark and is
 * parent-independent, so it is used here instead. */
static long peak_rss_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    long v = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "VmHWM:", 6) == 0) {
            sscanf(line + 6, "%ld", &v);
            break;
        }
    }
    fclose(f);
    return v;
}

static int is_kem(const char *alg) { return strncmp(alg, "ML-KEM-", 7) == 0; }
static int is_sig(const char *alg) { return strncmp(alg, "ML-DSA-", 7) == 0; }

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: pq_driver <cmd> <alg> [args...]\n");
        return 2;
    }
    const char *cmd = argv[1];
    const char *alg = argv[2];
    if (!is_kem(alg) && !is_sig(alg)) {
        printf("ERROR unknown algorithm %s\n", alg);
        return 2;
    }

    if (strcmp(cmd, "info") == 0) {
        if (is_kem(alg)) {
            OQS_KEM *kem = OQS_KEM_new(alg);
            if (!kem) { printf("ERROR algorithm not enabled %s\n", alg); return 1; }
            printf("type KEM\nlength_public_key %zu\nlength_secret_key %zu\n"
                   "length_ciphertext %zu\nlength_shared_secret %zu\n",
                   kem->length_public_key, kem->length_secret_key,
                   kem->length_ciphertext, kem->length_shared_secret);
            OQS_KEM_free(kem);
        } else {
            OQS_SIG *sig = OQS_SIG_new(alg);
            if (!sig) { printf("ERROR algorithm not enabled %s\n", alg); return 1; }
            printf("type SIG\nlength_public_key %zu\nlength_secret_key %zu\n"
                   "length_signature %zu\n",
                   sig->length_public_key, sig->length_secret_key,
                   sig->length_signature);
            OQS_SIG_free(sig);
        }
        return 0;
    }

    if (is_kem(alg)) {
        OQS_KEM *kem = OQS_KEM_new(alg);
        if (!kem) { printf("ERROR algorithm not enabled %s\n", alg); return 1; }
        size_t pk_len = kem->length_public_key, sk_len = kem->length_secret_key;
        size_t ct_len = kem->length_ciphertext, ss_len = kem->length_shared_secret;

        if (strcmp(cmd, "kem-keygen") == 0) {
            uint8_t *pk = malloc(pk_len), *sk = malloc(sk_len);
            if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) {
                printf("ERROR keypair failed\n"); return 1;
            }
            print_hex("public_key", pk, pk_len);
            print_hex("secret_key", sk, sk_len);
            return 0;
        }
        if (strcmp(cmd, "kem-encaps") == 0) {
            if (argc < 4) { printf("ERROR missing encapsulation key\n"); return 2; }
            uint8_t *ek = malloc(pk_len), *ct = malloc(ct_len), *ss = malloc(ss_len);
            long n = unhex(argv[3], ek, pk_len);
            if (n != (long)pk_len) {
                printf("ERROR encapsulation key length check failed: expected %zu bytes, got %ld\n",
                       pk_len, n < 0 ? -1 : n);
                return 2;
            }
            if (OQS_KEM_encaps(kem, ct, ss, ek) != OQS_SUCCESS) {
                printf("ERROR encaps failed\n"); return 1;
            }
            print_hex("ciphertext", ct, ct_len);
            print_hex("shared_secret", ss, ss_len);
            return 0;
        }
        if (strcmp(cmd, "kem-decaps") == 0) {
            if (argc < 5) { printf("ERROR missing decapsulation key or ciphertext\n"); return 2; }
            uint8_t *dk = malloc(sk_len), *ct = malloc(ct_len), *ss = malloc(ss_len);
            long n1 = unhex(argv[3], dk, sk_len);
            long n2 = unhex(argv[4], ct, ct_len);
            if (n1 != (long)sk_len) {
                printf("ERROR decapsulation key length check failed: expected %zu bytes, got %ld\n",
                       sk_len, n1 < 0 ? -1 : n1);
                return 2;
            }
            if (n2 != (long)ct_len) {
                printf("ERROR ciphertext length check failed: expected %zu bytes, got %ld\n",
                       ct_len, n2 < 0 ? -1 : n2);
                return 2;
            }
            if (OQS_KEM_decaps(kem, ss, ct, dk) != OQS_SUCCESS) {
                printf("ERROR decaps failed\n"); return 1;
            }
            print_hex("shared_secret", ss, ss_len);
            return 0;
        }
        if (strcmp(cmd, "kem-bench") == 0) {
            int n = argc >= 4 ? atoi(argv[3]) : 100;
            if (n < 1) n = 1;
            uint8_t *pk = malloc(pk_len), *sk = malloc(sk_len);
            uint8_t *ct = malloc(ct_len), *ss = malloc(ss_len), *ss2 = malloc(ss_len);
            double *t = malloc(sizeof(double) * (size_t)n);
            /* keygen */
            for (int i = 0; i < n; i++) {
                double s = now_ms();
                if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) { printf("ERROR keypair failed\n"); return 1; }
                t[i] = now_ms() - s;
            }
            printf("keygen_ms_median %.6f\n", median(t, (size_t)n));
            /* encaps */
            for (int i = 0; i < n; i++) {
                double s = now_ms();
                if (OQS_KEM_encaps(kem, ct, ss, pk) != OQS_SUCCESS) { printf("ERROR encaps failed\n"); return 1; }
                t[i] = now_ms() - s;
            }
            printf("encaps_ms_median %.6f\n", median(t, (size_t)n));
            /* decaps (round-trip check on the last encapsulation) */
            int ok = 0;
            for (int i = 0; i < n; i++) {
                if (OQS_KEM_encaps(kem, ct, ss, pk) != OQS_SUCCESS) { printf("ERROR encaps failed\n"); return 1; }
                double s = now_ms();
                if (OQS_KEM_decaps(kem, ss2, ct, sk) != OQS_SUCCESS) { printf("ERROR decaps failed\n"); return 1; }
                t[i] = now_ms() - s;
                if (memcmp(ss, ss2, ss_len) == 0) ok++;
            }
            printf("decaps_ms_median %.6f\n", median(t, (size_t)n));
            printf("roundtrip_ok %d/%d\n", ok, n);
            printf("peak_rss_kb %ld\n", peak_rss_kb());
            return 0;
        }
        printf("ERROR unknown KEM command %s\n", cmd);
        return 2;
    }

    /* --- signatures --- */
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) { printf("ERROR algorithm not enabled %s\n", alg); return 1; }
    size_t pk_len = sig->length_public_key, sk_len = sig->length_secret_key;
    size_t sig_len = sig->length_signature;

    if (strcmp(cmd, "sig-keygen") == 0) {
        uint8_t *pk = malloc(pk_len), *sk = malloc(sk_len);
        if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) {
            printf("ERROR keypair failed\n"); return 1;
        }
        print_hex("public_key", pk, pk_len);
        print_hex("secret_key", sk, sk_len);
        return 0;
    }
    if (strcmp(cmd, "sig-sign") == 0 || strcmp(cmd, "sig-sign-twice") == 0) {
        if (argc < 5) { printf("ERROR missing secret key or message\n"); return 2; }
        uint8_t *sk = malloc(sk_len);
        long nsk = unhex(argv[3], sk, sk_len);
        if (nsk != (long)sk_len) {
            printf("ERROR secret key length check failed: expected %zu bytes, got %ld\n",
                   sk_len, nsk < 0 ? -1 : nsk);
            return 2;
        }
        size_t msg_cap = strlen(argv[4]) / 2 + 1;
        uint8_t *msg = malloc(msg_cap);
        long nmsg = unhex(argv[4], msg, msg_cap);
        if (nmsg < 0) { printf("ERROR bad message hex\n"); return 2; }
        const uint8_t *ctx = NULL;
        size_t ctx_len = 0;
        uint8_t *ctxbuf = NULL;
        if (argc >= 6) {
            ctxbuf = malloc(strlen(argv[5]) / 2 + 1);
            long nctx = unhex(argv[5], ctxbuf, strlen(argv[5]) / 2 + 1);
            if (nctx < 0) { printf("ERROR bad context hex\n"); return 2; }
            ctx = ctxbuf; ctx_len = (size_t)nctx;
        }
        uint8_t *sg = malloc(sig_len);
        size_t sg_len = 0;
        OQS_STATUS st;
        if (ctx) st = OQS_SIG_sign_with_ctx_str(sig, sg, &sg_len, msg, (size_t)nmsg, ctx, ctx_len, sk);
        else     st = OQS_SIG_sign(sig, sg, &sg_len, msg, (size_t)nmsg, sk);
        if (st != OQS_SUCCESS) {
            printf("ERROR sign failed status %d\n", (int)st);
            return 1;
        }
        print_hex("signature", sg, sg_len);
        if (strcmp(cmd, "sig-sign-twice") == 0) {
            uint8_t *sg2 = malloc(sig_len);
            size_t sg2_len = 0;
            if (ctx) st = OQS_SIG_sign_with_ctx_str(sig, sg2, &sg2_len, msg, (size_t)nmsg, ctx, ctx_len, sk);
            else     st = OQS_SIG_sign(sig, sg2, &sg2_len, msg, (size_t)nmsg, sk);
            if (st != OQS_SUCCESS) {
                printf("ERROR second sign failed status %d\n", (int)st);
                return 1;
            }
            print_hex("signature2", sg2, sg2_len);
            printf("signatures_identical %s\n",
                   (sg_len == sg2_len && memcmp(sg, sg2, sg_len) == 0) ? "yes" : "no");
        }
        return 0;
    }
    if (strcmp(cmd, "sig-verify") == 0) {
        if (argc < 6) { printf("ERROR missing public key, message or signature\n"); return 2; }
        uint8_t *pk = malloc(pk_len);
        long npk = unhex(argv[3], pk, pk_len);
        if (npk != (long)pk_len) {
            printf("ERROR public key length check failed: expected %zu bytes, got %ld\n",
                   pk_len, npk < 0 ? -1 : npk);
            return 2;
        }
        size_t msg_cap = strlen(argv[4]) / 2 + 1;
        uint8_t *msg = malloc(msg_cap);
        long nmsg = unhex(argv[4], msg, msg_cap);
        if (nmsg < 0) { printf("ERROR bad message hex\n"); return 2; }
        /* Signature length is checked against the algorithm's length;
         * a truncated or over-long signature is refused here, before liboqs. */
        size_t sig_cap = strlen(argv[5]) / 2 + 1;
        uint8_t *sg = malloc(sig_cap);
        long nsg = unhex(argv[5], sg, sig_cap);
        if (nsg < 0) { printf("ERROR bad signature hex\n"); return 2; }
        if ((size_t)nsg != sig_len) {
            printf("ERROR signature length check failed: expected %zu bytes, got %ld\n",
                   sig_len, nsg);
            return 2;
        }
        const uint8_t *ctx = NULL;
        size_t ctx_len = 0;
        uint8_t *ctxbuf = NULL;
        if (argc >= 7) {
            ctxbuf = malloc(strlen(argv[6]) / 2 + 1);
            long nctx = unhex(argv[6], ctxbuf, strlen(argv[6]) / 2 + 1);
            if (nctx < 0) { printf("ERROR bad context hex\n"); return 2; }
            ctx = ctxbuf; ctx_len = (size_t)nctx;
        }
        OQS_STATUS st;
        if (ctx) st = OQS_SIG_verify_with_ctx_str(sig, msg, (size_t)nmsg, sg, sig_len, ctx, ctx_len, pk);
        else     st = OQS_SIG_verify(sig, msg, (size_t)nmsg, sg, sig_len, pk);
        printf("verify %s\n", st == OQS_SUCCESS ? "VALID" : "INVALID");
        return 0;
    }
    if (strcmp(cmd, "sig-bench") == 0) {
        int n = argc >= 4 ? atoi(argv[3]) : 100;
        if (n < 1) n = 1;
        uint8_t *pk = malloc(pk_len), *sk = malloc(sk_len);
        uint8_t *sg = malloc(sig_len);
        size_t sg_len = 0;
        const uint8_t msg[] = "benchmark message for ML-DSA throughput measurement";
        double *t = malloc(sizeof(double) * (size_t)n);
        for (int i = 0; i < n; i++) {
            double s = now_ms();
            if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) { printf("ERROR keypair failed\n"); return 1; }
            t[i] = now_ms() - s;
        }
        printf("keygen_ms_median %.6f\n", median(t, (size_t)n));
        int ok = 0;
        for (int i = 0; i < n; i++) {
            double s = now_ms();
            if (OQS_SIG_sign(sig, sg, &sg_len, msg, sizeof(msg) - 1, sk) != OQS_SUCCESS) {
                printf("ERROR sign failed\n"); return 1;
            }
            t[i] = now_ms() - s;
        }
        printf("sign_ms_median %.6f\n", median(t, (size_t)n));
        for (int i = 0; i < n; i++) {
            double s = now_ms();
            OQS_STATUS st = OQS_SIG_verify(sig, msg, sizeof(msg) - 1, sg, sg_len, pk);
            t[i] = now_ms() - s;
            if (st == OQS_SUCCESS) ok++;
        }
        printf("verify_ms_median %.6f\n", median(t, (size_t)n));
        printf("verify_ok %d/%d\n", ok, n);
        printf("peak_rss_kb %ld\n", peak_rss_kb());
        return 0;
    }
    printf("ERROR unknown SIG command %s\n", cmd);
    return 2;
}
