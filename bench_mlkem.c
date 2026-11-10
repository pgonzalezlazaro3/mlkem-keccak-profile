/*
 * bench_mlkem.c
 *
 * How much of ML-KEM's running time is spent in Keccak (SHA-3 / SHAKE)?
 *
 * That share is the most a SHA-3 hardware accelerator can save: if a fraction s
 * of the time is Keccak, making Keccak free speeds ML-KEM up by at most 1/(1-s)
 * (Amdahl's law).
 *
 * Method. liboqs routes every SHA-3 and SHAKE call through a table of function
 * pointers (OQS_SHA3_set_callbacks, OQS_SHA3_x4_set_callbacks). This program
 * copies liboqs' own default table, wraps every entry with a timer, and installs
 * the wrapped table. It then times key generation, encapsulation and
 * decapsulation for ML-KEM-512, 768 and 1024, and reports:
 *   - time per operation without the wrappers (the true cost),
 *   - time per operation with the wrappers, and the time spent inside Keccak,
 *   - the Keccak share and the Amdahl bound 1/(1-share),
 *   - the timer overhead, so the share can be read with the right error bar.
 *
 * Build: see run_benchmark.sh. The program links statically against liboqs,
 * which is what makes liboqs' default tables (sha3_default_callbacks,
 * sha3_x4_default_callbacks) visible to it.
 *
 * Usage: ./bench_mlkem <label> <output.csv>
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <oqs/oqs.h>

#define ITERATIONS 1000 /* operations per timing round */
#define ROUNDS 7        /* rounds per measurement; the median is reported */
#define CHECKS 100      /* full round trips checked for correctness first */

/* ---------- clock ---------- */

static inline uint64_t now_ns(void) {
#if defined(__APPLE__)
	return clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#else
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#endif
}

/* ---------- Keccak timing wrappers ---------- */

/* liboqs' default tables; defined inside liboqs (xkcp_sha3.c, xkcp_sha3x4.c). */
extern struct OQS_SHA3_callbacks sha3_default_callbacks;
extern struct OQS_SHA3_x4_callbacks sha3_x4_default_callbacks;

static struct OQS_SHA3_callbacks orig_sha3, timed_sha3;
static struct OQS_SHA3_x4_callbacks orig_sha3x4, timed_sha3x4;

static uint64_t keccak_ns = 0;    /* time spent inside SHA-3 / SHAKE calls */
static uint64_t keccak_calls = 0; /* number of outermost SHA-3 / SHAKE calls */
static int depth = 0;             /* so a call made from inside another is not counted twice */

#define TIMED(call)                               \
	do {                                          \
		if (depth++ == 0) {                       \
			uint64_t t0_ = now_ns();              \
			call;                                 \
			keccak_ns += now_ns() - t0_;          \
			keccak_calls++;                       \
		} else {                                  \
			call;                                 \
		}                                         \
		depth--;                                  \
	} while (0)

/* One wrapper per entry of the two tables, generated from liboqs' sha3_ops.h
 * and sha3x4_ops.h (liboqs 0.16.0). Each one times a single call. */

static void w_SHA3_sha3_256(uint8_t *output, const uint8_t *input, size_t inplen) {
	TIMED(orig_sha3.SHA3_sha3_256(output, input, inplen));
}

static void w_SHA3_sha3_256_inc_init(OQS_SHA3_sha3_256_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_sha3_256_inc_init(state));
}

static void w_SHA3_sha3_256_inc_absorb(OQS_SHA3_sha3_256_inc_ctx *state, const uint8_t *input, size_t inlen) {
	TIMED(orig_sha3.SHA3_sha3_256_inc_absorb(state, input, inlen));
}

static void w_SHA3_sha3_256_inc_finalize(uint8_t *output, OQS_SHA3_sha3_256_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_sha3_256_inc_finalize(output, state));
}

static void w_SHA3_sha3_256_inc_ctx_release(OQS_SHA3_sha3_256_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_sha3_256_inc_ctx_release(state));
}

static void w_SHA3_sha3_256_inc_ctx_reset(OQS_SHA3_sha3_256_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_sha3_256_inc_ctx_reset(state));
}

static void w_SHA3_sha3_256_inc_ctx_clone(OQS_SHA3_sha3_256_inc_ctx *dest, const OQS_SHA3_sha3_256_inc_ctx *src) {
	TIMED(orig_sha3.SHA3_sha3_256_inc_ctx_clone(dest, src));
}

static void w_SHA3_sha3_384(uint8_t *output, const uint8_t *input, size_t inplen) {
	TIMED(orig_sha3.SHA3_sha3_384(output, input, inplen));
}

static void w_SHA3_sha3_384_inc_init(OQS_SHA3_sha3_384_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_sha3_384_inc_init(state));
}

static void w_SHA3_sha3_384_inc_absorb(OQS_SHA3_sha3_384_inc_ctx *state, const uint8_t *input, size_t inlen) {
	TIMED(orig_sha3.SHA3_sha3_384_inc_absorb(state, input, inlen));
}

static void w_SHA3_sha3_384_inc_finalize(uint8_t *output, OQS_SHA3_sha3_384_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_sha3_384_inc_finalize(output, state));
}

static void w_SHA3_sha3_384_inc_ctx_release(OQS_SHA3_sha3_384_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_sha3_384_inc_ctx_release(state));
}

static void w_SHA3_sha3_384_inc_ctx_reset(OQS_SHA3_sha3_384_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_sha3_384_inc_ctx_reset(state));
}

static void w_SHA3_sha3_384_inc_ctx_clone(OQS_SHA3_sha3_384_inc_ctx *dest, const OQS_SHA3_sha3_384_inc_ctx *src) {
	TIMED(orig_sha3.SHA3_sha3_384_inc_ctx_clone(dest, src));
}

static void w_SHA3_sha3_512(uint8_t *output, const uint8_t *input, size_t inplen) {
	TIMED(orig_sha3.SHA3_sha3_512(output, input, inplen));
}

static void w_SHA3_sha3_512_inc_init(OQS_SHA3_sha3_512_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_sha3_512_inc_init(state));
}

static void w_SHA3_sha3_512_inc_absorb(OQS_SHA3_sha3_512_inc_ctx *state, const uint8_t *input, size_t inlen) {
	TIMED(orig_sha3.SHA3_sha3_512_inc_absorb(state, input, inlen));
}

static void w_SHA3_sha3_512_inc_finalize(uint8_t *output, OQS_SHA3_sha3_512_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_sha3_512_inc_finalize(output, state));
}

static void w_SHA3_sha3_512_inc_ctx_release(OQS_SHA3_sha3_512_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_sha3_512_inc_ctx_release(state));
}

static void w_SHA3_sha3_512_inc_ctx_reset(OQS_SHA3_sha3_512_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_sha3_512_inc_ctx_reset(state));
}

static void w_SHA3_sha3_512_inc_ctx_clone(OQS_SHA3_sha3_512_inc_ctx *dest, const OQS_SHA3_sha3_512_inc_ctx *src) {
	TIMED(orig_sha3.SHA3_sha3_512_inc_ctx_clone(dest, src));
}

static void w_SHA3_shake128(uint8_t *output, size_t outlen, const uint8_t *input, size_t inplen) {
	TIMED(orig_sha3.SHA3_shake128(output, outlen, input, inplen));
}

static void w_SHA3_shake128_inc_init(OQS_SHA3_shake128_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_shake128_inc_init(state));
}

static void w_SHA3_shake128_inc_absorb(OQS_SHA3_shake128_inc_ctx *state, const uint8_t *input, size_t inlen) {
	TIMED(orig_sha3.SHA3_shake128_inc_absorb(state, input, inlen));
}

static void w_SHA3_shake128_inc_finalize(OQS_SHA3_shake128_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_shake128_inc_finalize(state));
}

static void w_SHA3_shake128_inc_squeeze(uint8_t *output, size_t outlen, OQS_SHA3_shake128_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_shake128_inc_squeeze(output, outlen, state));
}

static void w_SHA3_shake128_inc_ctx_release(OQS_SHA3_shake128_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_shake128_inc_ctx_release(state));
}

static void w_SHA3_shake128_inc_ctx_clone(OQS_SHA3_shake128_inc_ctx *dest, const OQS_SHA3_shake128_inc_ctx *src) {
	TIMED(orig_sha3.SHA3_shake128_inc_ctx_clone(dest, src));
}

static void w_SHA3_shake128_inc_ctx_reset(OQS_SHA3_shake128_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_shake128_inc_ctx_reset(state));
}

static void w_SHA3_shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inplen) {
	TIMED(orig_sha3.SHA3_shake256(output, outlen, input, inplen));
}

static void w_SHA3_shake256_inc_init(OQS_SHA3_shake256_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_shake256_inc_init(state));
}

static void w_SHA3_shake256_inc_absorb(OQS_SHA3_shake256_inc_ctx *state, const uint8_t *input, size_t inlen) {
	TIMED(orig_sha3.SHA3_shake256_inc_absorb(state, input, inlen));
}

static void w_SHA3_shake256_inc_finalize(OQS_SHA3_shake256_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_shake256_inc_finalize(state));
}

static void w_SHA3_shake256_inc_squeeze(uint8_t *output, size_t outlen, OQS_SHA3_shake256_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_shake256_inc_squeeze(output, outlen, state));
}

static void w_SHA3_shake256_inc_ctx_release(OQS_SHA3_shake256_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_shake256_inc_ctx_release(state));
}

static void w_SHA3_shake256_inc_ctx_clone(OQS_SHA3_shake256_inc_ctx *dest, const OQS_SHA3_shake256_inc_ctx *src) {
	TIMED(orig_sha3.SHA3_shake256_inc_ctx_clone(dest, src));
}

static void w_SHA3_shake256_inc_ctx_reset(OQS_SHA3_shake256_inc_ctx *state) {
	TIMED(orig_sha3.SHA3_shake256_inc_ctx_reset(state));
}

static void w_SHA3_shake128_x4(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3, size_t outlen, const uint8_t *in0, const uint8_t *in1, const uint8_t *in2, const uint8_t *in3, size_t inlen) {
	TIMED(orig_sha3x4.SHA3_shake128_x4(out0, out1, out2, out3, outlen, in0, in1, in2, in3, inlen));
}

static void w_SHA3_shake128_x4_inc_init(OQS_SHA3_shake128_x4_inc_ctx *state) {
	TIMED(orig_sha3x4.SHA3_shake128_x4_inc_init(state));
}

static void w_SHA3_shake128_x4_inc_absorb(OQS_SHA3_shake128_x4_inc_ctx *state, const uint8_t *in0, const uint8_t *in1, const uint8_t *in2, const uint8_t *in3, size_t inlen) {
	TIMED(orig_sha3x4.SHA3_shake128_x4_inc_absorb(state, in0, in1, in2, in3, inlen));
}

static void w_SHA3_shake128_x4_inc_finalize(OQS_SHA3_shake128_x4_inc_ctx *state) {
	TIMED(orig_sha3x4.SHA3_shake128_x4_inc_finalize(state));
}

static void w_SHA3_shake128_x4_inc_squeeze(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3, size_t outlen, OQS_SHA3_shake128_x4_inc_ctx *state) {
	TIMED(orig_sha3x4.SHA3_shake128_x4_inc_squeeze(out0, out1, out2, out3, outlen, state));
}

static void w_SHA3_shake128_x4_inc_ctx_release(OQS_SHA3_shake128_x4_inc_ctx *state) {
	TIMED(orig_sha3x4.SHA3_shake128_x4_inc_ctx_release(state));
}

static void w_SHA3_shake128_x4_inc_ctx_clone(OQS_SHA3_shake128_x4_inc_ctx *dest, const OQS_SHA3_shake128_x4_inc_ctx *src) {
	TIMED(orig_sha3x4.SHA3_shake128_x4_inc_ctx_clone(dest, src));
}

static void w_SHA3_shake128_x4_inc_ctx_reset(OQS_SHA3_shake128_x4_inc_ctx *state) {
	TIMED(orig_sha3x4.SHA3_shake128_x4_inc_ctx_reset(state));
}

static void w_SHA3_shake256_x4(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3, size_t outlen, const uint8_t *in0, const uint8_t *in1, const uint8_t *in2, const uint8_t *in3, size_t inlen) {
	TIMED(orig_sha3x4.SHA3_shake256_x4(out0, out1, out2, out3, outlen, in0, in1, in2, in3, inlen));
}

static void w_SHA3_shake256_x4_inc_init(OQS_SHA3_shake256_x4_inc_ctx *state) {
	TIMED(orig_sha3x4.SHA3_shake256_x4_inc_init(state));
}

static void w_SHA3_shake256_x4_inc_absorb(OQS_SHA3_shake256_x4_inc_ctx *state, const uint8_t *in0, const uint8_t *in1, const uint8_t *in2, const uint8_t *in3, size_t inlen) {
	TIMED(orig_sha3x4.SHA3_shake256_x4_inc_absorb(state, in0, in1, in2, in3, inlen));
}

static void w_SHA3_shake256_x4_inc_finalize(OQS_SHA3_shake256_x4_inc_ctx *state) {
	TIMED(orig_sha3x4.SHA3_shake256_x4_inc_finalize(state));
}

static void w_SHA3_shake256_x4_inc_squeeze(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3, size_t outlen, OQS_SHA3_shake256_x4_inc_ctx *state) {
	TIMED(orig_sha3x4.SHA3_shake256_x4_inc_squeeze(out0, out1, out2, out3, outlen, state));
}

static void w_SHA3_shake256_x4_inc_ctx_release(OQS_SHA3_shake256_x4_inc_ctx *state) {
	TIMED(orig_sha3x4.SHA3_shake256_x4_inc_ctx_release(state));
}

static void w_SHA3_shake256_x4_inc_ctx_clone(OQS_SHA3_shake256_x4_inc_ctx *dest, const OQS_SHA3_shake256_x4_inc_ctx *src) {
	TIMED(orig_sha3x4.SHA3_shake256_x4_inc_ctx_clone(dest, src));
}

static void w_SHA3_shake256_x4_inc_ctx_reset(OQS_SHA3_shake256_x4_inc_ctx *state) {
	TIMED(orig_sha3x4.SHA3_shake256_x4_inc_ctx_reset(state));
}

static void install_wrapper_fields(void) {
	timed_sha3.SHA3_sha3_256 = w_SHA3_sha3_256;
	timed_sha3.SHA3_sha3_256_inc_init = w_SHA3_sha3_256_inc_init;
	timed_sha3.SHA3_sha3_256_inc_absorb = w_SHA3_sha3_256_inc_absorb;
	timed_sha3.SHA3_sha3_256_inc_finalize = w_SHA3_sha3_256_inc_finalize;
	timed_sha3.SHA3_sha3_256_inc_ctx_release = w_SHA3_sha3_256_inc_ctx_release;
	timed_sha3.SHA3_sha3_256_inc_ctx_reset = w_SHA3_sha3_256_inc_ctx_reset;
	timed_sha3.SHA3_sha3_256_inc_ctx_clone = w_SHA3_sha3_256_inc_ctx_clone;
	timed_sha3.SHA3_sha3_384 = w_SHA3_sha3_384;
	timed_sha3.SHA3_sha3_384_inc_init = w_SHA3_sha3_384_inc_init;
	timed_sha3.SHA3_sha3_384_inc_absorb = w_SHA3_sha3_384_inc_absorb;
	timed_sha3.SHA3_sha3_384_inc_finalize = w_SHA3_sha3_384_inc_finalize;
	timed_sha3.SHA3_sha3_384_inc_ctx_release = w_SHA3_sha3_384_inc_ctx_release;
	timed_sha3.SHA3_sha3_384_inc_ctx_reset = w_SHA3_sha3_384_inc_ctx_reset;
	timed_sha3.SHA3_sha3_384_inc_ctx_clone = w_SHA3_sha3_384_inc_ctx_clone;
	timed_sha3.SHA3_sha3_512 = w_SHA3_sha3_512;
	timed_sha3.SHA3_sha3_512_inc_init = w_SHA3_sha3_512_inc_init;
	timed_sha3.SHA3_sha3_512_inc_absorb = w_SHA3_sha3_512_inc_absorb;
	timed_sha3.SHA3_sha3_512_inc_finalize = w_SHA3_sha3_512_inc_finalize;
	timed_sha3.SHA3_sha3_512_inc_ctx_release = w_SHA3_sha3_512_inc_ctx_release;
	timed_sha3.SHA3_sha3_512_inc_ctx_reset = w_SHA3_sha3_512_inc_ctx_reset;
	timed_sha3.SHA3_sha3_512_inc_ctx_clone = w_SHA3_sha3_512_inc_ctx_clone;
	timed_sha3.SHA3_shake128 = w_SHA3_shake128;
	timed_sha3.SHA3_shake128_inc_init = w_SHA3_shake128_inc_init;
	timed_sha3.SHA3_shake128_inc_absorb = w_SHA3_shake128_inc_absorb;
	timed_sha3.SHA3_shake128_inc_finalize = w_SHA3_shake128_inc_finalize;
	timed_sha3.SHA3_shake128_inc_squeeze = w_SHA3_shake128_inc_squeeze;
	timed_sha3.SHA3_shake128_inc_ctx_release = w_SHA3_shake128_inc_ctx_release;
	timed_sha3.SHA3_shake128_inc_ctx_clone = w_SHA3_shake128_inc_ctx_clone;
	timed_sha3.SHA3_shake128_inc_ctx_reset = w_SHA3_shake128_inc_ctx_reset;
	timed_sha3.SHA3_shake256 = w_SHA3_shake256;
	timed_sha3.SHA3_shake256_inc_init = w_SHA3_shake256_inc_init;
	timed_sha3.SHA3_shake256_inc_absorb = w_SHA3_shake256_inc_absorb;
	timed_sha3.SHA3_shake256_inc_finalize = w_SHA3_shake256_inc_finalize;
	timed_sha3.SHA3_shake256_inc_squeeze = w_SHA3_shake256_inc_squeeze;
	timed_sha3.SHA3_shake256_inc_ctx_release = w_SHA3_shake256_inc_ctx_release;
	timed_sha3.SHA3_shake256_inc_ctx_clone = w_SHA3_shake256_inc_ctx_clone;
	timed_sha3.SHA3_shake256_inc_ctx_reset = w_SHA3_shake256_inc_ctx_reset;
	timed_sha3x4.SHA3_shake128_x4 = w_SHA3_shake128_x4;
	timed_sha3x4.SHA3_shake128_x4_inc_init = w_SHA3_shake128_x4_inc_init;
	timed_sha3x4.SHA3_shake128_x4_inc_absorb = w_SHA3_shake128_x4_inc_absorb;
	timed_sha3x4.SHA3_shake128_x4_inc_finalize = w_SHA3_shake128_x4_inc_finalize;
	timed_sha3x4.SHA3_shake128_x4_inc_squeeze = w_SHA3_shake128_x4_inc_squeeze;
	timed_sha3x4.SHA3_shake128_x4_inc_ctx_release = w_SHA3_shake128_x4_inc_ctx_release;
	timed_sha3x4.SHA3_shake128_x4_inc_ctx_clone = w_SHA3_shake128_x4_inc_ctx_clone;
	timed_sha3x4.SHA3_shake128_x4_inc_ctx_reset = w_SHA3_shake128_x4_inc_ctx_reset;
	timed_sha3x4.SHA3_shake256_x4 = w_SHA3_shake256_x4;
	timed_sha3x4.SHA3_shake256_x4_inc_init = w_SHA3_shake256_x4_inc_init;
	timed_sha3x4.SHA3_shake256_x4_inc_absorb = w_SHA3_shake256_x4_inc_absorb;
	timed_sha3x4.SHA3_shake256_x4_inc_finalize = w_SHA3_shake256_x4_inc_finalize;
	timed_sha3x4.SHA3_shake256_x4_inc_squeeze = w_SHA3_shake256_x4_inc_squeeze;
	timed_sha3x4.SHA3_shake256_x4_inc_ctx_release = w_SHA3_shake256_x4_inc_ctx_release;
	timed_sha3x4.SHA3_shake256_x4_inc_ctx_clone = w_SHA3_shake256_x4_inc_ctx_clone;
	timed_sha3x4.SHA3_shake256_x4_inc_ctx_reset = w_SHA3_shake256_x4_inc_ctx_reset;
}

static void use_timed_keccak(int on) {
	if (on) {
		OQS_SHA3_set_callbacks(&timed_sha3);
		OQS_SHA3_x4_set_callbacks(&timed_sha3x4);
	} else {
		OQS_SHA3_set_callbacks(&orig_sha3);
		OQS_SHA3_x4_set_callbacks(&orig_sha3x4);
	}
}

/* ---------- benchmark ---------- */

enum { KEYGEN = 0, ENCAPS = 1, DECAPS = 2 };
static const char *OP_NAME[3] = {"keygen", "encaps", "decaps"};

typedef struct {
	OQS_KEM *kem;
	uint8_t *pk, *sk, *ct, *ss_enc, *ss_dec;
} kem_buffers;

static int cmp_double(const void *a, const void *b) {
	double x = *(const double *)a, y = *(const double *)b;
	return (x > y) - (x < y);
}

static double median(double *v, int n) {
	qsort(v, (size_t)n, sizeof(double), cmp_double);
	return v[n / 2];
}

static OQS_STATUS run_op(kem_buffers *b, int op) {
	switch (op) {
	case KEYGEN:
		return OQS_KEM_keypair(b->kem, b->pk, b->sk);
	case ENCAPS:
		return OQS_KEM_encaps(b->kem, b->ct, b->ss_enc, b->pk);
	default:
		return OQS_KEM_decaps(b->kem, b->ss_dec, b->ct, b->sk);
	}
}

/* One round: ITERATIONS calls of one operation. Returns microseconds per call,
 * and (if timed) the Keccak microseconds per call. */
static int time_round(kem_buffers *b, int op, double *us_per_op, double *keccak_us_per_op) {
	keccak_ns = 0;
	keccak_calls = 0;
	uint64_t t0 = now_ns();
	for (int i = 0; i < ITERATIONS; i++) {
		if (run_op(b, op) != OQS_SUCCESS) {
			return 0;
		}
	}
	uint64_t t1 = now_ns();
	*us_per_op = (double)(t1 - t0) / 1000.0 / ITERATIONS;
	*keccak_us_per_op = (double)keccak_ns / 1000.0 / ITERATIONS;
	return 1;
}

static int check_round_trips(kem_buffers *b) {
	for (int i = 0; i < CHECKS; i++) {
		if (run_op(b, KEYGEN) != OQS_SUCCESS || run_op(b, ENCAPS) != OQS_SUCCESS ||
		        run_op(b, DECAPS) != OQS_SUCCESS) {
			return 0;
		}
		if (memcmp(b->ss_enc, b->ss_dec, b->kem->length_shared_secret) != 0) {
			return 0;
		}
	}
	return 1;
}

int main(int argc, char **argv) {
	if (argc != 3) {
		fprintf(stderr, "Usage: %s <label> <output.csv>\n", argv[0]);
		return EXIT_FAILURE;
	}
	const char *label = argv[1];
	FILE *csv = fopen(argv[2], "w");
	if (csv == NULL) {
		perror("fopen");
		return EXIT_FAILURE;
	}
	fprintf(csv, "build,algorithm,operation,us_per_op,us_per_op_with_timers,keccak_us_per_op,"
	        "keccak_calls_per_op,keccak_share,amdahl_bound,timer_overhead\n");

	OQS_init();
	orig_sha3 = sha3_default_callbacks;
	orig_sha3x4 = sha3_x4_default_callbacks;
	timed_sha3 = orig_sha3;
	timed_sha3x4 = orig_sha3x4;
	install_wrapper_fields();

	const char *algs[3] = {OQS_KEM_alg_ml_kem_512, OQS_KEM_alg_ml_kem_768, OQS_KEM_alg_ml_kem_1024};

	printf("\nBuild: %s   (%d rounds of %d operations, median round reported)\n\n", label, ROUNDS, ITERATIONS);
	printf("%-12s %-7s %12s %14s %12s %8s %10s\n", "Algorithm", "Op", "us/op", "Keccak us/op", "Keccak share",
	       "Amdahl", "Overhead");

	for (int a = 0; a < 3; a++) {
		kem_buffers b;
		b.kem = OQS_KEM_new(algs[a]);
		if (b.kem == NULL) {
			fprintf(stderr, "%s is not enabled in this liboqs build\n", algs[a]);
			return EXIT_FAILURE;
		}
		b.pk = malloc(b.kem->length_public_key);
		b.sk = malloc(b.kem->length_secret_key);
		b.ct = malloc(b.kem->length_ciphertext);
		b.ss_enc = malloc(b.kem->length_shared_secret);
		b.ss_dec = malloc(b.kem->length_shared_secret);
		if (!b.pk || !b.sk || !b.ct || !b.ss_enc || !b.ss_dec) {
			fprintf(stderr, "out of memory\n");
			return EXIT_FAILURE;
		}

		use_timed_keccak(0);
		if (!check_round_trips(&b)) {
			fprintf(stderr, "%s: shared secrets do not match, stopping\n", algs[a]);
			return EXIT_FAILURE;
		}
		use_timed_keccak(1);
		if (!check_round_trips(&b)) {
			fprintf(stderr, "%s: shared secrets do not match with timers on, stopping\n", algs[a]);
			return EXIT_FAILURE;
		}
		/* Leave a valid key pair and ciphertext in the buffers for the decaps rounds. */
		run_op(&b, KEYGEN);
		run_op(&b, ENCAPS);

		for (int op = 0; op < 3; op++) {
			double plain[ROUNDS], timed[ROUNDS], kec[ROUNDS], share[ROUNDS], dummy;
			double calls = 0;
			for (int r = 0; r < ROUNDS; r++) {
				/* Alternate plain and timed rounds so drift in clock speed hits both alike. */
				use_timed_keccak(0);
				if (!time_round(&b, op, &plain[r], &dummy)) {
					fprintf(stderr, "%s %s failed\n", algs[a], OP_NAME[op]);
					return EXIT_FAILURE;
				}
				use_timed_keccak(1);
				if (!time_round(&b, op, &timed[r], &kec[r])) {
					fprintf(stderr, "%s %s failed\n", algs[a], OP_NAME[op]);
					return EXIT_FAILURE;
				}
				share[r] = kec[r] / timed[r];
				calls = (double)keccak_calls / ITERATIONS;
			}
			double us = median(plain, ROUNDS);
			double us_t = median(timed, ROUNDS);
			double k = median(kec, ROUNDS);
			double s = median(share, ROUNDS);
			double amdahl = 1.0 / (1.0 - s);
			double overhead = us_t / us - 1.0;

			printf("%-12s %-7s %12.2f %14.2f %11.1f%% %7.2fx %9.1f%%\n", algs[a], OP_NAME[op], us, k, 100.0 * s,
			       amdahl, 100.0 * overhead);
			fprintf(csv, "%s,%s,%s,%.4f,%.4f,%.4f,%.1f,%.4f,%.4f,%.4f\n", label, algs[a], OP_NAME[op], us, us_t, k,
			        calls, s, amdahl, overhead);
		}

		use_timed_keccak(0);
		OQS_KEM_free(b.kem);
		free(b.pk);
		free(b.sk);
		free(b.ct);
		free(b.ss_enc);
		free(b.ss_dec);
	}

	use_timed_keccak(0);
	OQS_destroy();
	fclose(csv);
	printf("\nSaved %s\n", argv[2]);
	return EXIT_SUCCESS;
}
