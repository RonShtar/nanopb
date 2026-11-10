/*
 * Validation benchmark: time pb_decode, pb_decode + pb_validate_Envelope and
 * the generated Envelope_filter_udp on a valid packet, a packet that breaks
 * the first rule checked and one that breaks the last.
 *
 * Usage: bench_validate [iterations]   (default 1000: a quick correctness run)
 * tests/validate_benchmark/bench.py builds it in several configurations and
 * prints a comparison table.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <pb_encode.h>
#include <pb_decode.h>
#include "bench.pb.h"
#include "bench_validate.h"

typedef struct
{
    const char *name;
    pb_byte_t data[512];
    size_t size;
} packet_t;

static packet_t packets[3] = { { "valid" }, { "bad_first" }, { "bad_last" } };

static volatile int sink;

static double now_ns(void)
{
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static void make(Envelope *env, int variant)
{
    pb_size_t i;
    Telemetry *t = &env->body.telemetry;

    memset(env, 0, sizeof(*env));
    env->version = (variant == 1) ? 2 : 1; /* bad_first: the first rule checked */
    env->which_body = Envelope_telemetry_tag;
    strcpy(t->device, "dev-0042");
    t->seq = 7;
    t->readings_count = 8;
    for (i = 0; i < 8; i++)
    {
        t->readings[i].sensor = i * 10;
        t->readings[i].value = 1.5f * (float)i;
        strcpy(t->readings[i].unit, "C");
    }
    strcpy(t->contact, "ops@fleet.example");
    if (variant == 2)
        strcpy(t->contact, "not an email"); /* bad_last: the last rule checked */
}

static int encode_packets(void)
{
    int i;
    for (i = 0; i < 3; i++)
    {
        Envelope env;
        pb_ostream_t stream = pb_ostream_from_buffer(packets[i].data, sizeof(packets[i].data));
        make(&env, i);
        if (!pb_encode(&stream, Envelope_fields, &env))
        {
            printf("encode failed: %s\n", PB_GET_ERROR(&stream));
            return 0;
        }
        packets[i].size = stream.bytes_written;
    }
    return 1;
}

static int decode_only(const packet_t *p)
{
    Envelope env;
    pb_istream_t stream = pb_istream_from_buffer(p->data, p->size);
    return pb_decode(&stream, Envelope_fields, &env);
}

static int decode_validate(const packet_t *p)
{
    Envelope env;
    pb_violations_t violations;
    pb_istream_t stream = pb_istream_from_buffer(p->data, p->size);
    if (!pb_decode(&stream, Envelope_fields, &env))
        return 0;
    pb_violations_init(&violations);
    return pb_validate_Envelope(&env, &violations);
}

/* Pass/fail only: no violations buffer, no path bookkeeping. */
static int decode_validate_nobuf(const packet_t *p)
{
    Envelope env;
    pb_istream_t stream = pb_istream_from_buffer(p->data, p->size);
    if (!pb_decode(&stream, Envelope_fields, &env))
        return 0;
    return pb_validate_Envelope(&env, NULL);
}

static int filter(const packet_t *p)
{
    return Envelope_filter_udp(NULL, p->data, p->size) == 0;
}

#if defined(__GNUC__) || defined(__clang__)
#define NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE
#endif

/* Stack high-water mark: paint a region below the current frame, run the
 * operation from the same depth, then count the bytes it overwrote. */
#define PROBE_BYTES 32768
#define PAINT 0xA5

static NOINLINE void paint_stack(void)
{
    volatile unsigned char area[PROBE_BYTES];
    size_t i;
    for (i = 0; i < PROBE_BYTES; i++)
        area[i] = PAINT;
}

static NOINLINE size_t scan_stack(void)
{
    volatile unsigned char area[PROBE_BYTES];
    size_t untouched = 0;
    while (untouched < PROBE_BYTES && area[untouched] == PAINT)
        untouched++;
    return PROBE_BYTES - untouched;
}

static NOINLINE size_t stack_of(int (*fn)(const packet_t *), const packet_t *p)
{
    paint_stack();
    sink += fn(p);
    return scan_stack();
}

#define REPEATS 7

static void run(const char *what, int (*fn)(const packet_t *), long iterations)
{
    int i;
    for (i = 0; i < 3; i++)
    {
        /* Best of several runs: the minimum is the least disturbed one. */
        double best = 0;
        int r;
        for (r = 0; r < REPEATS; r++)
        {
            long n;
            double start = now_ns(), took;
            for (n = 0; n < iterations; n++)
                sink += fn(&packets[i]);
            took = (now_ns() - start) / (double)iterations;
            if (r == 0 || took < best)
                best = took;
        }
        printf("%-16s %-10s %8.1f ns\n", what, packets[i].name, best);
    }
    printf("stack %-16s %u\n", what, (unsigned)stack_of(fn, &packets[0]));
}

int main(int argc, char **argv)
{
    long iterations = argc > 1 ? atol(argv[1]) : 1000;

    if (!encode_packets())
        return 1;

    /* Correctness first: the numbers are meaningless if the verdicts are wrong. */
    if (!decode_validate(&packets[0]) || decode_validate(&packets[1]) || decode_validate(&packets[2]) ||
        !decode_validate_nobuf(&packets[0]) || decode_validate_nobuf(&packets[1]) ||
        decode_validate_nobuf(&packets[2]) ||
        !filter(&packets[0]) || filter(&packets[1]) || filter(&packets[2]))
    {
        printf("FAIL: unexpected validation verdict\n");
        return 1;
    }

    printf("sizeof Envelope        %u\n", (unsigned)sizeof(Envelope));
    printf("sizeof pb_violations_t %u\n", (unsigned)sizeof(pb_violations_t));
    printf("sizeof pb_validate_context_t %u\n", (unsigned)sizeof(pb_validate_context_t));
    printf("packet bytes           %u\n", (unsigned)packets[0].size);

    run("decode", decode_only, iterations);
    run("decode+validate", decode_validate, iterations);
    run("decode+validate(NULL)", decode_validate_nobuf, iterations);
    run("filter_udp", filter, iterations);
    return 0;
}
