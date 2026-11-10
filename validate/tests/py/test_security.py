"""Security tests for generated packet filters and validators.

Every filter entry point (<name>_udp / <name>_tcp) of the generated C is fed
the generated test packets, thousands of mutations of them and random data:

- each input ends exactly at a protected memory page, so reading one byte past
  the packet crashes (VirtualAlloc guard page on Windows, mmap elsewhere);
- the harness is built with -fsanitize=undefined in trap mode, so signed
  overflow, bad shifts, misaligned or null accesses abort;
- every call must return exactly 0 or -1, the same value twice in a row, and
  the generated packets must keep their PASSED / DROPPED verdict.

Run: python -m unittest discover -s validate/tests/py -p test_security.py -v
Needs a C compiler (gcc/clang/cc, CC, or pip ziglang) and the generator deps.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from helpers import FIXTURES, STRESS_PROTOS, run_backend
from test_backend import find_cc


#: Mutated and random inputs per protocol; a few seconds in total.
FUZZ_ROUNDS = int(os.environ.get('NANOPB_FUZZ_ROUNDS', '20000'))

HARNESS = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "%(header)s"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#define MAX_INPUT 8192

typedef int (*udp_fn)(void *, const uint8_t *, size_t);
typedef int (*tcp_fn)(void *, const uint8_t *, size_t, bool);

static const udp_fn udp_filters[] = { %(udp)s };
static const tcp_fn tcp_filters[] = { %(tcp)s };
static const char *const filter_names[] = { %(names)s };
#define FILTER_COUNT (sizeof(udp_filters) / sizeof(udp_filters[0]))

%(seeds)s

/* MAX_INPUT bytes followed by one page nobody may touch. */
static uint8_t *guarded;
static size_t page;

static void setup_guard(void)
{
#ifdef _WIN32
    SYSTEM_INFO si;
    DWORD old;
    GetSystemInfo(&si);
    page = si.dwPageSize;
    guarded = (uint8_t *)VirtualAlloc(NULL, MAX_INPUT + page, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!guarded || !VirtualProtect(guarded + MAX_INPUT, page, PAGE_NOACCESS, &old)) abort();
#else
    page = (size_t)sysconf(_SC_PAGESIZE);
    guarded = (uint8_t *)mmap(NULL, MAX_INPUT + page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (guarded == MAP_FAILED || mprotect(guarded + MAX_INPUT, page, PROT_NONE) != 0) abort();
#endif
}

/* Copy so that the last byte of the packet is the last readable byte. */
static const uint8_t *place(const uint8_t *data, size_t size)
{
    uint8_t *dst = guarded + MAX_INPUT - size;
    if (size) memcpy(dst, data, size);
    return dst;
}

static unsigned long long rng_state = 0x9e3779b97f4a7c15ULL;
static unsigned long long rnd(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static long calls;

/* Every filter on one input: verdict 0 or -1, the same twice, for UDP and TCP. */
static int check_all(const uint8_t *data, size_t size, int filter_index)
{
    const uint8_t *p = place(data, size);
    size_t i;
    int verdict = 0;
    for (i = 0; i < FILTER_COUNT; i++) {
        int a = udp_filters[i](NULL, p, size);
        int b = udp_filters[i](NULL, p, size);
        int c = tcp_filters[i](NULL, p, size, true);
        calls += 3;
        if ((a != 0 && a != -1) || a != b || a != c) {
            printf("BAD VERDICT %%s: %%d %%d %%d (size %%u)\n", filter_names[i], a, b, c, (unsigned)size);
            exit(3);
        }
        if ((int)i == filter_index) verdict = a;
    }
    return verdict;
}

static size_t mutate(uint8_t *buf, size_t size)
{
    int steps = 1 + (int)(rnd() %% 4);
    while (steps--) {
        size_t pos = size ? (size_t)(rnd() %% size) : 0;
        switch (rnd() %% 9) {
        case 0: if (size) buf[pos] ^= (uint8_t)(1u << (rnd() %% 8)); break;      /* bit flip */
        case 1: if (size) buf[pos] = (uint8_t)rnd(); break;                     /* random byte */
        case 2: size = size ? (size_t)(rnd() %% size) : 0; break;               /* truncate */
        case 3: if (size) buf[pos] = 0xff; break;                               /* inflate a length */
        case 4: if (size) buf[pos] = 0x7f; break;
        case 5:                                                                 /* overlong varint */
            if (size + 10 < MAX_INPUT) {
                memmove(buf + pos + 10, buf + pos, size - pos);
                memset(buf + pos, 0xff, 10);
                size += 10;
            }
            break;
        case 6:                                                                 /* append junk */
            while (size < MAX_INPUT && (rnd() %% 8)) buf[size++] = (uint8_t)rnd();
            break;
        case 7:                                                                 /* duplicate a chunk */
            if (size && size * 2 < MAX_INPUT) { memcpy(buf + size, buf, size); size *= 2; }
            break;
        default: if (size) buf[pos] = (uint8_t)(buf[pos] + 1); break;
        }
    }
    return size;
}

int main(int argc, char **argv)
{
    static uint8_t buf[MAX_INPUT];
    size_t i;
    long round;
    int failures = 0;
    setup_guard();
    if (argc > 1 && strcmp(argv[1], "--guard-selftest") == 0) {
        /* Must crash: proves a read past the packet is caught. */
        volatile const uint8_t *p = place(buf, 4);
        printf("read past end: %%d\n", p[4]);
        return 0;
    }

    /* 1. Generated packets keep their verdict. */
    for (i = 0; i < SEED_COUNT; i++) {
        int v = check_all(seeds[i].data, seeds[i].size, seeds[i].filter);
        if (seeds[i].filter >= 0 && v != seeds[i].expect) {
            printf("VERDICT %%s seed %%u: got %%d, expected %%d\n",
                   filter_names[seeds[i].filter], (unsigned)i, v, seeds[i].expect);
            failures++;
        }
    }

    /* 2. Edge cases. */
    check_all(NULL, 0, -1);
    memset(buf, 0, sizeof(buf));
    check_all(buf, 1, -1);
    check_all(buf, MAX_INPUT, -1);
    memset(buf, 0xff, sizeof(buf));
    check_all(buf, MAX_INPUT, -1);

    /* 3. Mutations of the generated packets, then random data. */
    for (round = 0; round < %(rounds)d; round++) {
        size_t size;
        if (SEED_COUNT && (round %% 4) != 3) {
            const struct seed *s = &seeds[rnd() %% SEED_COUNT];
            memcpy(buf, s->data, s->size);
            size = mutate(buf, s->size);
        } else {
            size = (size_t)(rnd() %% 512);
            for (i = 0; i < size; i++) buf[i] = (uint8_t)rnd();
        }
        check_all(buf, size, -1);
    }
    printf("calls=%%ld failures=%%d\n", calls, failures);
    return failures ? 1 : 0;
}
'''


def c_bytes(data):
    return ', '.join('0x%02x' % b for b in data) or '0'


class FilterSecurityTests(unittest.TestCase):
    def setUp(self):
        self.cc = find_cc()
        if not self.cc:
            self.skipTest('no C compiler')
        self.tmp = tempfile.mkdtemp(prefix='nanopb_sec_')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fuzz(self, protos_root):
        out = os.path.join(self.tmp, 'c')
        status, result, err = run_backend('gen-c', '--protos-root', protos_root, '--out', out, '--with-runtime')
        self.assertEqual(status, 0, err)
        status, packets, err = run_backend('gen-packets', '--protos-root', protos_root, '--mode', 'protocol',
                                           '--out', os.path.join(self.tmp, 'packets'),
                                           '--plugins-dir', os.path.join(self.tmp, 'plugins'))
        self.assertEqual(status, 0, err)
        with open(packets['manifest']) as handle:
            manifest = json.load(handle)

        tested = 0
        for unit in result['units']:
            unit_dir = unit['dir']
            header = os.path.join(unit_dir, unit['unit'] + '.pb.h')
            with open(header) as handle:
                names = re.findall(r'^int (\w+)_udp\(void \*ctx', handle.read(), re.M)
            if not names:
                continue
            protocol = (unit.get('protocol_filter') or '')[:-len('_udp')]
            seeds, rows = [], []
            for entry in manifest['packets']:
                if entry['unit'] != unit['unit']:
                    continue
                index = names.index(protocol) if protocol in names and entry['any_wrapped'] else -1
                expect = 0 if entry['expect'] == 'passed' else -1
                data = bytes.fromhex(entry['hex'])
                rows.append('    { s%d, %d, %d, %d },' % (len(seeds), len(data), index, expect))
                seeds.append('static const uint8_t s%d[] = { %s };' % (len(seeds), c_bytes(data)))
            seed_block = '\n'.join(seeds) + (
                '\nstruct seed { const uint8_t *data; size_t size; int filter; int expect; };\n'
                'static const struct seed seeds[] = {\n%s\n    { 0, 0, -1, 0 }\n};\n'
                '#define SEED_COUNT (sizeof(seeds) / sizeof(seeds[0]) - 1)\n' % '\n'.join(rows))
            harness = os.path.join(unit_dir, 'security_harness.c')
            with open(harness, 'w') as handle:
                handle.write(HARNESS % {
                    'header': os.path.basename(header),
                    'udp': ', '.join(n + '_udp' for n in names),
                    'tcp': ', '.join(n + '_tcp' for n in names),
                    'names': ', '.join('"%s"' % n for n in names),
                    'seeds': seed_block,
                    'rounds': FUZZ_ROUNDS,
                })
            exe = os.path.join(unit_dir, 'security_harness.exe')
            sources = [os.path.join(unit_dir, f) for f in os.listdir(unit_dir) if f.endswith('.c')]
            flags = ['-std=c99', '-O1', '-g', '-fsanitize=undefined', '-fsanitize-trap=undefined',
                     '-fno-sanitize=function', '-I', unit_dir]
            build = subprocess.run(self.cc + flags + ['-o', exe] + sources, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, universal_newlines=True)
            self.assertEqual(build.returncode, 0, build.stdout[-3000:])
            guard = subprocess.run([exe, '--guard-selftest'], stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, universal_newlines=True, timeout=60)
            self.assertNotEqual(guard.returncode, 0, 'guard page did not catch a read past the packet')
            run = subprocess.run([exe], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 universal_newlines=True, timeout=600)
            self.assertEqual(run.returncode, 0, '%s: exit %s (crash = out-of-bounds read or undefined '
                                                'behaviour)\n%s' % (unit['unit'], run.returncode, run.stdout[-3000:]))
            self.assertIn('failures=0', run.stdout)
            tested += 1
        self.assertGreater(tested, 0, 'no filters were generated')

    def test_fixture_protocols(self):
        self.fuzz(FIXTURES)

    def test_stress_protocols(self):
        self.fuzz(STRESS_PROTOS)


if __name__ == '__main__':
    unittest.main()
