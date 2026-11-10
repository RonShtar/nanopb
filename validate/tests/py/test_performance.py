"""Performance budgets for validation and packet filters.

Runs validate/tests/c/validate_benchmark/bench.py (generated validators and filter,
-O2, every build configuration) and fails when a budget is exceeded. Time
budgets are ratios to plain pb_decode of the same packet on the same machine,
so they hold on slow and fast computers; stack and struct sizes are bytes.

Measured when the budgets were set (zig cc 0.x, x86-64, default build):
filter_udp on a valid packet = 1.09 x decode, validation alone ~100 ns,
filter_udp stack 2088 bytes, pb_validate_context_t 272 bytes.

Run: python -m unittest discover -s validate/tests/py -p test_performance.py -v
NANOPB_PERF_ITERATIONS sets the iterations per measurement (default 20000).
"""

import os
import re
import subprocess
import sys
import unittest

from helpers import C_TESTS_DIR
from test_backend import find_cc

BENCH = os.path.join(C_TESTS_DIR, 'validate_benchmark', 'bench.py')
ITERATIONS = os.environ.get('NANOPB_PERF_ITERATIONS', '20000')

#: filter_udp(valid) / decode(valid), per build configuration.
FILTER_OVER_DECODE = {
    'default': 1.25,
    'PB_BUFFER_ONLY + PB_NO_ERRMSG': 1.25,
    'PB_VALIDATE_FILTER_STATIC_BUFFERS': 1.30,
    'PB_VALIDATE_DEBUG': 2.40,
}
#: A packet dropped at its first field must not cost more than a valid one.
DROP_OVER_VALID = 1.15
#: Peak stack bytes of filter_udp on the valid packet.
FILTER_STACK = {
    'default': 2400,
    'PB_BUFFER_ONLY + PB_NO_ERRMSG': 2300,
    'PB_VALIDATE_FILTER_STATIC_BUFFERS': 2100,
    'PB_VALIDATE_DEBUG': 9000,
}
CONTEXT_BYTES = 320


def parse_tables(text):
    """{'time': {config: {column: ns}}, 'stack': {config: {column: bytes}}, 'sizes': {...}}"""
    tables, current, header = {'time': {}, 'stack': {}}, None, None
    for line in text.splitlines():
        if line.startswith('ns per packet'):
            current = 'time'
        elif line.startswith('Peak stack'):
            current = 'stack'
        elif line.startswith('| configuration'):
            header = [c.strip() for c in line.strip('|').split('|')]
        elif current and header and line.startswith('| ') and not line.startswith('|---'):
            cells = [c.strip() for c in line.strip('|').split('|')]
            tables[current][cells[0]] = dict((h, float(v)) for h, v in zip(header[1:], cells[1:]))
    sizes = dict((m.group(1), int(m.group(2))) for m in re.finditer(r'sizeof\((\w+)\) (\d+)', text))
    tables['sizes'] = sizes
    return tables


class PerformanceBudgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not find_cc():
            raise unittest.SkipTest('no C compiler')
        run = subprocess.run([sys.executable, BENCH, '--iterations', ITERATIONS], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, universal_newlines=True, timeout=1800)
        if run.returncode != 0:
            raise AssertionError('benchmark failed:\n' + run.stdout[-3000:])
        cls.output = run.stdout
        cls.tables = parse_tables(run.stdout)

    def test_filter_time_relative_to_decode(self):
        for config, budget in FILTER_OVER_DECODE.items():
            row = self.tables['time'][config]
            ratio = row['filter_udp valid'] / row['decode valid']
            self.assertLessEqual(ratio, budget, '%s: filter_udp is %.2f x decode (budget %.2f)\n%s'
                                 % (config, ratio, budget, self.output))

    def test_drops_are_not_slower_than_accepts(self):
        row = self.tables['time']['default']
        for packet in ('bad_first', 'bad_last'):
            ratio = row['filter_udp ' + packet] / row['filter_udp valid']
            self.assertLessEqual(ratio, DROP_OVER_VALID, 'filter_udp %s is %.2f x valid' % (packet, ratio))

    def test_filter_stack(self):
        for config, budget in FILTER_STACK.items():
            used = self.tables['stack'][config]['filter_udp']
            self.assertLessEqual(used, budget, '%s: filter_udp uses %d stack bytes (budget %d)'
                                 % (config, used, budget))

    def test_context_size(self):
        self.assertLessEqual(self.tables['sizes']['pb_validate_context_t'], CONTEXT_BYTES)


if __name__ == '__main__':
    unittest.main()
