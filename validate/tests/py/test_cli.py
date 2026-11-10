"""The public command line: python -m nanopb_validate check|gen|packets|wireshark|test."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from helpers import FIXTURES, PKG_DIR, VALIDATE_DIR


def cli(*argv, cwd=None):
    """Run `python validate/nanopb_validate ...` as a user would; returns (status, stdout, stderr)."""

    proc = subprocess.run([sys.executable, PKG_DIR] + list(argv), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True, cwd=cwd)
    return proc.returncode, proc.stdout, proc.stderr


def result(stdout):
    body = stdout.rstrip().rsplit('__EXIT__=', 1)[0].strip()
    return json.loads(body)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nanopb_cli_')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, rel, text):
        path = os.path.join(self.tmp, *rel.split('/'))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as handle:
            handle.write(text)
        return path

    def test_help_lists_the_five_commands(self):
        status, out, _ = cli('--help')
        self.assertEqual(status, 0)
        for command in ('check', 'gen', 'packets', 'wireshark', 'test'):
            self.assertIn('nanopb_validate %s' % command, out)

    def test_check_clean_directory(self):
        status, out, err = cli('check', FIXTURES)
        self.assertEqual(status, 0, err)
        report = result(out)
        self.assertEqual([p['protocol'] for p in report['protocols']], ['envelope', 'telemetry'])
        self.assertEqual((report['errors'], report['warnings']), (0, 0))

    def test_check_reports_errors_and_warnings(self):
        root = os.path.join(self.tmp, 'protos')
        self.write('protos/broken/broken.proto', 'syntax = "proto3";\nmessage A { uint32 x = 1 }\n')
        self.write('protos/loose/loose.proto', 'syntax = "proto3";\npackage loose;\nmessage L { string name = 1; }\n')
        self.write('protos/big/big.proto', 'syntax = "proto3";\npackage big;\nimport "nanopb.proto";\n'
                   'message B { bytes data = 1 [(nanopb).max_size = 70000]; }\n')
        status, out, _ = cli('check', root)
        self.assertEqual(status, 1)
        report = result(out)
        by_name = dict((p['protocol'], p) for p in report['protocols'])
        self.assertTrue(by_name['broken']['errors'])
        self.assertEqual(by_name['loose']['errors'], [])
        self.assertIn('callbacks', ' '.join(by_name['loose']['warnings']))
        self.assertIn('PB_FIELD_32BIT', ' '.join(by_name['big']['warnings']))

    def test_gen_single_files(self):
        proto = self.write('one/cmd.proto', 'syntax = "proto3";\npackage cmd;\nimport "validate.proto";\n'
                           'message Command { uint32 level = 1 [(validate.rules).uint32.lte = 5]; }\n')
        status, _, err = cli('gen', '--nanopb-opt=-q', '--filter', 'cmd.Command', os.path.basename(proto),
                             cwd=os.path.dirname(proto))
        self.assertEqual(status, 0, err)
        files = sorted(os.listdir(os.path.dirname(proto)))
        self.assertEqual(files, ['cmd.pb.c', 'cmd.pb.h', 'cmd.proto', 'cmd_validate.c', 'cmd_validate.h'])
        with open(os.path.join(os.path.dirname(proto), 'cmd.pb.h')) as handle:
            self.assertIn('int cmd_Command_filter_udp(', handle.read())

    def test_gen_directory_merges_per_protocol(self):
        out = os.path.join(self.tmp, 'out')
        status, stdout, err = cli('gen', FIXTURES, '--out', out, '--unit', 'telemetry')
        self.assertEqual(status, 0, err)
        self.assertEqual(result(stdout)['units'][0]['unit'], 'telemetry')
        self.assertTrue(os.path.isfile(os.path.join(out, 'telemetry', 'telemetry_validate.c')))

    def test_wireshark_subcommands(self):
        status, out, err = cli('wireshark', 'units', '--protos-root', FIXTURES, '--names-only')
        self.assertEqual(status, 0, err)
        self.assertEqual(result(out)['units'], ['envelope', 'telemetry'])
        status, _, err = cli('wireshark', 'nonsense')
        self.assertEqual(status, 1)
        self.assertIn('install', err)

    def test_unknown_command(self):
        status, _, err = cli('frobnicate')
        self.assertEqual(status, 1)
        self.assertIn('unknown command', err)


if __name__ == '__main__':
    unittest.main()
