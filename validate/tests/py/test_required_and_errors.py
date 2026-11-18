"""(validate.rules).required on every kind of field, and protoc errors users can act on.

required used to be checked only on fields with a has_ flag and silently ignored on
proto3 strings, numbers and repeated fields. Now it means what protovalidate means: the
field differs from its default (non-empty, non-zero, at least one item, present).
"""

import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest

from helpers import VALIDATE_DIR, run_backend
from test_backend import find_cc

PROTO = '''syntax = "proto3";
package req;
import "validate.proto";
message Inner { uint32 a = 1; }
message M {
  string name = 1 [(validate.rules).required = true];
  uint32 id = 2 [(validate.rules).required = true];
  bytes blob = 3 [(validate.rules).required = true];
  Inner inner = 4 [(validate.rules).required = true];
  repeated uint32 xs = 5 [(validate.rules).required = true];
  optional int32 opt = 6 [(validate.rules).required = true];
  bool flag = 7 [(validate.rules).required = true];
  double ratio = 8 [(validate.rules).required = true];
}
'''
OPTIONS = 'req.M.name max_size:16\nreq.M.blob max_size:8\nreq.M.xs max_count:4\n'

MAIN = '''#include <stdio.h>
#include <string.h>
#include "req.pb.h"
#include "req_validate.h"

static req_M full(void)
{
    req_M m = req_M_init_zero;
    strcpy(m.name, "x");
    m.id = 7;
    m.blob.size = 1;
    m.has_inner = true;
    m.xs_count = 1;
    m.has_opt = true;
    m.flag = true;
    m.ratio = 0.5;
    return m;
}

int main(void)
{
    int bad = 0;
    req_M m = full();
    if (!req_validate_M(&m, NULL)) { printf("FAIL: everything set but invalid\\n"); bad++; }
#define MISSING(what, change) do { m = full(); change; \\
        if (req_validate_M(&m, NULL)) { printf("FAIL: %s missing but valid\\n", what); bad++; } } while (0)
    MISSING("name", m.name[0] = 0);
    MISSING("id", m.id = 0);
    MISSING("blob", m.blob.size = 0);
    MISSING("inner", m.has_inner = false);
    MISSING("xs", m.xs_count = 0);
    MISSING("opt", m.has_opt = false);
    MISSING("flag", m.flag = false);
    MISSING("ratio", m.ratio = 0.0);
    printf("%d wrong\\n", bad);
    return bad != 0;
}
'''


class RequiredTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nanopb_ws_required_')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, rel, text):
        path = os.path.join(self.tmp, *rel.split('/'))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', newline='\n') as handle:
            handle.write(text)
        return path

    def test_required_on_every_kind_of_field(self):
        self.write('protos/req/req.proto', PROTO)
        self.write('protos/req/req.options', OPTIONS)
        out = os.path.join(self.tmp, 'out')
        status, _, err = run_backend('gen-c', '--protos-root', os.path.join(self.tmp, 'protos'), '--out', out,
                                     '--with-runtime', '--no-filter')
        self.assertEqual(status, 0, err)
        unit = os.path.join(out, 'req')
        with open(os.path.join(unit, 'req_validate.c')) as handle:
            source = handle.read()
        for check in ("msg->name[0] == '\\0'", 'msg->id == 0', 'msg->blob.size == 0', '!msg->has_inner',
                      'msg->xs_count == 0', '!msg->has_opt', 'msg->flag == 0', 'msg->ratio == 0'):
            self.assertIn('if (%s) {' % check, source)
        cc = find_cc()
        if not cc:
            return
        main = self.write('out/req/main.c', MAIN)
        objects = []
        for name in sorted(os.listdir(unit)):
            if name.endswith('.c'):
                obj = os.path.join(self.tmp, name + '.o')
                proc = subprocess.run(cc + ['-std=c99', '-O2', '-Wall', '-Werror', '-I', unit, '-c',
                                            os.path.join(unit, name), '-o', obj],
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
                self.assertEqual(proc.returncode, 0, proc.stdout)
                objects.append(obj)
        exe = os.path.join(self.tmp, 'req' + ('.exe' if os.name == 'nt' else ''))
        proc = subprocess.run(cc + ['-o', exe] + objects, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              universal_newlines=True)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        proc = subprocess.run([exe], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn('0 wrong', proc.stdout)
        self.assertTrue(os.path.isfile(main))

    def test_required_test_data_is_never_the_default(self):
        """packets: a PASSED sample sets every required field to a non-default value."""
        self.write('protos/req/req.proto', PROTO.replace('import "validate.proto";',
                                                         'import "validate.proto";\nimport "google/protobuf/any.proto";')
                   + 'message Packet { google.protobuf.Any payload = 1; }\n')
        self.write('protos/req/req.options', OPTIONS)
        out = os.path.join(self.tmp, 'packets')
        status, result, err = run_backend('gen-packets', '--mode', 'protocol', '--protos-root',
                                          os.path.join(self.tmp, 'protos'), '--out', out, '--no-install')
        self.assertEqual(status, 0, err)
        self.assertGreater(result['passed'], 0)
        self.assertGreater(result['dropped'], 0)
        # The real dissector gives every packet the verdict the generator meant (PASSED samples
        # set every required field, DROPPED ones leave one out).
        import test_tshark
        if test_tshark.TSHARK is None:
            return
        tmp = os.path.join(self.tmp, 'tshark')
        os.makedirs(tmp)
        test_tshark.TsharkTests.check_generated(self, os.path.join(self.tmp, 'protos'), tmp, 'protocol')

    def test_required_on_a_oneof_member_is_a_clear_error(self):
        self.write('protos/one/one.proto', 'syntax = "proto3";\npackage one;\nimport "validate.proto";\n'
                   'message M { oneof body { uint32 a = 1 [(validate.rules).required = true]; uint32 b = 2; } }\n')
        status, _, err = run_backend('gen-c', '--protos-root', os.path.join(self.tmp, 'protos'),
                                     '--out', os.path.join(self.tmp, 'out'))
        self.assertEqual(status, 1)
        self.assertIn('inside oneof "body"', err)


class ProtocErrorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nanopb_ws_protoc_err_')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def gen(self, proto):
        os.makedirs(os.path.join(self.tmp, 'protos', 'p'))
        with open(os.path.join(self.tmp, 'protos', 'p', 'p.proto'), 'w') as handle:
            handle.write(proto)
        return run_backend('gen-c', '--protos-root', os.path.join(self.tmp, 'protos'),
                           '--out', os.path.join(self.tmp, 'out'))

    def test_missing_validate_import_says_what_to_add(self):
        status, _, err = self.gen('syntax = "proto3";\npackage p;\n'
                                  'message M { uint32 id = 1 [(validate.rules).uint32.gte = 1]; }\n')
        self.assertEqual(status, 1)
        self.assertIn('protoc (the protobuf compiler) rejected', err)
        self.assertIn('p.proto:3:28: Option "(validate.rules)" unknown', err)
        self.assertIn('add  import "validate.proto";', err)
        self.assertNotIn('protoc failed (status 1)', err)
        self.assertEqual(err.count('Option "(validate.rules)" unknown'), 1)     # once, not per layout

    def test_syntax_error_shows_the_line(self):
        status, _, err = self.gen('syntax = "proto3";\npackage p;\nmessage M { uint32 id = 1 }\n')
        self.assertEqual(status, 1)
        self.assertIn('p.proto:3:27: Expected ";".', err)
        self.assertIn('syntax error at that line and column', err)


class ConverterImportTests(unittest.TestCase):
    def test_converter_adds_the_import_when_the_rules_need_it(self):
        path = os.path.join(VALIDATE_DIR, 'tools', 'buf_to_validate.py')
        spec = importlib.util.spec_from_file_location('buf_to_validate', path)
        buf = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(buf)
        report = buf.Report()
        text = ('syntax = "proto3";\npackage p;\nimport "google/protobuf/any.proto";\n'
                'message M { uint32 id = 1 [(buf.validate.field).uint32.gte = 1]; }\n')
        out = buf.ensure_validate_import(buf.convert_text(text, 'p.proto', report, 'validate.proto'), 'validate.proto')
        self.assertIn('import "google/protobuf/any.proto";\nimport "validate.proto";\n', out)
        vendored = text.replace('import "google/protobuf/any.proto";',
                                'import "third_party/buf/validate/validate.proto";')
        out = buf.ensure_validate_import(buf.convert_text(vendored, 'p.proto', report, 'validate.proto'),
                                         'validate.proto')
        self.assertEqual(out.count('import "validate.proto";'), 1)
        self.assertNotIn('buf/validate', out)
        plain = 'syntax = "proto3";\nmessage M { uint32 id = 1; }\n'
        self.assertEqual(buf.ensure_validate_import(plain, 'validate.proto'), plain)


if __name__ == '__main__':
    unittest.main()
