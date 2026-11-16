"""validate/tools/buf_to_validate.py: protovalidate (buf.validate) -> nanopb-validate.

The script is standalone (standard library only); it is loaded by path here, and its
output is run through the real generator to prove it is accepted and enforced.
"""

import importlib.util
import os
import re
import shutil
import tempfile
import unittest

from helpers import VALIDATE_DIR, run_backend

SCRIPT = os.path.join(VALIDATE_DIR, 'tools', 'buf_to_validate.py')
spec = importlib.util.spec_from_file_location('buf_to_validate', SCRIPT)
buf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(buf)

SOURCE = '''syntax = "proto3";
package demo;

import "buf/validate/validate.proto";
import "google/protobuf/timestamp.proto";

message User {
  option (buf.validate.message).cel = {
    id: "adult"
    message: "must be an adult"
    expression: "this.age >= 18"
  };

  // The name.
  string name = 1 [(buf.validate.field).string.min_len = 1, (buf.validate.field).string.max_len = 20];
  uint32 age = 2 [(buf.validate.field).uint32 = {gte: 18, lte: 150}];
  string email = 3 [(buf.validate.field).string.email = true];
  string code = 4 [(buf.validate.field).string = {len: 4, pattern: "^[A-Z]+$"}];
  int32 kind = 5 [(buf.validate.field).int32 = {in: [1, 2, 3]}];
  bytes blob = 6 [(buf.validate.field).bytes.const = "\\x01"];
  repeated string tags = 7 [(buf.validate.field).repeated = {
    min_items: 1
    max_items: 4
    items: {string: {min_len: 2}}
  }];
  bool flag = 8 [(buf.validate.field).bool.const = true];
  google.protobuf.Timestamp when = 9 [(buf.validate.field).timestamp.lt_now = true];
  string note = 10 [(buf.validate.field).cel = {id: "n", expression: "true"}, deprecated = true];
  string url = 11 [(buf.validate.field).string.uri = true];
  oneof pick {
    option (buf.validate.oneof).required = true;
    string a = 12;
    string b = 13;
  }
}
'''


class BufConvertTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nanopb_buf_convert_')
        self.src = os.path.join(self.tmp, 'in', 'demo')
        os.makedirs(self.src)
        with open(os.path.join(self.src, 'demo.proto'), 'w', newline='') as handle:
            handle.write(SOURCE)
        with open(os.path.join(self.src, 'demo.options'), 'w') as handle:
            handle.write('demo.User.name max_size:21\ndemo.User.email max_size:64\n'
                         'demo.User.code max_size:8\ndemo.User.blob max_size:16\n'
                         'demo.User.tags max_count:4\ndemo.User.tags max_size:16\n')
        # protovalidate's own validate.proto must not be copied.
        os.makedirs(os.path.join(self.src, 'buf', 'validate'))
        with open(os.path.join(self.src, 'buf', 'validate', 'validate.proto'), 'w') as handle:
            handle.write('syntax = "proto2";\n')
        self.out = os.path.join(self.tmp, 'out', 'demo')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def convert(self):
        report, converted, copied = buf.convert_path(self.src, self.out)
        with open(os.path.join(self.out, 'demo.proto'), newline='') as handle:
            return handle.read(), report, converted, copied

    def test_converts_the_rules_we_can_enforce(self):
        text, _, converted, copied = self.convert()
        self.assertEqual(converted, ['demo.proto'])
        self.assertEqual(copied, ['demo.options'])
        self.assertFalse(os.path.exists(os.path.join(self.out, 'buf')))
        self.assertIn('import "validate.proto";', text)
        # buf.validate is named only inside the comments that mark what was dropped.
        kept = re.sub(r'/\* nanopb-validate: dropped [^*]*\*/', '', text)
        self.assertNotIn('buf.validate', kept)
        self.assertIn('// The name.\n', text)                                     # comments survive
        self.assertIn('string name = 1 [(validate.rules).string.min_len = 1, '
                      '(validate.rules).string.max_len = 20];', text)
        self.assertIn('[(validate.rules).uint32.gte = 18, (validate.rules).uint32.lte = 150]', text)
        self.assertIn('[(validate.rules).string.email = true]', text)
        self.assertIn('[(validate.rules).string.min_len = 4, (validate.rules).string.max_len = 4]', text)
        for value in '123':
            self.assertIn('(validate.rules).int32.in = %s' % value, text)
        self.assertIn('(validate.rules).bytes.const_value = "\\x01"', text)
        self.assertIn('(validate.rules).repeated.items.string.min_len = 2', text)   # multi-line group
        self.assertIn('(validate.rules).bool.const_value = true', text)
        self.assertIn('(validate.rules).timestamp.lt_now = true', text)
        self.assertIn('[deprecated = true] /* nanopb-validate: dropped field.cel */', text)

    def test_reports_what_cannot_be_enforced(self):
        text, report, _, _ = self.convert()
        dropped = {rule for _, rule, _ in report.items}
        self.assertEqual(dropped, {'buf.validate.message.cel', 'field.string.pattern', 'field.cel',
                                   'field.string.uri', 'buf.validate.oneof.required'})
        for where, _, why in report.items:
            self.assertRegex(where, r'^demo\.proto:\d+$')
            self.assertTrue(why)
        self.assertIn('/* nanopb-validate: dropped option (buf.validate.message.cel) */', text)
        self.assertIn('/* nanopb-validate: dropped option (buf.validate.oneof.required) */', text)

    def test_converted_proto_is_accepted_by_the_generator(self):
        """The output goes through the real generator, which accepts every converted rule
        (it rejects a rule on the wrong type or without storage), and the generated
        validator carries the bounds. Running the validator is covered by the validation tests."""
        self.convert()
        out = os.path.join(self.tmp, 'gen')
        status, _, err = run_backend('gen-c', '--protos-root', os.path.join(self.tmp, 'out'), '--out', out,
                                     '--unit', 'demo', '--no-filter')
        self.assertEqual(status, 0, err)
        with open(os.path.join(out, 'demo', 'demo_validate.c')) as handle:
            c = handle.read()
        self.assertIn('min_len', c.replace('MIN_LEN', 'min_len').lower())
        self.assertIn('150', c)          # age lte
        self.assertIn('18', c)           # age gte

    def test_in_place_conversion_is_refused(self):
        with self.assertRaises(SystemExit):
            buf.main([self.src, '--out', self.src])

    def test_strict_exit_status(self):
        out = os.path.join(self.tmp, 'strict')
        self.assertEqual(buf.main([self.src, '--out', out]), 0)
        self.assertEqual(buf.main([self.src, '--out', out, '--strict']), 1)

    def test_already_converted_file_is_unchanged(self):
        plain = 'syntax = "proto3";\nmessage A { uint32 x = 1 [(validate.rules).uint32.lte = 5, deprecated = true]; }\n'
        report = buf.Report()
        self.assertEqual(buf.convert_text(plain, 'a.proto', report, 'validate.proto'), plain)
        self.assertEqual(report.items, [])


if __name__ == '__main__':
    unittest.main()
