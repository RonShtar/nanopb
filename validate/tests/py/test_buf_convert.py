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


class BufReplaceTests(unittest.TestCase):
    """--replace: buf.validate is replaced by (validate.rules) (the old behaviour)."""
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nanopb_buf_convert_')
        self.src = os.path.join(self.tmp, 'in', 'demo')
        os.makedirs(self.src)
        with open(os.path.join(self.src, 'demo.proto'), 'w', newline='') as handle:
            handle.write(SOURCE)
        with open(os.path.join(self.src, 'demo.options'), 'w') as handle:
            handle.write('demo.User.name max_size:21\ndemo.User.email max_size:64\n'
                         'demo.User.code max_size:8\ndemo.User.blob max_size:16\n'
                         'demo.User.tags max_count:4\ndemo.User.tags max_size:16\n'
                         'demo.User.note max_size:16\ndemo.User.url max_size:64\n'
                         'demo.User.a max_size:8\ndemo.User.b max_size:8\n')
        # protovalidate's own validate.proto must not be copied.
        os.makedirs(os.path.join(self.src, 'buf', 'validate'))
        with open(os.path.join(self.src, 'buf', 'validate', 'validate.proto'), 'w') as handle:
            handle.write('syntax = "proto2";\n')
        self.out = os.path.join(self.tmp, 'out', 'demo')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def convert(self):
        report, converted, copied = buf.convert_path(self.src, self.out, opts=buf.Options(append=False, sizes=False))
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
        self.assertEqual(buf.main([self.src, '--out', out, '--replace']), 0)
        self.assertEqual(buf.main([self.src, '--out', out, '--replace', '--strict']), 1)

    def test_already_converted_file_is_unchanged(self):
        plain = 'syntax = "proto3";\nmessage A { uint32 x = 1 [(validate.rules).uint32.lte = 5, deprecated = true]; }\n'
        report = buf.Report()
        self.assertEqual(buf.convert_text(plain, 'a.proto', report, 'validate.proto'), plain)
        self.assertEqual(report.items, [])


PROTOVALIDATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures', 'protovalidate')

APPEND_SOURCE = '''syntax = "proto3";
package fleet;

import "buf/validate/validate.proto";

message Move {
  option (buf.validate.message).cel = {id: "x", expression: "true"};
  // The name.
  string name = 1 [(buf.validate.field).string = {min_len: 1, max_len: 20}];
  uint32 speed = 2 [(buf.validate.field).uint32 = {gte: 1, lte: 100}];
  repeated uint32 waypoints = 3 [
    (buf.validate.field).repeated.max_items = 8 // at most eight
  ];
  bytes blob = 4 [(buf.validate.field).bytes.max_len = 16];
  string code = 5 [(buf.validate.field).string = {in: ["ab", "abcd"]}];
  string sized = 6 [(buf.validate.field).string.max_len = 9];
  repeated string tags = 7 [(buf.validate.field).repeated = {max_items: 3, items: {string: {max_len: 5}}}];
  oneof pick {
    string ip = 8 [(buf.validate.field).string.ipv4 = true];
    string re = 9 [(buf.validate.field).string.pattern = "^a$", (buf.validate.field).string.max_len = 4];
  }
}
'''


class BufAppendTests(unittest.TestCase):
    """Default: buf.validate stays, (validate.rules) and nanopb sizes are added, our
    validate.proto sits next to buf's under another name, and the tool generates the
    result without ever generating buf's messages."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nanopb_buf_append_')
        self.src = os.path.join(self.tmp, 'protos')
        shutil.copytree(PROTOVALIDATE, self.src)
        os.makedirs(os.path.join(self.src, 'fleet'))
        with open(os.path.join(self.src, 'fleet', 'fleet.proto'), 'w', newline='') as handle:
            handle.write(APPEND_SOURCE)
        with open(os.path.join(self.src, 'fleet', 'fleet.options'), 'w') as handle:
            handle.write('fleet.Move.sized max_size:40\n')
        self.out = os.path.join(self.tmp, 'out')
        self.result = buf.convert_path(self.src, self.out)
        with open(os.path.join(self.out, 'fleet', 'fleet.proto'), newline='') as handle:
            self.text = handle.read()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_buf_setup_is_kept(self):
        self.assertIn('import "buf/validate/validate.proto";', self.text)
        self.assertIn('option (buf.validate.message).cel = {id: "x", expression: "true"};', self.text)
        with open(os.path.join(PROTOVALIDATE, 'buf', 'validate', 'validate.proto'), newline='') as a, \
                open(os.path.join(self.out, 'buf', 'validate', 'validate.proto'), newline='') as b:
            self.assertEqual(a.read(), b.read())
        # Every buf option is still there, word for word.
        for line in APPEND_SOURCE.splitlines():
            if '(buf.validate.field)' in line:
                self.assertIn(line.split('[', 1)[-1].split('];')[0].split(' //')[0].strip(), self.text)

    def test_ours_is_added_next_to_buf(self):
        self.assertTrue(os.path.isfile(os.path.join(self.out, 'buf', 'validate', 'nanopb_validate.proto')))
        self.assertIn('import "buf/validate/nanopb_validate.proto";', self.text)
        self.assertIn('import "nanopb.proto";', self.text)
        self.assertTrue(os.path.isfile(os.path.join(self.out, 'nanopb.proto')))
        self.assertIn('(buf.validate.field).string = {min_len: 1, max_len: 20}, (validate.rules).string.min_len = 1, '
                      '(validate.rules).string.max_len = 20, (nanopb).max_size = 21]', self.text)
        self.assertIn('(validate.rules).uint32.gte = 1, (validate.rules).uint32.lte = 100]', self.text)
        # multi-line group: ours after the last option, the trailing comment untouched
        self.assertIn('(buf.validate.field).repeated.max_items = 8,\n      (validate.rules).repeated.max_items = 8,\n'
                      '      (nanopb).max_count = 8 // at most eight\n  ];', self.text)

    def test_nanopb_sizes(self):
        sized = dict(((field, option), value) for _, field, option, value in self.result.sized)
        self.assertEqual(sized[('fleet.Move.name', 'max_size')], 21)
        self.assertEqual(sized[('fleet.Move.blob', 'max_size')], 16)          # bytes: no NUL
        self.assertEqual(sized[('fleet.Move.code', 'max_size')], 5)           # longest of "in" + NUL
        self.assertEqual(sized[('fleet.Move.tags', 'max_count')], 3)
        self.assertEqual(sized[('fleet.Move.tags', 'max_size')], 6)           # items.string.max_len + NUL
        self.assertEqual(sized[('fleet.Move.ip', 'max_size')], 16)            # oneof member, ipv4
        self.assertEqual(sized[('fleet.Move.re', 'max_size')], 5)
        self.assertNotIn(('fleet.Move.sized', 'max_size'), sized)             # .options already sizes it
        self.assertNotIn('(nanopb).max_size = 10', self.text)

    def test_unenforced_rules_are_listed_and_kept(self):
        rules = {rule for _, rule, _ in self.result.report.items}
        self.assertEqual(rules, {'buf.validate.message.cel', 'field.string.pattern'})
        self.assertIn('(buf.validate.field).string.pattern = "^a$"', self.text)
        self.assertIn('/* nanopb-validate: not enforced by nanopb-validate (kept for buf) field.string.pattern */',
                      self.text)

    def test_generated_without_buf_messages(self):
        out = os.path.join(self.tmp, 'gen')
        status, result, err = run_backend('gen-c', '--protos-root', self.out, '--out', out, '--no-filter')
        self.assertEqual(status, 0, err or result)
        self.assertEqual(sorted(os.listdir(out)), ['fleet'])                  # buf/ is not a protocol
        for name in os.listdir(os.path.join(out, 'fleet')):
            with open(os.path.join(out, 'fleet', name)) as handle:
                self.assertNotIn('buf_validate', handle.read(), name)
        with open(os.path.join(out, 'fleet', 'fleet_validate.c')) as handle:
            self.assertIn('"string.max_len"', handle.read())
        with open(os.path.join(out, 'fleet', 'fleet.pb.h')) as handle:
            header = handle.read()
        self.assertIn('char name[21];', header)
        self.assertIn('pb_size_t waypoints_count;', header)

    def test_validate_name_option(self):
        out = os.path.join(self.tmp, 'named')
        self.assertEqual(buf.main([self.src, '--out', out, '--validate-name', 'rules.proto']), 0)
        self.assertTrue(os.path.isfile(os.path.join(out, 'buf', 'validate', 'rules.proto')))
        with open(os.path.join(out, 'fleet', 'fleet.proto')) as handle:
            self.assertIn('import "buf/validate/rules.proto";', handle.read())
        with self.assertRaises(SystemExit):
            buf.main([self.src, '--out', out, '--validate-name', 'validate.proto'])


TRICKY_COMMENTS = '''syntax = "proto3";
package fleet;
import "buf/validate/validate.proto";

// The robot's move command; it's sent every 10 ms.
message Move {
  // Name of the robot; don't leave it empty.
  string name = 1 [(buf.validate.field).string.max_len = 20];
  /* speed: can't be zero; {really} */ uint32 speed = 2 [(buf.validate.field).uint32.gte = 1];
  // Tags; each one isn't longer than 8 {characters}.
  repeated string tags = 3 [(buf.validate.field).repeated = {max_items: 4, items: {string: {max_len: 8}}}];
  string mode = 4 [(buf.validate.field).string = {in: ["a;b", "it's {x}"]}];
}
'''


class BufCommentTests(unittest.TestCase):
    """Apostrophes, semicolons and braces in comments and strings (it used to stop with
    'unterminated string'), and a file it cannot read is copied, not a crash."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nanopb_buf_comments_')
        self.src = os.path.join(self.tmp, 'protos', 'fleet')
        os.makedirs(self.src)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_apostrophes_and_braces_in_comments(self):
        with open(os.path.join(self.src, 'fleet.proto'), 'w', newline='') as handle:
            handle.write(TRICKY_COMMENTS)
        result = buf.convert_path(os.path.dirname(self.src), os.path.join(self.tmp, 'out'))
        self.assertEqual(result.failed, [])
        sized = dict(((field, option), value) for _, field, option, value in result.sized)
        self.assertEqual(sized, {('fleet.Move.name', 'max_size'): 21, ('fleet.Move.tags', 'max_count'): 4,
                                 ('fleet.Move.tags', 'max_size'): 9, ('fleet.Move.mode', 'max_size'): 9})
        with open(os.path.join(self.tmp, 'out', 'fleet', 'fleet.proto'), newline='') as handle:
            text = handle.read()
        self.assertIn("// The robot's move command; it's sent every 10 ms.\n", text)
        self.assertIn('[(buf.validate.field).uint32.gte = 1, (validate.rules).uint32.gte = 1]', text)

    def test_unreadable_file_is_copied_and_reported(self):
        broken = 'syntax = "proto3";\nmessage A {\n  string a = 1 [(buf.validate.field).string.const = "abc];\n}\n'
        with open(os.path.join(self.src, 'broken.proto'), 'w', newline='') as handle:
            handle.write(broken)
        with open(os.path.join(self.src, 'fleet.proto'), 'w', newline='') as handle:
            handle.write(TRICKY_COMMENTS)
        out = os.path.join(self.tmp, 'out')
        self.assertEqual(buf.main([os.path.dirname(self.src), '--out', out]), 1)
        with open(os.path.join(out, 'fleet', 'broken.proto'), newline='') as handle:
            self.assertEqual(handle.read(), broken)
        with open(os.path.join(out, 'fleet', 'fleet.proto'), newline='') as handle:
            self.assertIn('(validate.rules).string.max_len = 20', handle.read())   # the others still converted


class OptionProtoDetectionTests(unittest.TestCase):
    """Files that only define options are never a protocol and never generated, whatever their
    name: protovalidate's buf/validate/*, and any file that extends google.protobuf.*Options."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nanopb_option_protos_')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def layout(self, buf_path, import_name):
        root = os.path.join(self.tmp, 'protos')
        target = os.path.join(root, *buf_path.split('/'))
        os.makedirs(os.path.dirname(target))
        shutil.copyfile(os.path.join(PROTOVALIDATE, 'buf', 'validate', 'validate.proto'), target)
        os.makedirs(os.path.join(root, 'fleet'), exist_ok=True)
        with open(os.path.join(root, 'fleet', 'fleet.proto'), 'w') as handle:
            handle.write('syntax = "proto3";\npackage fleet;\nimport "%s";\nimport "nanopb.proto";\n'
                         'message Move { uint32 speed = 1 [(buf.validate.field).uint32.lte = 9]; '
                         'string name = 2 [(nanopb).max_size = 8]; }\n' % import_name)
        return root

    def assert_only_fleet(self, root):
        out = os.path.join(self.tmp, 'gen')
        status, result, err = run_backend('gen-c', '--protos-root', root, '--out', out, '--no-filter')
        self.assertEqual(status, 0, err or result)
        self.assertEqual(sorted(os.listdir(out)), ['fleet'])
        for name in os.listdir(os.path.join(out, 'fleet')):
            with open(os.path.join(out, 'fleet', name)) as handle:
                text = handle.read()
            self.assertNotIn('buf_validate_Rule', text, name)
            self.assertNotIn('google_protobuf_Duration', text, name)   # only buf's file imports it

    def test_buf_validate_under_another_name(self):
        # Before the fix: a "buf" protocol and ~100 buf_validate_*: CALLBACK fields.
        self.assert_only_fleet(self.layout('buf/validate/protovalidate.proto', 'buf/validate/protovalidate.proto'))

    def test_buf_validate_inside_the_protocol(self):
        self.assert_only_fleet(self.layout('fleet/buf/validate/validate.proto', 'buf/validate/validate.proto'))

    def test_options_file_with_any_name(self):
        self.assert_only_fleet(self.layout('common/my_rules.proto', 'common/my_rules.proto'))


if __name__ == '__main__':
    unittest.main()
