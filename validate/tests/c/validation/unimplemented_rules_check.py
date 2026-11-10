#!/usr/bin/env python3
"""Standalone negative test: validate.proto options with no C-runtime
enforcement must fail code generation loudly, not silently produce a
validator that doesn't check them.

This is deliberately NOT wired into the SCons build graph (unlike the rest
of tests/validation/): a failing `protoc` invocation is the thing under
test here, so it must not be treated as a build failure by the normal
`scons` run. Also deliberately not named test_*.py: tests/.gitignore
excludes tests/*/test_* (compiled test binaries), which would otherwise
swallow this script. Run directly:

    python3 tests/validation/unimplemented_rules_check.py

Each fixture under unimplemented_rules/ declares exactly one option from
one of the six currently-unenforced categories (see
docs/validation.md#unimplemented-options). Generation is expected to exit
non-zero with a message naming the offending option.
"""

import os
import subprocess
import sys

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
FIXTURES_DIR = os.path.join(THIS_DIR, 'unimplemented_rules')
REPO_ROOT = os.path.dirname(os.path.dirname(THIS_DIR))
PROTOC = os.path.join(REPO_ROOT, 'generator', 'protoc')
VALIDATE_PROTO_DIR = os.path.join(REPO_ROOT, 'generator', 'proto')

# fixture filename -> substring that must appear in protoc's stderr
CASES = {
    'message_requires.proto': 'message.requires',
    'message_mutex.proto': 'message.mutex',
    'message_at_least.proto': 'message.at_least',
    'oneof_required.proto': 'oneof_required',
    'map_no_sparse.proto': 'map.no_sparse',
    'string_pattern.proto': 'string.pattern',
    'bytes_pattern.proto': 'bytes.pattern',
    'string_min_max_bytes.proto': 'string.min_bytes',
}


def run_one(fixture, expect_substring, tmp_out):
    cmd = [
        sys.executable, PROTOC,
        '-I', FIXTURES_DIR,
        '-I', VALIDATE_PROTO_DIR,
        '--nanopb_out=--protoc-insertion-points,-x,validate.proto:' + tmp_out,
        '--nanopb-validate_out=-x,validate.proto:' + tmp_out,
        fixture,
    ]
    proc = subprocess.run(cmd, cwd=FIXTURES_DIR, capture_output=True, text=True)

    if proc.returncode == 0:
        return 'expected generation to fail, but it succeeded (exit 0)'

    if expect_substring not in proc.stderr:
        return ('generation failed as expected (exit %d), but stderr did not '
                'mention %r:\n%s' % (proc.returncode, expect_substring, proc.stderr))

    return None


def main():
    import tempfile

    failures = []
    with tempfile.TemporaryDirectory() as tmp_out:
        for fixture, expect_substring in sorted(CASES.items()):
            error = run_one(fixture, expect_substring, tmp_out)
            if error:
                failures.append((fixture, error))
            else:
                print('[PASS] %s correctly failed generation (mentions %r)'
                      % (fixture, expect_substring))

    if failures:
        print('\n%d/%d cases FAILED:' % (len(failures), len(CASES)))
        for fixture, error in failures:
            print('  %s: %s' % (fixture, error))
        return 1

    print('\nAll %d unimplemented-option cases correctly fail generation.' % len(CASES))
    return 0


if __name__ == '__main__':
    sys.exit(main())
