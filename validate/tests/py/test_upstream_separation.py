"""Upgrading nanopb must stay a plain merge: nothing outside validate/ changes.

validate/UPSTREAM names the nanopb commit this tree is based on. Compared with
it, every file outside validate/ must be unchanged, except files nanopb does
not have (CLAUDE.md, agent_docs/, .claude/) and one block appended to the end
of .gitignore. After merging a new nanopb version, put its commit in
validate/UPSTREAM.

Skipped outside a git checkout, or when the base commit is not available.
"""

import os
import subprocess
import unittest

from helpers import REPO_ROOT, VALIDATE_DIR

#: Paths nanopb does not have; adding them never conflicts with a merge.
FORK_ONLY = ('validate', 'CLAUDE.md', 'agent_docs', '.claude')
#: Files we may append to (and only append to).
APPEND_ONLY = ('.gitignore',)


def git(*args):
    return subprocess.run(['git', '-C', REPO_ROOT] + list(args), stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, universal_newlines=True)


class UpstreamSeparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(VALIDATE_DIR, 'UPSTREAM')) as handle:
            cls.base = handle.read().strip()
        if git('rev-parse', '--is-inside-work-tree').returncode != 0:
            raise unittest.SkipTest('not a git checkout')
        if git('cat-file', '-e', cls.base + '^{commit}').returncode != 0:
            raise unittest.SkipTest('nanopb base commit %s is not in this repository' % cls.base[:12])

    def changed(self):
        """(status, path) of every file that differs from the base, working tree included."""

        out = git('diff', '--name-status', '--no-renames', self.base).stdout
        untracked = git('ls-files', '--others', '--exclude-standard').stdout
        rows = [line.split('\t', 1) for line in out.splitlines() if line]
        rows += [['A', path] for path in untracked.splitlines() if path]
        return [(status, path) for status, path in rows]

    def test_nothing_of_nanopb_is_modified(self):
        touched = []
        for status, path in self.changed():
            top = path.split('/', 1)[0]
            if top in FORK_ONLY or path in APPEND_ONLY:
                continue
            touched.append('%s %s' % (status, path))
        self.assertEqual(touched, [], 'these nanopb files differ from %s; move the change into validate/:\n  %s'
                         % (self.base[:12], '\n  '.join(touched)))

    def test_fork_only_paths_are_new_to_nanopb(self):
        for status, path in self.changed():
            if path.split('/', 1)[0] in FORK_ONLY:
                self.assertNotEqual(status, 'M', '%s exists in nanopb %s: it is not ours to change'
                                    % (path, self.base[:12]))

    def test_gitignore_is_only_appended_to(self):
        upstream = git('show', self.base + ':.gitignore').stdout
        with open(os.path.join(REPO_ROOT, '.gitignore')) as handle:
            ours = handle.read()
        self.assertTrue(ours.startswith(upstream), '.gitignore must keep nanopb\'s rules unchanged at the top '
                                                   'and only add a block at the end')


if __name__ == '__main__':
    unittest.main()
