"""Claude Code hooks for this nanopb checkout.

Usage: python nanopb_hook.py post|pre   (hook JSON on stdin)
Exit 2 sends stderr back to Claude (PostToolUse: feedback, PreToolUse: block).
"""
import glob
import json
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def fail(msg):
    sys.stderr.write(msg + "\n")
    sys.exit(2)


def find_line_comments(text):
    """Return line numbers of // comments outside strings and /* */ blocks."""
    hits, state, line, i, n = [], "code", 1, 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                hits.append(line)
                while i < n and text[i] != "\n":
                    i += 1
                continue
            if c == "/" and nxt == "*":
                state, i = "block", i + 2
                continue
            if c in "\"'":
                state = c
        elif state == "block":
            if c == "*" and nxt == "/":
                state, i = "code", i + 2
                continue
        elif c == "\\":
            i += 2
            continue
        elif c == state:
            state = "code"
        if c == "\n":
            line += 1
        i += 1
    return hits


def regenerate():
    protos = sorted(glob.glob(os.path.join(REPO, "proto", "*.proto")))
    if not protos:
        return
    os.makedirs(os.path.join(REPO, "generated"), exist_ok=True)
    cmd = [sys.executable, os.path.join(REPO, "generator", "nanopb_generator.py"),
           "-I", "proto", "-D", "generated"] + [os.path.relpath(p, REPO) for p in protos]
    res = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
    if res.returncode != 0:
        fail("nanopb_generator failed:\n" + res.stdout + res.stderr)
    flagged = []
    for h in glob.glob(os.path.join(REPO, "generated", "*.pb.h")):
        with open(h, encoding="utf-8", errors="replace") as f:
            if "pb_callback_t" in f.read():
                flagged.append(os.path.relpath(h, REPO))
    if flagged:
        fail("Regenerated, but pb_callback_t found in: " + ", ".join(flagged)
             + ". Add max_size/max_count to the matching proto/*.options.")


def post(data):
    path = (data.get("tool_input") or {}).get("file_path") or ""
    if not path:
        return
    rel = os.path.relpath(os.path.abspath(path), REPO).replace("\\", "/")
    if rel.startswith("../"):
        return
    if rel.startswith("proto/") and rel.endswith((".proto", ".options")):
        regenerate()
    elif re.fullmatch(r"pb[^/]*\.[ch]", rel):
        with open(path, encoding="utf-8", errors="replace") as f:
            hits = find_line_comments(f.read())
        if hits:
            fail("%s: C++-style // comment on line(s) %s; runtime is C89 (-ansi), use /* */."
                 % (rel, ", ".join(map(str, hits))))
    elif rel.startswith("generator/") and rel.endswith(".py"):
        with open(path, "rb") as f:
            src = f.read()
        try:
            compile(src, path, "exec")
        except SyntaxError as e:
            fail("Python syntax error in %s line %s: %s" % (rel, e.lineno, e.msg))


RM_RE = re.compile(r"\brm\s+((?:-\w+\s+)*)(?P<targets>[^;&|]*)")
PS_RE = re.compile(r"\bRemove-Item\b(?P<targets>[^;&|]*)", re.IGNORECASE)


def is_repo_target(t):
    t = t.strip("\"'").rstrip("/\\")
    if not t or t.startswith("-"):
        return False
    return os.path.basename(t).lower() == "nanopb" or t in (".", "*") or \
        os.path.normcase(os.path.abspath(t)) == os.path.normcase(REPO)


def pre(data):
    cmd = (data.get("tool_input") or {}).get("command") or ""
    targets = []
    for m in RM_RE.finditer(cmd):
        if re.search(r"-\w*[rR]", m.group(1)):
            targets += m.group("targets").split()
    for m in PS_RE.finditer(cmd):
        if re.search(r"-r(ecurse)?\b", m.group(0), re.IGNORECASE):
            targets += m.group("targets").split()
    for t in targets:
        if is_repo_target(t):
            fail("Blocked: recursive delete of the nanopb tree (%s). Ask the user to do this manually." % t)


def main():
    data = json.load(sys.stdin)
    {"post": post, "pre": pre}[sys.argv[1]](data)


if __name__ == "__main__":
    main()
