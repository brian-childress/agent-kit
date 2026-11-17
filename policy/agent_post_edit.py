#!/usr/bin/env python3
"""agent-post-edit — format + check an edited file with the project's own tools.

Usage:
  agent-post-edit FILE...                 exit 2 + diagnostics on stderr when a check fails
  agent-post-edit --hook claude|codex     reads hook JSON (tool_input.file_path) on stdin
  agent-post-edit --hook cursor           reads {"file_path": ...}; formats only, always exit 0

Checks by file type (silent on success):
  JS/TS/JSON/CSS/... → project-local biome (if biome.json[c] exists), else project-local prettier, else JSON parse
  *.tf/*.tfvars      → terraform fmt
  *.sh/*.bash        → shellcheck -S error
  *.py               → py_compile
  openspec/changes/<id>/** → openspec validate <id> --strict
Opt out per project: {"post_edit": false} in <repo>/.agent-policy.json, or AGENT_POST_EDIT=0.
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from agent_policy import load_policy, repo_root, shutil_which  # noqa: E402

SKIP_PARTS = ("/node_modules/", "/.git/", "/dist/", "/build/", "/.next/", "/.terraform/", "/.astro/")
JS_EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".json", ".jsonc", ".css", ".graphql",
          ".vue", ".svelte", ".astro", ".html")


def find_up(start, stop, rel):
    d = start
    while True:
        p = os.path.join(d, rel)
        if os.path.exists(p):
            return p
        if d == stop or d == os.path.dirname(d):
            return None
        d = os.path.dirname(d)


def run(cmd, cwd):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=120)
    return r.returncode, (r.stdout + r.stderr).strip()


def check(path):
    """Return (tool, output) on failure, None on success/skip."""
    path = os.path.abspath(path)
    if not os.path.isfile(path) or any(s in path for s in SKIP_PARTS):
        return None
    d = os.path.dirname(path)
    root = repo_root(d)
    if os.environ.get("AGENT_POST_EDIT") == "0" or os.environ.get("CLAUDE_POST_EDIT_CHECK") == "0":
        return None
    if not load_policy(d).get("post_edit", True):
        return None
    base = os.path.basename(path)
    if path.endswith(JS_EXT):
        biome = find_up(d, root, "node_modules/.bin/biome")
        cfg = find_up(d, root, "biome.json") or find_up(d, root, "biome.jsonc")
        if biome and cfg:
            rc, out = run([biome, "check", "--write", "--no-errors-on-unmatched", "--max-diagnostics=20", path],
                          os.path.dirname(cfg))
            return ("biome", out) if rc else None
        prettier = find_up(d, root, "node_modules/.bin/prettier")
        if prettier and any(f.startswith((".prettierrc", "prettier.config")) for f in os.listdir(root)):
            rc, out = run([prettier, "--write", "--log-level", "warn", path], root)
            return ("prettier", out) if rc else None
        if base.endswith(".json") and not base.startswith(("tsconfig", "jsconfig")) and "/.vscode/" not in path:
            try:
                with open(path) as f:
                    json.load(f)
            except Exception as e:
                return ("invalid JSON", str(e))
    elif path.endswith((".tf", ".tfvars")) and shutil_which("terraform"):
        rc, out = run(["terraform", "fmt", "-no-color", path], d)
        if rc:
            return ("terraform fmt", out)
    elif path.endswith((".sh", ".bash")) and shutil_which("shellcheck"):
        rc, out = run(["shellcheck", "-S", "error", path], d)
        if rc:
            return ("shellcheck", out)
    elif path.endswith(".py"):
        rc, out = run([sys.executable, "-I", "-m", "py_compile", path], d)
        if rc:
            return ("python syntax", out)
    if "/openspec/changes/" in path and shutil_which("openspec"):
        cid = path.split("/openspec/changes/", 1)[1].split("/", 1)[0]
        if cid and cid != "archive":
            rc, out = run(["openspec", "validate", cid, "--strict", "--no-interactive"], root)
            if rc:
                return ("openspec validate %s" % cid, out)
    return None


def main(argv):
    hook = None
    files = []
    i = 0
    while i < len(argv):
        if argv[i] == "--hook":
            hook = argv[i + 1] if i + 1 < len(argv) else "claude"
            i += 2
            continue
        if argv[i] in ("-h", "--help"):
            print(__doc__)
            return 0
        files.append(argv[i])
        i += 1
    if hook:
        try:
            data = json.load(sys.stdin)
        except Exception:
            return 0
        ti = data.get("tool_input") or data.get("args") or data
        f = ti.get("file_path") or ti.get("filePath") or ti.get("path") or data.get("file_path")
        files = [f] if f else []
    failed = False
    for f in files:
        res = check(f)
        if res:
            failed = True
            tool, out = res
            lines = out.splitlines()[-40:]
            sys.stderr.write("post-edit check failed for %s (%s):\n%s\n" % (f, tool, "\n".join(lines)))
    if hook == "cursor":
        return 0  # Cursor's afterFileEdit is observational; formatting still applied
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
