#!/usr/bin/env python3
"""agent-policy — harness-neutral shell command policy for coding agents.

Decides allow / deny / defer for a shell command string:
  allow  every part of the command (including chains, pipes, loops, $(...)) is read-only,
         or a permitted local write (git add/commit, formatters, installs, writes under temp dirs)
  deny   a guard fired (AI attribution trailers, secrets in a commit, file edits via the shell)
  defer  anything else: the harness applies its own permission rules / prompts as usual

Usage:
  agent-policy check [--cwd DIR] [--json] [CMD]     (CMD from stdin if omitted)
  agent-policy hook claude|codex|cursor|gemini       (reads the harness hook JSON on stdin)
  agent-policy test                                  (runs built-in self-tests)

Config: <kit>/config/policy.json, overlaid by ~/.config/agent-kit/policy.json and <repo>/.agent-policy.json.
Env overrides: AGENT_ALLOW_SHELL_EDITS=1, AGENT_SKIP_GITLEAKS=1, AGENT_REWRITE_HINTS=0 (CLAUDE_* equivalents also honored).

Rewrite hints (Claude only by default): Claude Code prompts for `cd X && ...` chains and shell loops even when
this hook allows them. For such commands the hook denies with a concrete rewrite so the agent retries on its own.
Limits: the same command is never hinted twice, and after `max_consecutive` hints in a row (no clean command in
between) the hook stops hinting and the normal approval prompt appears.
Stdlib only; python3 >= 3.8.
"""
import fnmatch
import json
import os
import re
import shlex
import hashlib
import subprocess
import sys
import tempfile

KIT = os.environ.get("AGENT_KIT_HOME") or os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
ALLOW, DENY, DEFER = "allow", "deny", "defer"
SUBST = "__AGENT_SUBST__"
STD_BIN_DIRS = ("/bin", "/usr/bin", "/usr/local/bin", "/opt/homebrew/bin", "/sbin", "/usr/sbin")
TRAILER_RE = re.compile(r"co-authored-by:|generated with \[?claude|🤖 generated", re.I)
WRITE_CODE_RE = re.compile(
    r"open\([^)]*,\s*['\"][wax]|\.write_text\(|\.write_bytes\(|writeFileSync|writeFile\(|appendFileSync|"
    r"File\.write|shutil\.(copy|move)|os\.(remove|rename|unlink)|\.unlink\(|fs\.(rm|unlink|rename)")
LITERAL_PATH_RE = re.compile(r"['\"]((?:/|\./|\.\./|~/)?[\w.\-/\[\]]+\.[\w]+|/[\w.\-/]+)['\"]")


# ----------------------------------------------------------------------------- config
def _merge(base, over):
    for k, v in over.items():
        if k.startswith("_"):
            continue
        if isinstance(v, list) and isinstance(base.get(k), list):
            base[k] = base[k] + v
        elif isinstance(v, dict) and isinstance(base.get(k), dict):
            base[k] = dict(base[k], **v)
        else:
            base[k] = v
    return base


def repo_root(cwd):
    try:
        out = subprocess.run(["git", "-C", cwd, "rev-parse", "--show-toplevel"], capture_output=True, text=True, timeout=5)
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return cwd


def load_policy(cwd):
    with open(os.path.join(KIT, "config", "policy.json")) as f:
        pol = json.load(f)
    for p in (os.path.expanduser("~/.config/agent-kit/policy.json"), os.path.join(repo_root(cwd), ".agent-policy.json")):
        if os.path.isfile(p):
            try:
                with open(p) as f:
                    _merge(pol, json.load(f))
            except Exception as e:  # a broken overlay must not break the agent
                sys.stderr.write("agent-policy: ignoring %s (%s)\n" % (p, e))
    env = os.environ.get
    if env("AGENT_ALLOW_SHELL_EDITS") == "1" or env("CLAUDE_ALLOW_SHELL_EDITS") == "1":
        pol["guards"]["block_shell_edits"] = False
    if env("AGENT_SKIP_GITLEAKS") == "1" or env("CLAUDE_SKIP_GITLEAKS") == "1":
        pol["guards"]["gitleaks_on_commit"] = False
    tmp = os.environ.get("TMPDIR", "")
    pol["temp_dirs"] = [tmp.rstrip("/") if d == "$TMPDIR" else d for d in pol["temp_dirs"] if d != "$TMPDIR" or tmp]
    return pol


# ----------------------------------------------------------------------------- lexing
def extract_heredocs(text):
    """Remove heredoc bodies. Returns (text_without_bodies, [body, ...]) in order of appearance."""
    lines = text.split("\n")
    out, bodies, i = [], [], 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        tags = re.findall(r"<<-?\s*(['\"]?)([A-Za-z_][\w]*)\1", line)
        i += 1
        for _, tag in tags:
            body = []
            while i < len(lines) and lines[i].strip() != tag:
                body.append(lines[i])
                i += 1
            i += 1
            bodies.append("\n".join(body))
    return "\n".join(out), bodies


def extract_substitutions(text):
    """Replace $(...), `...`, <(...), >(...) with a placeholder; return (text, [inner commands])."""
    res, inner, i, n = [], [], 0, len(text)
    sq = dq = False
    while i < n:
        c = text[i]
        if c == "\\" and not sq and i + 1 < n:
            res.append(text[i:i + 2]); i += 2; continue
        if c == "'" and not dq:
            sq = not sq; res.append(c); i += 1; continue
        if c == '"' and not sq:
            dq = not dq; res.append(c); i += 1; continue
        if not sq and (text.startswith("$(", i) or (not dq and text[i:i + 2] in ("<(", ">("))):
            if text.startswith("$((", i):  # arithmetic expansion: no command
                depth, j = 0, i + 1
                while j < n:
                    if text[j] == "(":
                        depth += 1
                    elif text[j] == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                res.append("0"); i = j + 1; continue
            depth, j, isq, idq = 1, i + 2, False, False
            while j < n and depth:
                ch = text[j]
                if ch == "\\" and j + 1 < n:
                    j += 2; continue
                if ch == "'" and not idq:
                    isq = not isq
                elif ch == '"' and not isq:
                    idq = not idq
                elif not isq and not idq:
                    if ch == "(":
                        depth += 1
                    elif ch == ")":
                        depth -= 1
                j += 1
            inner.append(text[i + 2:j - 1]); res.append(SUBST); i = j; continue
        if c == "`" and not sq:
            j = text.find("`", i + 1)
            j = n if j < 0 else j
            inner.append(text[i + 1:j]); res.append(SUBST); i = j + 1; continue
        res.append(c); i += 1
    return "".join(res), inner


def unquoted_newlines_to_semicolons(text):
    out, sq, dq, i = [], False, False, 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text):
            if text[i + 1] == "\n":
                out.append(" "); i += 2; continue
            out.append(text[i:i + 2]); i += 2; continue
        if c == "'" and not dq:
            sq = not sq
        elif c == '"' and not sq:
            dq = not dq
        elif c == "\n" and not sq and not dq:
            out.append(" ; "); i += 1; continue
        out.append(c); i += 1
    return "".join(out)


OPS = {";", "&&", "||", "|", "&", "|&", "(", ")", ";;"}
REDIRS = {">", ">>", ">|", "&>", "&>>", ">&", "<", "<<", "<<-", "<<<", "<>", "<&"}


def tokenize(text):
    lex = shlex.shlex(text, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    return list(lex)


def split_commands(tokens):
    """Split a token stream into simple commands: list of (words, redirects[(op, target)])."""
    cmds, words, redirs, i = [], [], [], 0
    while i < len(tokens):
        t = tokens[i]
        if t in OPS:
            if words or redirs:
                cmds.append((words, redirs))
            words, redirs = [], []
            i += 1; continue
        if t in REDIRS or re.fullmatch(r"[<>&|]+", t):
            if words and re.fullmatch(r"\d", words[-1]):
                words.pop()  # fd number glued to the operator, e.g. 2>&1
            target = tokens[i + 1] if i + 1 < len(tokens) else ""
            redirs.append((t, target)); i += 2; continue
        words.append(t); i += 1
    if words or redirs:
        cmds.append((words, redirs))
    return cmds


# ----------------------------------------------------------------------------- normalization
def strip_prefixes(words):
    """Drop env assignments, shell keywords and transparent wrappers; resolve binary paths."""
    w = list(words)
    changed = True
    while w and changed:
        changed = False
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w[0]):
            w.pop(0); changed = True; continue
        if w[0] in ("!", "then", "do", "else", "elif", "if", "while", "until", "{", "}", "time", "command",
                    "builtin", "nohup", "exec", "nice", "caffeinate"):
            if w[0] == "command" and len(w) > 1 and w[1] in ("-v", "-V"):
                return ["which"] + w[2:]
            w.pop(0); changed = True; continue
        if w[0] == "env":
            w.pop(0)
            while w and (w[0].startswith("-") or "=" in w[0]):
                w.pop(0)
            changed = True; continue
        if w[0] in ("timeout", "gtimeout") and len(w) > 1:
            w.pop(0)
            while w and (w[0].startswith("-") or re.fullmatch(r"[\d.]+[smhd]?", w[0])):
                w.pop(0)
            changed = True; continue
    if w and "/" in w[0]:
        d, b = os.path.split(w[0])
        if d in STD_BIN_DIRS or "node_modules/.bin" in d or d.endswith("/.agent-kit/bin") or d.endswith("/.local/bin"):
            w[0] = b
    return w


def drop_opts(args, with_value, flags=(), eq_prefixes=()):
    out, i = [], 0
    while i < len(args):
        a = args[i]
        if a in with_value:
            i += 2; continue
        if a in flags or any(a.startswith(p) for p in eq_prefixes):
            i += 1; continue
        out.append(a); i += 1
    return out


def normalize(words):
    """Canonical form used for prefix matching (e.g. `git -C x log` -> `git log`)."""
    w = strip_prefixes(words)
    if not w:
        return w
    h = w[0]
    if h == "git":
        return ["git"] + drop_opts(w[1:], {"-C", "-c", "--git-dir", "--work-tree", "--namespace"},
                                   {"--no-pager", "-P", "--paginate", "--no-optional-locks", "--bare"},
                                   ("--git-dir=", "--work-tree=", "-c=", "--namespace="))
    if h in ("pnpm", "npm", "yarn", "bun"):
        return [h] + drop_opts(w[1:], {"--dir", "-C", "--filter", "-F", "--prefix", "--workspace", "-w", "--cwd"},
                               {"--silent", "-s", "--workspace-root", "-r", "--recursive", "--if-present",
                                "--reporter=silent", "-q", "--quiet"},
                               ("--dir=", "--filter=", "--prefix=", "--workspace=", "--cwd="))
    if h == "terraform":
        return ["terraform"] + [a for a in w[1:] if not a.startswith("-chdir=")]
    if h == "gh":
        return ["gh"] + drop_opts(w[1:], {"-R", "--repo"}, (), ("--repo=",))
    if h == "docker-compose":
        return ["docker", "compose"] + w[1:]
    if h == "docker" and len(w) > 1 and w[1] == "compose":
        return ["docker", "compose"] + drop_opts(w[2:], {"-f", "--file", "-p", "--project-name", "--env-file",
                                                         "--profile", "--project-directory"}, (),
                                                 ("--file=", "--project-name=", "--env-file=", "--profile="))
    if h == "aws":
        return ["aws"] + drop_opts(w[1:], {"--region", "--profile", "--output", "--query", "--color", "--endpoint-url",
                                           "--cli-read-timeout", "--cli-connect-timeout"},
                                   {"--no-cli-pager", "--no-paginate", "--debug", "--no-verify-ssl"},
                                   ("--region=", "--profile=", "--output=", "--query="))
    return w


def starts_with(words, prefix):
    p = prefix.split()
    return words[:len(p)] == p


# ----------------------------------------------------------------------------- classification
class Ctx:
    def __init__(self, pol, cwd, bodies):
        self.pol, self.cwd, self.bodies = pol, cwd, list(bodies)
        self.notes = []


def in_temp(path, ctx):
    if not path:
        return False
    if path in ("/dev/null", "/dev/stdout", "/dev/stderr") or re.fullmatch(r"&?\d|-", path):
        return True
    if path.startswith("$TMPDIR") or path.startswith("${TMPDIR"):
        return True
    p = os.path.normpath(os.path.join(ctx.cwd, os.path.expanduser(path)))
    return any(p == d or p.startswith(d.rstrip("/") + "/") for d in ctx.pol["temp_dirs"] if d)


def write_target_ok(path, ctx):
    if in_temp(path, ctx):
        return True
    if not ctx.pol.get("allow_local_writes"):
        return False
    root = repo_root(ctx.cwd)
    p = os.path.normpath(os.path.join(ctx.cwd, os.path.expanduser(path)))
    rel = os.path.relpath(p, root)
    return not rel.startswith("..") and any(fnmatch.fnmatch(rel, g) for g in ctx.pol.get("write_allow_globs", []))


def classify_simple(words, ctx):
    """Return (decision, reason) for one simple command (words already include no operators)."""
    pol = ctx.pol
    w = normalize(words)
    if not w:
        return ALLOW, ""
    h = w[0]
    if h.startswith("$") or SUBST in h:
        return DEFER, "dynamic command name"
    if h in ("for", "select", "case", "function") or h.endswith("()") or (len(w) > 1 and w[1] in ("()", "(")):
        return (DEFER, "case/function") if h in ("case", "function") or h.endswith("()") else (ALLOW, "")
    if h in ("done", "fi", "esac", "in", "read", "break", "continue", "local", "return", "exit", "trap", "let",
             "declare", "typeset", "readonly", "jobs"):
        return ALLOW, ""
    if h in ("bash", "sh", "zsh", "dash") and len(w) >= 3 and re.fullmatch(r"-[a-z]*c", w[1]):
        res = evaluate(w[2], ctx.cwd, pol, 1)  # look inside `bash -c "..."`
        return res["decision"], res["reason"]
    if h == "cd" or h == "pushd":
        target = w[1] if len(w) > 1 else "~"
        if SUBST not in target and not target.startswith("$"):
            ctx.cwd = os.path.normpath(os.path.join(ctx.cwd, os.path.expanduser(target)))
        return ALLOW, ""
    for p in pol.get("deny_prefixes", []):
        if starts_with(w, p):
            return DENY, "denied by policy prefix: %s" % p
    for p in pol.get("allow_prefixes", []):
        if starts_with(w, p) or starts_with(words, p):
            return ALLOW, ""
    for p in pol.get("readonly_prefixes", []):
        if starts_with(w, p):
            return ALLOW, ""
    if pol.get("allow_local_writes"):
        for p in pol.get("local_write_prefixes", []):
            if starts_with(w, p):
                return ALLOW, ""

    # command-specific rules
    if h in pol["readonly_commands"]:
        if h == "sort" and any(a in ("-o", "--output") or a.startswith("--output=") for a in w):
            i = w.index("-o") if "-o" in w else -1
            return (ALLOW, "") if i >= 0 and i + 1 < len(w) and in_temp(w[i + 1], ctx) else (DEFER, "sort -o")
        if h == "jq" and any(a in ("-i", "--in-place") for a in w):
            return DEFER, "jq in-place"
        if h == "openssl" and len(w) > 1 and w[1] not in ("x509", "s_client", "version", "dgst", "rand", "req", "verify"):
            return DEFER, "openssl subcommand"
        return ALLOW, ""
    if h == "tee":
        targets = [a for a in w[1:] if not a.startswith("-")]
        return (ALLOW, "") if all(write_target_ok(t, ctx) for t in targets) else (DEFER, "tee to project file")
    if h in ("sed", "gsed"):
        if any(re.match(r"^-[a-zA-Z]*i", a) or a.startswith("--in-place") for a in w[1:]):
            return DEFER, "sed in-place"
        script = " ".join(a for a in w[1:] if not a.startswith("-"))
        return (DEFER, "sed w command") if re.search(r"(^|[;}\s])w\s+\S", script) else (ALLOW, "")
    if h in ("awk", "gawk", "mawk"):
        prog = " ".join(w[1:])
        return (DEFER, "awk writes/execs") if re.search(r"system\(|\|\s*getline|print[f]?[^;]*>\s*\"|\">\s*\"", prog) else (ALLOW, "")
    if h in ("find", "fd"):
        if any(a in ("-delete", "-fprint", "-fprint0", "-fprintf", "-fls") for a in w):
            return DEFER, "find writes"
        for flag in ("-exec", "-execdir", "-ok", "-okdir"):
            if flag in w:
                i = w.index(flag) + 1
                inner = []
                while i < len(w) and w[i] not in (";", "+", "\\;"):
                    inner.append(w[i]); i += 1
                inner = [x for x in inner if x != "{}"]
                d, r = classify_simple(inner, ctx)
                if d != ALLOW:
                    return d, "find -exec: " + r
        return ALLOW, ""
    if h == "xargs":
        i = 1
        while i < len(w) and w[i].startswith("-"):
            i += 2 if w[i] in ("-I", "-n", "-P", "-L", "-d", "-s", "-E") else 1
        inner = [x for x in w[i:] if x != "{}"] or ["echo"]
        return classify_simple(inner, ctx)
    if h in ("rm", "rmdir", "cp", "mv", "ln", "chmod", "unzip", "tar"):
        paths = [a for a in w[1:] if not a.startswith("-")]
        if h == "unzip" and "-d" in w:
            paths = [w[w.index("-d") + 1]] if w.index("-d") + 1 < len(w) else []
        if h == "tar":
            return (ALLOW, "") if re.match(r"^-?[tv]*t", w[1] if len(w) > 1 else "") else (DEFER, "tar extract/create")
        if paths and all(in_temp(p, ctx) for p in paths):
            return ALLOW, ""
        if h == "cp" and len(paths) >= 2 and in_temp(paths[-1], ctx):
            return ALLOW, ""  # copying project files into a temp dir
        return DEFER, "%s outside temp dirs" % h
    if h == "curl":
        bad = ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-F", "--form", "-T",
               "--upload-file", "--json", "-K", "--config")
        for i, a in enumerate(w):
            if a in bad or any(a.startswith(b + "=") for b in bad if b.startswith("--")):
                return DEFER, "curl sends data"
            if a in ("-X", "--request") and i + 1 < len(w) and w[i + 1].upper() not in ("GET", "HEAD", "OPTIONS"):
                return DEFER, "curl %s" % w[i + 1]
            if re.match(r"^-X(POST|PUT|PATCH|DELETE)", a, re.I):
                return DEFER, "curl write method"
            if a in ("-o", "--output") and i + 1 < len(w) and not in_temp(w[i + 1], ctx):
                return DEFER, "curl -o to project path"
        return ALLOW, ""
    if h == "sqlite3":
        return (ALLOW, "") if "-readonly" in w else (DEFER, "sqlite3 without -readonly")
    if h == "git":
        sub = w[1] if len(w) > 1 else ""
        if sub == "branch":
            rest = [a for a in w[2:]]
            if any(a in ("-d", "-D", "--delete", "-m", "-M", "--move", "-c", "-C", "--copy", "-f", "--force",
                         "-u", "--set-upstream-to", "--unset-upstream", "--edit-description") for a in rest):
                return DEFER, "git branch mutation"
            positional = [a for a in rest if not a.startswith("-")]
            listing = any(a in ("-l", "--list", "-a", "-r", "--all", "--remotes", "--contains", "--merged",
                                "--no-merged", "--points-at", "--show-current", "-v", "-vv") for a in rest)
            if positional and not listing:
                return (ALLOW, "") if pol.get("allow_local_writes") else (DEFER, "git branch create")
            return ALLOW, ""
        if sub == "tag":
            rest = w[2:]
            return (ALLOW, "") if not rest or any(a in ("-l", "--list", "--contains", "--points-at") for a in rest) else (DEFER, "git tag create")
        if sub == "stash" and len(w) == 2:
            return (ALLOW, "") if pol.get("allow_local_writes") else (DEFER, "git stash")
        return DEFER, "git %s" % sub
    if h == "gh" and len(w) > 1 and w[1] == "api":
        rest = w[2:]
        for i, a in enumerate(rest):
            if a in ("-X", "--method") and i + 1 < len(rest) and rest[i + 1].upper() != "GET":
                return DEFER, "gh api non-GET"
            if a in ("-f", "-F", "--field", "--raw-field", "--input") or re.match(r"^-X(?!GET)", a):
                return DEFER, "gh api with body"
        return ALLOW, ""
    if h == "aws" and len(w) >= 3:
        svc, op = w[1], w[2]
        if "%s %s" % (svc, op) in pol.get("aws_sensitive_ops", []):
            return DEFER, "aws sensitive read"
        if svc == "ssm" and op in ("get-parameter", "get-parameters", "get-parameters-by-path") and "--with-decryption" in w:
            return DEFER, "aws ssm decrypt"
        if re.match(pol["aws_readonly_op_regex"], op):
            return ALLOW, ""
        return DEFER, "aws %s %s" % (svc, op)
    if h in ("pnpm", "npm", "yarn", "bun"):
        args = w[1:]
        if args and args[0] in ("exec", "dlx", "x") or (h == "yarn" and args and args[0] not in ("run", "install")):
            tool = args[1:] if args and args[0] in ("exec", "dlx", "x") else args
            return classify_js_tool(tool, ctx)
        if args and args[0] in ("run", "run-script"):
            args = args[1:]
        if args and h == "npm" and args[0] == "test":
            return ALLOW, ""
        script = args[0] if args else ""
        if script in pol.get("package_scripts_readonly", []) or re.match(r"^(test|lint|typecheck|type-check|check)(:|$)", script):
            return ALLOW, ""
        if pol.get("allow_local_writes") and script in pol.get("local_package_scripts", []):
            return ALLOW, ""
        return DEFER, "%s %s" % (h, script)
    if h in ("npx", "bunx"):
        args = [a for a in w[1:] if a not in ("--no-install", "-y", "--yes", "--no")]
        return classify_js_tool(args, ctx)
    if h in ("tsc", "vitest", "jest", "biome", "eslint", "prettier", "astro", "next", "playwright", "knip"):
        return classify_js_tool(w, ctx)
    if h == "python3" or h == "python":
        if len(w) >= 2 and w[1] in ("--version", "-V"):
            return ALLOW, ""
        if "-m" in w:
            mod = w[w.index("-m") + 1] if w.index("-m") + 1 < len(w) else ""
            if mod in ("json.tool", "py_compile", "pyflakes", "tabnanny"):
                return ALLOW, ""
        return DEFER, "python code"
    return DEFER, "unlisted command: %s" % h


def classify_js_tool(args, ctx):
    if not args:
        return DEFER, "js tool"
    t = args[0].split("/")[-1].split("@")[0] or args[0]
    joined = " ".join([t] + args[1:])
    for p in ctx.pol.get("js_tools_readonly", []):
        if starts_with(joined.split(), p):
            if t == "biome" and any(a in ("--write", "--fix", "--apply", "--unsafe") for a in args):
                return (ALLOW, "") if ctx.pol.get("allow_local_writes") else (DEFER, "biome --write")
            if t == "eslint" and "--fix" in args and not ctx.pol.get("allow_local_writes"):
                return DEFER, "eslint --fix"
            return ALLOW, ""
    if ctx.pol.get("allow_local_writes"):
        for p in ctx.pol.get("local_write_prefixes", []):
            if starts_with(joined.split(), p):
                return ALLOW, ""
    if t not in ("tsc", "vitest", "jest", "biome", "eslint", "prettier", "astro", "next", "playwright", "knip", "tsx",
                 "ts-node", "node"):
        d, r = classify_simple([t] + list(args[1:]), ctx)  # e.g. `npx openspec validate` → openspec rules
        if d == ALLOW:
            return d, r
    return DEFER, "js tool: %s" % t


# ----------------------------------------------------------------------------- guards
def guard(raw, cmds, ctx):
    """Return a deny reason or None. `cmds` = list of (normalized words, redirects, cwd-at-command)."""
    g = ctx.pol["guards"]
    for w, redirs, cwd in cmds:
        is_commit = starts_with(w, "git commit")
        is_pr = starts_with(w, "gh pr create") or starts_with(w, "gh pr edit") or starts_with(w, "gh pr comment")
        if g.get("no_ai_trailers") and (is_commit or is_pr):
            if TRAILER_RE.search(" ".join(w)) or any(TRAILER_RE.search(b) for b in ctx.bodies):
                return "Policy: no Co-Authored-By trailers or 'Generated with Claude' footers in commits/PRs. Remove them and retry."
        if g.get("gitleaks_on_commit") and is_commit:
            r = gitleaks(cwd)
            if r:
                return r
        if g.get("block_shell_edits"):
            r = shell_edit(w, redirs, ctx)
            if r:
                return "Policy: edit files with your Edit/Write tools, not the shell (%s). Writing under temp dirs is fine." % r
    return None


def shell_edit(w, redirs, ctx):
    if not w:
        return None
    h = w[0]
    files = [a for a in w[1:] if not a.startswith("-")]
    if h in ("sed", "gsed") and any(re.match(r"^-[a-zA-Z]*i", a) or a.startswith("--in-place") for a in w[1:]):
        pos = [a for a in files if a != ""]  # "" is the macOS `-i ''` backup suffix
        has_e = any(a in ("-e", "-f", "--expression", "--file") for a in w)
        targets = pos if has_e else pos[1:]
        if not targets or not all(in_temp(t, ctx) for t in targets):
            return "sed -i"
    if h == "perl" and any(re.match(r"^-[a-zA-Z]*i", a) for a in w[1:]):
        targets = [a for a in files if not a.startswith("'")][1:]
        if not targets or not all(in_temp(t, ctx) for t in targets):
            return "perl -i"
    heredoc = any(op in ("<<", "<<-") for op, _ in redirs)
    if h in ("python", "python3", "node", "ruby", "perl", "bun", "deno", "tsx"):
        code = ""
        for flag in ("-c", "-e", "--eval"):
            if flag in w and w.index(flag) + 1 < len(w):
                code += w[w.index(flag) + 1]
        if heredoc or (len(w) > 1 and w[1] == "-"):
            code += "\n".join(ctx.bodies)
        if code and WRITE_CODE_RE.search(code):
            paths = [m.group(1) for m in LITERAL_PATH_RE.finditer(code)]
            if not paths or not all(in_temp(p, ctx) for p in paths):
                return "%s script writing files" % h
    if heredoc or h in ("cat", "echo", "printf"):
        for op, target in redirs:
            if op in (">", ">>", ">|", "&>") and heredoc and not in_temp(target, ctx):
                return "heredoc into %s" % target
        if h == "tee" and heredoc:
            t = [a for a in w[1:] if not a.startswith("-")]
            if t and not all(in_temp(x, ctx) for x in t):
                return "heredoc into %s" % t[0]
    return None


def gitleaks(cwd):
    if not shutil_which("gitleaks"):
        return None
    try:
        if subprocess.run(["git", "-C", cwd, "rev-parse", "--git-dir"], capture_output=True, timeout=5).returncode:
            return None
        found = []
        for extra in ([], ["--staged"]):
            r = subprocess.run(["gitleaks", "git", "--pre-commit", *extra, "-v", "--no-color", "--redact", "--no-banner",
                                "--exit-code", "3"], cwd=cwd, capture_output=True, text=True, timeout=60)
            if r.returncode == 3:
                found += [l.strip() for l in (r.stdout + r.stderr).splitlines()
                          if re.match(r"\s*(RuleID|File|Line):", l)]
        if found:
            return "gitleaks found possible secrets in uncommitted changes; commit blocked:\n" + "\n".join(sorted(set(found))[:20])
    except Exception:
        return None
    return None


def shutil_which(name):
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


# ----------------------------------------------------------------------------- top level
def evaluate(raw, cwd=None, pol=None, depth=0):
    cwd = os.path.abspath(os.path.expanduser(cwd or os.getcwd()))
    pol = pol or load_policy(cwd)
    text, bodies = extract_heredocs(raw)
    text, inner = extract_substitutions(text)
    ctx = Ctx(pol, cwd, bodies)
    try:
        cmds = split_commands(tokenize(unquoted_newlines_to_semicolons(text)))
    except ValueError as e:
        return {"decision": DEFER, "reason": "unparseable: %s" % e, "parts": []}
    parts, normed = [], []
    shape = {"cd": [w[1] if len(w) > 1 else "~" for w, _ in cmds if w and w[0] in ("cd", "pushd")] if len(cmds) > 1 else [],
             "loop": any(w and w[0] in ("for", "while", "until", "select") for w, _ in cmds)}
    for words, redirs in cmds:
        before = ctx.cwd
        d, r = classify_simple(words, ctx)
        normed.append((normalize(words), redirs, before))
        for op, target in redirs:
            if op in (">", ">>", ">|", "&>", "&>>") and not write_target_ok(target, ctx):
                if d == ALLOW:
                    d, r = DEFER, "redirect into %s" % target
        parts.append({"cmd": " ".join(words)[:120], "decision": d, "reason": r})
    deny = guard(raw, normed, ctx)
    if deny:
        return {"decision": DENY, "reason": deny, "parts": parts}
    for sub in inner:
        if depth < 5:
            res = evaluate(sub, ctx.cwd, pol, depth + 1)
            parts.append({"cmd": "$(%s)" % sub[:100], "decision": res["decision"], "reason": res["reason"]})
            if res["decision"] == DENY:
                return {"decision": DENY, "reason": res["reason"], "parts": parts}
    blocking = [p for p in parts if p["decision"] != ALLOW]
    if not blocking:
        return {"decision": ALLOW, "reason": "agent-policy: all %d part(s) read-only or permitted" % len(parts),
                "parts": parts, "shape": shape}
    return {"decision": DEFER, "reason": "; ".join(sorted({p["reason"] for p in blocking}))[:300], "parts": parts}


# ----------------------------------------------------------------------------- rewrite hints
def rewrite_hint(shape):
    what, tips = [], []
    if shape.get("cd"):
        d = shape["cd"][0]
        what.append("`cd` chains")
        tips.append("Drop the `cd %s &&`: use absolute paths or the tool's directory flag (`git -C %s`, "
                    "`pnpm --dir %s`, `npm --prefix %s`, `terraform -chdir=%s`, `make -C %s`, `rg PATTERN %s`). "
                    "If the tool has no such flag, run `cd %s` as its own call, then the command." % ((d,) * 8))
    if shape.get("loop"):
        what.append("shell loops")
        tips.append("Replace the loop with one command that takes several paths (`wc -l a b c`, `head -n 40 a b`, "
                    "`grep -n PAT a b`, `ls -la d1 d2`), or `find DIR -name GLOB -exec CMD {} +`.")
    return ("agent-policy rewrite hint: Claude Code asks the user to approve %s even when they are read-only. "
            "Retry with a rewritten command; don't ask the user. " % " and ".join(what)) + " ".join(tips)


def hint_gate(pol, session, cmd, wants_hint):
    """True if a rewrite hint should be issued. Per-session limits live in a temp state file."""
    limit = int((pol.get("rewrite_hints") or {}).get("max_consecutive", 2))
    name = re.sub(r"[^\w.-]", "_", session or "nosession") + ".json"
    path = os.path.join(tempfile.gettempdir(), "agent-kit-hints", name)
    try:
        with open(path) as f:
            st = json.load(f)
    except Exception:
        st = {"consecutive": 0, "hinted": []}
    key = hashlib.sha1(cmd.encode()).hexdigest()[:16]
    if wants_hint:
        if key in st["hinted"] or st["consecutive"] >= limit:
            return False  # repeat or limit reached: the harness prompts as usual
        st["consecutive"] += 1
        st["hinted"] = (st["hinted"] + [key])[-200:]
    elif st["consecutive"] == 0:
        return False
    else:
        st["consecutive"] = 0
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(st, f)
    except OSError:
        pass
    return wants_hint


def hints_enabled(pol, harness):
    if "0" in (os.environ.get("AGENT_REWRITE_HINTS"), os.environ.get("CLAUDE_REWRITE_HINTS")):
        return False
    cfg = pol.get("rewrite_hints") or {}
    return bool(cfg.get("enabled", True)) and harness in cfg.get("harnesses", ["claude"])


# ----------------------------------------------------------------------------- harness adapters
def hook(harness):
    try:
        data = json.load(sys.stdin)
    except Exception:
        return 0
    if harness in ("claude", "codex", "gemini"):
        ti = data.get("tool_input") or {}
        cmd, cwd = ti.get("command"), data.get("cwd")
    elif harness == "cursor":
        cmd, cwd = data.get("command"), data.get("cwd") or (data.get("workspace_roots") or [None])[0]
    else:
        cmd, cwd = data.get("command"), data.get("cwd")
    if not cmd:
        return 0
    pol = load_policy(os.path.abspath(os.path.expanduser(cwd or os.getcwd())))
    res = evaluate(cmd, cwd, pol)
    d, reason = res["decision"], res["reason"]
    if d != DENY and hints_enabled(pol, harness):
        shape = res.get("shape") or {}
        wants = d == ALLOW and bool(shape.get("cd") or shape.get("loop"))
        if hint_gate(pol, data.get("session_id") or data.get("conversation_id"), cmd, wants):
            d, reason = DENY, rewrite_hint(shape)
    if harness in ("claude", "codex"):
        if d == DEFER:
            return 0
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": d,
                                                 "permissionDecisionReason": reason}}))
    elif harness == "gemini":
        if d == DENY:
            print(json.dumps({"decision": "deny", "reason": reason}))
        elif d == ALLOW:
            print(json.dumps({"decision": "allow", "reason": reason}))
    elif harness == "cursor":
        if d == DENY:
            print(json.dumps({"permission": "deny", "user_message": reason, "agent_message": reason}))
        elif d == ALLOW:
            print(json.dumps({"permission": "allow"}))
        else:
            print("{}")
    return 0


# ----------------------------------------------------------------------------- self-test
TESTS = [
    ("git status", ALLOW), ("git -C /repo log --oneline -5", ALLOW), ("cd /tmp && grep -rn foo . | head", ALLOW),
    ("for f in a b; do cat $f; done", ALLOW), ("A=~/x; sed -n '1,20p' $A/f.md", ALLOW),
    ("ls $(git rev-parse --show-toplevel)", ALLOW), ("git log --format=%h -1 2>&1 | tail -3", ALLOW),
    ("terraform -chdir=infra plan -no-color", ALLOW), ("pnpm --dir apps/web test", ALLOW),
    ("AWS_PROFILE=x aws ecs describe-services --cluster c --services s", ALLOW),
    ("aws secretsmanager get-secret-value --secret-id x", DEFER), ("aws s3 cp a s3://b/", DEFER),
    ("find . -name '*.ts' -exec grep -l foo {} +", ALLOW), ("find . -name '*.tmp' -delete", DEFER),
    ("curl -s https://x/health", ALLOW), ("curl -X POST https://x -d a=1", DEFER),
    ("rm -rf /tmp/scratch", ALLOW), ("rm -rf build", DEFER), ("git push origin main", DEFER),
    ("gh pr view 12 --json state", ALLOW), ("gh pr create --title x --body y", DEFER),
    ("gh api repos/o/r/pulls", ALLOW), ("gh api -X POST repos/o/r/issues -f title=x", DEFER),
    ("sed -i '' 's/a/b/' src/x.ts", DENY), ("sed -i '' 's/a/b/' /tmp/x.ts", DEFER),
    ("cat > src/a.ts <<EOF\nx\nEOF", DENY), ("cat > /tmp/a.json <<'EOF'\n{}\nEOF", ALLOW),
    ("python3 - <<'EOF'\np='src/a.ts'; s=open(p).read(); open(p,'w').write(s)\nEOF", DENY),
    ("python3 - <<'EOF'\nimport json; print(json.load(open('/tmp/x.json')))\nEOF", DEFER),
    ("python3 /tmp/sim.py <<'EOF'\nprint('sed -i inside a heredoc body is data')\nEOF", DEFER),
    ("git commit -m \"fix: x\n\nCo-Authored-By: Claude <noreply@anthropic.com>\"", DENY),
    ("git add -A && git commit -m 'fix: clean'", ALLOW), ("git log > .artifacts/log.txt", ALLOW),
    ("git log > notes.txt", DEFER), ("echo hi > /dev/null", ALLOW), ("$G status", DEFER),
    ("npx vitest run src/a.test.ts", ALLOW), ("npx biome check --write src", ALLOW),
    ("pnpm exec tsc --noEmit", ALLOW), ("pnpm install", ALLOW), ("pnpm add lodash", DEFER),
    ("docker compose -f x.yml ps", ALLOW), ("docker compose up -d", DEFER), ("verify --quick", ALLOW),
    ("wait-for url http://localhost:3000 200", ALLOW), ("/usr/bin/grep -n foo a.txt", ALLOW),
    ("xargs -I{} rm {}", DEFER), ("ls | xargs wc -l", ALLOW), ("t(){ cat $1; }; t a", DEFER),
    ("sqlite3 -readonly db.sqlite '.tables'", ALLOW), ("git branch -a --contains abc", ALLOW),
    ("git branch -D old", DEFER), ("git checkout -b feat/x", ALLOW), ("git checkout -- src/a.ts", DEFER),
    ("echo $((1+2))", ALLOW), ("bash -c 'git status && ls'", ALLOW), ("bash -c 'rm -rf src'", DEFER),
    ("while read f; do wc -l \"$f\"; done < list.txt", ALLOW), ("npx openspec validate x --strict", ALLOW),
    ("bash /tmp/linear-q.sh", DEFER), ("awk '{print $1}' f | sort | uniq -c", ALLOW), ("awk '{system(\"rm x\")}' f", DEFER),
]


def self_test():
    work = "/work/repo"  # a non-temp project dir (needn't exist)
    pol = load_policy(work)
    pol["guards"]["gitleaks_on_commit"] = False
    fails = 0
    for cmd, want in TESTS:
        got = evaluate(cmd, work, pol)
        ok = got["decision"] == want
        fails += not ok
        if not ok:
            print("FAIL want=%-5s got=%-5s %r  (%s)" % (want, got["decision"], cmd, got["reason"]))
    # rewrite-hint limits: hint, hint, limit reached, clean command resets, hint again, never repeat a command
    sess = "selftest-%d" % os.getpid()
    seq = [("cd /a && ls", True, True), ("for f in a b; do cat $f; done", True, True), ("cd /b && ls", True, False),
           ("ls", False, False), ("cd /c && ls", True, True), ("cd /c && ls", True, False)]
    for cmd, wants, want in seq:
        got = hint_gate(pol, sess, cmd, wants)
        fails += got != want
        if got != want:
            print("FAIL hint_gate %r want=%s got=%s" % (cmd, want, got))
    try:
        os.remove(os.path.join(tempfile.gettempdir(), "agent-kit-hints", sess + ".json"))
    except OSError:
        pass
    total = len(TESTS) + len(seq)
    print("%d/%d passed" % (total - fails, total))
    return 1 if fails else 0


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__); return 0
    if argv[0] == "hook":
        return hook(argv[1] if len(argv) > 1 else "claude")
    if argv[0] == "test":
        return self_test()
    if argv[0] == "check":
        args, cwd, as_json, cmd = argv[1:], None, False, None
        while args:
            a = args.pop(0)
            if a == "--cwd":
                cwd = args.pop(0)
            elif a == "--json":
                as_json = True
            else:
                cmd = a
        cmd = cmd if cmd is not None else sys.stdin.read()
        res = evaluate(cmd, cwd)
        if as_json:
            print(json.dumps(res))
        else:
            print("%s  %s" % (res["decision"].upper(), res["reason"]))
            for p in res["parts"]:
                print("  %-5s %s%s" % (p["decision"], p["cmd"], ("  (%s)" % p["reason"]) if p["reason"] else ""))
        return 0
    print(__doc__); return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
