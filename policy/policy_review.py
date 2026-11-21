#!/usr/bin/env python3
"""policy_review — scoped policy, a reviewed proposal queue, and harness directory sync for agent-policy.

`bin/agent-policy` runs this file. It adds three things on top of policy/agent_policy.py (which it wraps, unchanged):

1. Scopes (folder-specific policy). `config/scopes/<name>.json` = {"match": [path globs], ...policy keys}. A scope
   applies when the working directory, or any parent of it, matches one of its globs (`~` expands). Scopes only WIDEN
   (list keys append; `directories` merges); they sit between the user overlay and the main checkout's
   `.agent-policy.json`. Broader access for a folder tree (e.g. every worktree of one product) goes here.
2. Proposals. Session retros queue candidate entries; nothing reaches a policy file until a human accepts it.
     agent-policy proposals add FILE            (JSON list or JSONL of proposals; merges evidence, dedupes)
     agent-policy proposals list [--all|--status S] [--json]
     agent-policy proposals show ID
     agent-policy proposals accept ID [--target T] [--match GLOB]   T = repo:<path> | scope:<name> | user | base
     agent-policy proposals reject ID --reason TEXT       (remembered; never proposed again)
     agent-policy proposals gate ID --reason TEXT         (keep-gated: must keep prompting; never accepted)
   Keys: readonly_prefixes, local_write_prefixes, allow_prefixes, deny_prefixes, write_allow_globs,
   directories.read, directories.write, habit_hints ({"pattern": regex, "hint": text}).
   Destructive / publishing commands and credential or over-broad directories are auto-gated and cannot be accepted.
3. Directory sync. `directories.read/write` render into each harness's own config — the hook cannot lift
   Claude Code's outside-the-working-folder prompt.
     agent-policy sync [--cwd DIR] [--all-worktrees] [--dry-run]   Claude: <checkout>/.claude/settings.local.json
     agent-policy sync --user [--dry-run]                          Claude: ~/.claude/settings.json (base + user overlay)
     agent-policy scopes [--cwd DIR]                               which scopes apply here
   Plus `habit_hints`: the Claude hook denies a matching command once with the hint, so the agent rewrites it
   instead of tripping Claude's built-in safety prompt.

State (machine-local, git-ignored): <kit>/state/proposals.json, decisions.jsonl, sync.json, hints/.
Self-test: agent-policy review-test
"""
import copy
import fnmatch
import glob
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import agent_policy as ap  # noqa: E402

KIT = ap.KIT
HOME = os.path.expanduser("~")
STATE = os.environ.get("AGENT_KIT_STATE") or os.path.join(KIT, "state")
SCOPES = os.environ.get("AGENT_KIT_SCOPES") or os.path.join(KIT, "config", "scopes")
USER_OVERLAY = os.path.expanduser("~/.config/agent-kit/policy.json")
LIST_KEYS = ("readonly_prefixes", "local_write_prefixes", "allow_prefixes", "deny_prefixes", "write_allow_globs",
             "habit_hints")
DIR_KEYS = ("directories.read", "directories.write")
KEYS = LIST_KEYS + DIR_KEYS
WIDENING = ("readonly_prefixes", "local_write_prefixes", "allow_prefixes", "write_allow_globs") + DIR_KEYS


# ----------------------------------------------------------------------------- scopes
def _x(p):
    return os.path.normpath(os.path.expanduser(p))


def matching_scopes(cwd):
    """[(depth, name, data)] for scopes whose globs match cwd or a parent of it, broadest first."""
    cwd = os.path.realpath(_x(cwd))
    chain, p = [], cwd
    while True:
        chain.append(p)
        parent = os.path.dirname(p)
        if parent == p:
            break
        p = parent
    out = []
    for f in sorted(glob.glob(os.path.join(SCOPES, "*.json"))):
        try:
            with open(f) as fh:
                data = json.load(fh)
        except Exception as e:
            sys.stderr.write("agent-policy: ignoring scope %s (%s)\n" % (f, e))
            continue
        best = -1
        for g in data.get("match", []):
            g = _x(g)
            for a in chain:
                if fnmatch.fnmatch(a, g) or fnmatch.fnmatch(os.path.realpath(a), g):
                    best = max(best, a.count("/"))
        if best >= 0:
            out.append((best, os.path.splitext(os.path.basename(f))[0], data))
    return sorted(out, key=lambda t: t[0])


def merge_scope(pol, data):
    for k, v in data.items():
        if k.startswith("_") or k == "match":
            continue
        if k == "directories" and isinstance(v, dict):
            d = pol.setdefault("directories", {})
            for kk in ("read", "write"):
                d[kk] = list(d.get(kk, [])) + [x for x in v.get(kk, []) if x not in d.get(kk, [])]
        elif isinstance(v, list) and isinstance(pol.get(k, []), list):
            pol[k] = list(pol.get(k, [])) + v
        # scalars and other dicts are ignored: scopes only widen
    return pol


_orig_load = ap.load_policy
_cache = {}


def load_policy(cwd):
    key = os.path.realpath(_x(cwd or os.getcwd()))
    if key not in _cache:
        pol = _orig_load(cwd)
        for _, _, data in matching_scopes(key):
            merge_scope(pol, data)
        _cache[key] = pol
    return copy.deepcopy(_cache[key])


ap.load_policy = load_policy  # evaluate() and hook() resolve load_policy at call time


# ----------------------------------------------------------------------------- safety
HOME_RE = re.escape(HOME)
UNSAFE_CMD = re.compile(r"""^(
    sudo\b | rm\b | rmdir\b | unlink\b | shred\b | dd\b | mkfs | kill\b | pkill\b | killall\b | shutdown\b | reboot\b |
    chmod\s+-R | chown\s+-R |
    git\s+(push|reset|clean|rebase|filter-branch|filter-repo|update-ref|gc|prune|reflog\s+expire|stash\s+(drop|clear)|
           branch\s+-[dD]|tag\s+-d|worktree\s+remove|checkout\s+--|restore\b) |
    docker\s+(rm|rmi|kill|volume\s+rm|volume\s+prune|system\s+prune|image\s+prune|container\s+prune|builder\s+prune|
              network\s+(rm|prune)|compose\s+down) |
    (terraform|tofu)\s+(apply|destroy|import|state|taint|untaint|force-unlock) |
    aws\s+\S+\s+(delete|terminate|put|create|update|remove|modify|start|stop|reboot|attach|detach|run|invoke|send|
                 publish|deregister|register|revoke|authorize|reset|restore|copy|cp|mv|rm|sync) |
    gh\s+(pr\s+(create|merge|close|edit|comment|review|ready)|issue\s+(create|close|edit|comment|delete)|release|
          repo\s+(create|delete|edit|rename|archive)|secret|variable|workflow\s+(run|enable|disable)|run\s+(cancel|rerun)|
          api\s+.*-X\s*(POST|PUT|PATCH|DELETE)|api\s+.*(-f|-F|--field|--raw-field)\b) |
    kubectl\s+(delete|apply|scale|edit|patch|drain|cordon|replace|rollout) |
    (npm|pnpm|yarn|bun)\s+publish | eas\s+(submit|update|build) |
    curl\s+.*(-X\s*(POST|PUT|PATCH|DELETE)|--data|\s-d\s|--form|\s-F\s) |
    .*\bprune\b | .*\bdelete\b | .*\bdestroy\b
)""", re.X | re.I)
RUNS_ANYTHING = {"python", "python3", "node", "deno", "bun", "ruby", "perl", "php", "pwsh", "powershell", "bash", "sh",
                 "zsh", "fish", "env", "eval", "exec", "xargs", "nohup", "time", "timeout", "watch", "command",
                 "npx", "pnpm", "pnpm exec", "pnpm dlx", "npm", "npm exec", "yarn", "uv", "uv run", "uvx", "pipx",
                 "dotnet", "go", "cargo", "make", "just", "docker", "docker exec", "docker run", "docker compose",
                 "kubectl", "ssh", "git", "gh", "gh api", "aws", "curl", "wget", "rtk", "rtk proxy", "sed", "awk",
                 "cat", "tee", "cp", "mv", "ln", "open", "osascript", "sudo"}
SECRET_DIRS = ("~/.ssh", "~/.aws", "~/.gnupg", "~/.kube", "~/.docker", "~/.config/gh", "~/Library/Keychains",
               "~/.netrc", "~/.npmrc", "~/.pypirc", "~/Library/Application Support/Google/Chrome")
TOO_BROAD = ("/", "~", "~/Library", "~/.config", "~/Documents", "~/Desktop", "~/Downloads", "/Users", "/private",
             "/var", "/etc", "/System", "/Applications", "/opt", "/usr")


def unsafe(key, value):
    """Reason this key/value must keep prompting, or None."""
    if key in ("readonly_prefixes", "local_write_prefixes", "allow_prefixes"):
        if UNSAFE_CMD.search(str(value).strip()):
            return "destructive, publishing or remote-write command"
        if str(value).strip() in RUNS_ANYTHING:
            return "interpreter or wrapper prefix would allow arbitrary commands"
        if re.search(r"[$`'\"(){};|&<>]", str(value)):
            return "not a plain command prefix"
        if not str(value).strip():
            return "empty prefix allows everything"
    if key in DIR_KEYS or key == "write_allow_globs":
        p = os.path.realpath(_x(str(value))) if key in DIR_KEYS else None
        if p:
            for d in TOO_BROAD:
                if p == os.path.realpath(_x(d)):
                    return "over-broad directory (%s)" % d
            if HOME.startswith(p.rstrip("/") + "/"):
                return "ancestor of the home directory"
            for d in SECRET_DIRS:
                sd = os.path.realpath(_x(d))
                if p == sd or p.startswith(sd + "/") or sd.startswith(p.rstrip("/") + "/"):
                    return "contains or is inside a credential directory (%s)" % d
        elif str(value).strip() in ("*", "**", "**/*"):
            return "write glob matches everything"
    if key == "habit_hints":
        if not isinstance(value, dict) or not value.get("pattern") or not value.get("hint"):
            return "habit_hints needs {pattern, hint}"
        try:
            re.compile(value["pattern"])
        except re.error as e:
            return "bad regex: %s" % e
    return None


SECRET_RE = re.compile(r"(?i)((?:[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*)\s*[=:]\s*)\S+|"
                       r"\b(lin_api_|sk_live_|sk_test_|ghp_|gho_|github_pat_|xox[bp]-|AKIA)[A-Za-z0-9_\-]+")


def redact(s):
    return SECRET_RE.sub(lambda m: (m.group(1) or m.group(2)) + "[REDACTED]", str(s))[:240]


# ----------------------------------------------------------------------------- targets
def main_checkout(path):
    fn = getattr(ap, "main_checkout", None)
    return (fn(path) if fn else None) or ap.repo_root(path)


def canon_target(t, cwd):
    t = t or "repo"
    if t == "repo":
        t = "repo:" + cwd
    if t.startswith("repo:"):
        return "repo:" + main_checkout(_x(t[5:]))
    if t.startswith("scope:") or t in ("user", "base"):
        return t
    raise SystemExit("bad target %r (repo[:path] | scope:<name> | user | base)" % t)


def target_file(t):
    if t.startswith("repo:"):
        return os.path.join(t[5:], ".agent-policy.json")
    if t.startswith("scope:"):
        return os.path.join(SCOPES, t[6:] + ".json")
    return USER_OVERLAY if t == "user" else os.path.join(KIT, "config", "policy.json")


def target_cwd(t, cwd):
    if t.startswith("repo:"):
        return t[5:]
    if t.startswith("scope:"):
        try:
            with open(target_file(t)) as f:
                for g in json.load(f).get("match", []):
                    hits = sorted(glob.glob(_x(g)))
                    if hits:
                        return hits[0]
        except Exception:
            pass
    return cwd


def ensure_excluded(repo):
    """The main checkout's .agent-policy.json is local setup: keep it out of git via .git/info/exclude."""
    if subprocess.run(["git", "-C", repo, "check-ignore", "-q", ".agent-policy.json"]).returncode == 0:
        return
    ex = os.path.join(repo, ".git", "info", "exclude")
    if os.path.isdir(os.path.dirname(ex)):
        with open(ex, "a") as f:
            f.write("\n.agent-policy.json\n")


# ----------------------------------------------------------------------------- store
def _p(name):
    os.makedirs(STATE, exist_ok=True)
    return os.path.join(STATE, name)


def load_store():
    try:
        with open(_p("proposals.json")) as f:
            return json.load(f)
    except FileNotFoundError:
        return {"proposals": {}}


def save_store(s):
    tmp = _p("proposals.json.tmp")
    with open(tmp, "w") as f:
        json.dump(s, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, _p("proposals.json"))


def log_decision(rec):
    with open(_p("decisions.jsonl"), "a") as f:
        f.write(json.dumps(dict(rec, at=time.strftime("%Y-%m-%dT%H:%M:%S"))) + "\n")


def pid(target, key, value):
    return "p" + hashlib.sha1(json.dumps([target, key, value], sort_keys=True).encode()).hexdigest()[:8]


def add(items, cwd):
    s, now, out = load_store(), time.strftime("%Y-%m-%d"), []
    for it in items:
        key, value = it.get("key"), it.get("value")
        if key not in KEYS:
            out.append(("skip", None, "unknown key %r" % key)); continue
        if key in DIR_KEYS:
            value = _x(value).replace(HOME, "~", 1) if _x(value).startswith(HOME) else _x(value)
        target = canon_target(it.get("target"), cwd)
        i = pid(target, key, value)
        ev = it.get("evidence", {})
        p = s["proposals"].get(i)
        if not p:
            p = s["proposals"][i] = {"id": i, "status": "pending", "target": target, "key": key, "value": value,
                                     "kind": it.get("kind", ""), "rationale": it.get("rationale", ""),
                                     "evidence": {"prompts": 0, "sessions": [], "reasons": {}, "examples": [],
                                                  "first_seen": now}}
            why = unsafe(key, value)
            if why:
                p.update(status="keep-gated", decided_reason="auto: " + why, decided_at=now)
            elif it.get("status") == "keep-gated":  # e.g. the human refused it in the session
                p.update(status="keep-gated", decided_reason=it.get("reason", "refused in session"), decided_at=now)
        e = p["evidence"]
        e["prompts"] += int(ev.get("prompts", 0))
        for sid in [ev.get("session")] + list(ev.get("sessions", [])):
            if sid and sid not in e["sessions"]:
                e["sessions"].append(sid)
        for r, n in (ev.get("reasons") or {}).items():
            e["reasons"][r] = e["reasons"].get(r, 0) + n
        for x in ev.get("examples", []):
            x = redact(x)
            if x not in e["examples"] and len(e["examples"]) < 5:
                e["examples"].append(x)
        e["last_seen"] = now
        if it.get("rationale") and not p.get("rationale"):
            p["rationale"] = it["rationale"]
        if p["status"] != "pending":
            p["seen_after_decision"] = p.get("seen_after_decision", 0) + 1
        out.append((p["status"], i, "%s %s" % (key, json.dumps(value))))
    save_store(s)
    return out


def get(s, i):
    p = s["proposals"].get(i) or next((v for k, v in s["proposals"].items() if k.startswith(i)), None)
    if not p:
        raise SystemExit("no proposal %s" % i)
    return p


def apply_entry(path, key, value, match=None):
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {"_doc": "agent-policy overlay; entries added by `agent-policy proposals accept`."}
        if path.startswith(SCOPES):
            if not match:
                raise SystemExit("new scope: pass --match GLOB (the folders it applies to)")
            data["match"] = match
    if match and path.startswith(SCOPES):
        data["match"] = sorted(set(data.get("match", []) + match))
    if key in DIR_KEYS:
        lst = data.setdefault("directories", {}).setdefault(key.split(".")[1], [])
    else:
        lst = data.setdefault(key, [])
    if value not in lst:
        lst.append(value)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def check_examples(p, cwd):
    return [(x, ap.evaluate(x, cwd).get("decision")) for x in p["evidence"]["examples"]]


def accept(i, target=None, match=None, cwd=None):
    s = load_store()
    p = get(s, i)
    if p["status"] == "keep-gated":
        raise SystemExit("%s is keep-gated (%s); it must keep prompting" % (p["id"], p.get("decided_reason")))
    if target:
        p["target"] = canon_target(target, cwd)
    why = unsafe(p["key"], p["value"])
    if why:
        raise SystemExit("refused: %s" % why)
    tcwd = target_cwd(p["target"], cwd)
    prefixes = p["key"].endswith("_prefixes")
    before = check_examples(p, tcwd) if prefixes else []
    path = target_file(p["target"])
    apply_entry(path, p["key"], p["value"], match)
    if p["target"].startswith("repo:"):
        ensure_excluded(p["target"][5:])
    _cache.clear()
    print("applied %s: %s += %s  →  %s" % (p["id"], p["key"], json.dumps(p["value"]), path.replace(HOME, "~")))
    after = check_examples(p, tcwd) if prefixes else []
    for (x, b), (_, a) in zip(before, after):
        print("  %-5s → %-5s %s" % (b, a, x[:110]))
    if p["key"] in DIR_KEYS:
        sync_target(p["target"])
    p.update(status="accepted", decided_at=time.strftime("%Y-%m-%d"), applied_to=path)
    save_store(s)
    log_decision({"id": p["id"], "decision": "accepted", "target": p["target"], "key": p["key"], "value": p["value"]})


def decide(i, status, reason):
    if not reason:
        raise SystemExit("--reason is required")
    s = load_store()
    p = get(s, i)
    if p["status"] == "accepted":
        raise SystemExit("%s is already applied to %s; remove it there by hand first" % (p["id"], p.get("applied_to")))
    p.update(status=status, decided_reason=reason, decided_at=time.strftime("%Y-%m-%d"))
    save_store(s)
    log_decision({"id": p["id"], "decision": status, "reason": reason, "key": p["key"], "value": p["value"]})
    print("%s %s" % (p["id"], status))


def short_target(t):
    return t.replace(HOME, "~")


def list_(status="pending", as_json=False):
    ps = [p for p in load_store()["proposals"].values() if status in (None, p["status"])]
    ps.sort(key=lambda p: (-len(p["evidence"]["sessions"]), -p["evidence"]["prompts"], p["key"]))
    if as_json:
        print(json.dumps(ps, indent=2)); return
    if not ps:
        print("no %s proposals" % (status or "")); return
    print("%-9s %-10s %4s %4s  %-20s %-38s %s" % ("id", "status", "sess", "hits", "key", "target", "value"))
    for p in ps:
        print("%-9s %-10s %4d %4d  %-20s %-38s %s" % (
            p["id"], p["status"], len(p["evidence"]["sessions"]), p["evidence"]["prompts"], p["key"],
            short_target(p["target"])[:38], json.dumps(p["value"])[:80]))


def show(i):
    p = get(load_store(), i)
    print(json.dumps(p, indent=2).replace(HOME, "~"))
    if p["key"].endswith("_prefixes"):
        cwd = target_cwd(p["target"], os.getcwd())
        print("\ncurrent decisions for the examples (cwd %s):" % short_target(cwd))
        for x, d in check_examples(p, cwd):
            print("  %-5s %s" % (d, x[:120]))


# ----------------------------------------------------------------------------- sync
def worktrees(cwd):
    out = subprocess.run(["git", "-C", cwd, "worktree", "list", "--porcelain"], capture_output=True, text=True)
    return [l[9:] for l in out.stdout.splitlines() if l.startswith("worktree ")] or [ap.repo_root(cwd)]


def wanted_dirs(cwd):
    d, want = load_policy(cwd).get("directories", {}), []
    for x in list(d.get("read", [])) + list(d.get("write", [])):
        x = _x(x)
        if x not in want and not unsafe("directories.read", x):
            want.append(x)
    return want


def sync(cwd, all_worktrees=False, dry=False, user=False):
    """Render directories.read/write into Claude Code's additionalDirectories: each checkout's
    .claude/settings.local.json, or (user=True) the base + user overlay into ~/.claude/settings.json."""
    if user:
        jobs = [(os.path.join(HOME, ".claude", "settings.json"), wanted_dirs(HOME))]
    else:
        roots = worktrees(cwd) if all_worktrees else [ap.repo_root(_x(cwd))]
        jobs = [(os.path.join(r, ".claude", "settings.local.json"), wanted_dirs(r)) for r in roots]
    try:
        with open(_p("sync.json")) as f:
            managed = json.load(f)
    except FileNotFoundError:
        managed = {}
    for path, want in jobs:
        try:
            with open(path) as f:
                s = json.load(f)
        except FileNotFoundError:
            s = {}
        perm = s.setdefault("permissions", {})
        cur = perm.get("additionalDirectories", [])
        prev = managed.get(path, [])
        new = [x for x in cur if x not in prev or x in want] + [x for x in want if x not in cur]
        added, removed = [x for x in new if x not in cur], [x for x in cur if x not in new]
        print("%s %s: +%d -%d %s" % ("would update" if dry else "synced", short_target(path), len(added), len(removed),
                                     " ".join(short_target(x) for x in added)))
        if dry or (not added and not removed):
            managed[path] = want
            continue
        if new:
            perm["additionalDirectories"] = new
        else:
            perm.pop("additionalDirectories", None)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path + ".tmp", "w") as f:
            json.dump(s, f, indent=2)
            f.write("\n")
        os.replace(path + ".tmp", path)
        managed[path] = want
    if not dry:
        with open(_p("sync.json"), "w") as f:
            json.dump(managed, f, indent=2)


def sync_target(target):
    """Sync every checkout a target covers: a repo's worktrees, or each git checkout a scope's globs match."""
    if target.startswith("repo:"):
        return sync(target[5:], all_worktrees=True)
    if target in ("user", "base"):
        return sync(HOME, user=True)
    roots = []
    if target.startswith("scope:"):
        with open(target_file(target)) as f:
            for g in json.load(f).get("match", []):
                for hit in sorted(glob.glob(_x(g))):
                    if os.path.isdir(hit) and os.path.exists(os.path.join(hit, ".git")):
                        roots.append(hit)
    for r in roots:
        sync(r)
    if not roots:
        print("  no checkouts to sync; run `agent-policy sync --cwd <checkout>` where it applies")


# ----------------------------------------------------------------------------- habit hints (Claude hook)
def habit_hook(harness):
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
        cmd = (data.get("tool_input") or {}).get("command") or ""
        cwd = data.get("cwd") or os.getcwd()
        pol = load_policy(cwd) if cmd else {}
        harnesses = (pol.get("rewrite_hints") or {}).get("harnesses", ["claude"])
        if harness in harnesses and (pol.get("rewrite_hints") or {}).get("enabled", True) \
                and os.environ.get("AGENT_REWRITE_HINTS") != "0":
            for h in pol.get("habit_hints", []):
                if re.search(h.get("pattern", "(?!)"), cmd):
                    seen = _p(os.path.join("hints", re.sub(r"\W", "_", str(data.get("session_id", "x"))) + ".txt"))
                    os.makedirs(os.path.dirname(seen), exist_ok=True)
                    hsh = hashlib.sha1(cmd.encode()).hexdigest()
                    done = open(seen).read().split() if os.path.exists(seen) else []
                    if hsh in done:
                        break
                    with open(seen, "a") as f:
                        f.write(hsh + "\n")
                    print(json.dumps({"hookSpecificOutput": {
                        "hookEventName": "PreToolUse", "permissionDecision": "deny",
                        "permissionDecisionReason": "agent-policy rewrite hint: " + h["hint"]}}))
                    return 0
    except Exception as e:  # never break the agent
        sys.stderr.write("agent-policy habit hints: %s\n" % e)
    sys.stdin = io.StringIO(raw)
    return ap.hook(harness)


# ----------------------------------------------------------------------------- self-test
def self_test():
    global STATE, SCOPES
    fails = 0
    with tempfile.TemporaryDirectory() as t:
        t = os.path.realpath(t)
        STATE, SCOPES = os.path.join(t, "state"), os.path.join(t, "scopes")
        repo = os.path.join(t, "proj")
        os.makedirs(repo)
        subprocess.run(["git", "init", "-q", repo], check=True)
        wt = os.path.join(t, "proj-wt-a")
        subprocess.run(["git", "-C", repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q",
                        "--allow-empty", "-m", "i"], check=True)
        subprocess.run(["git", "-C", repo, "worktree", "add", "-q", wt, "-b", "a"], check=True)

        def ok(name, cond):
            nonlocal fails
            print("%s  %s" % ("ok  " if cond else "FAIL", name))
            fails += not cond

        ok("unsafe: docker volume rm", bool(unsafe("readonly_prefixes", "docker volume rm")))
        ok("unsafe: git push", bool(unsafe("local_write_prefixes", "git push origin")))
        ok("safe: orbctl status", unsafe("readonly_prefixes", "orbctl status") is None)
        ok("unsafe: bare python3", bool(unsafe("readonly_prefixes", "python3")))
        ok("unsafe: rtk proxy", bool(unsafe("readonly_prefixes", "rtk proxy")))
        ok("unsafe: shell syntax", bool(unsafe("readonly_prefixes", "$(git config")))
        ok("unsafe dir: ~", bool(unsafe("directories.read", "~")))
        ok("unsafe dir: ~/.aws/sso", bool(unsafe("directories.read", "~/.aws/sso")))
        ok("unsafe dir: ~/Library", bool(unsafe("directories.read", "~/Library")))
        ok("safe dir: ~/Library/Caches", unsafe("directories.read", "~/Library/Caches") is None)
        ok("redacts tokens", "lin_api_abc" not in redact("curl -H 'Authorization: lin_api_abc123'"))  # gitleaks:allow (fake token)

        cmd = "zzqtool status --brief"
        ok("unknown tool defers", ap.evaluate(cmd, wt).get("decision") == "defer")
        res = add([{"key": "readonly_prefixes", "value": "zzqtool status", "target": "repo:" + wt,
                    "evidence": {"prompts": 2, "session": "s1", "examples": [cmd]}},
                   {"key": "readonly_prefixes", "value": "zzqtool status", "target": "repo:" + wt,
                    "evidence": {"prompts": 1, "session": "s2", "examples": [cmd]}},
                   {"key": "readonly_prefixes", "value": "rm -rf", "target": "repo:" + wt}], t)
        ids = {r[2]: r for r in res}
        p = load_store()["proposals"][res[0][1]]
        ok("dedupe + evidence merge", p["evidence"]["prompts"] == 3 and p["evidence"]["sessions"] == ["s1", "s2"])
        ok("repo target = main checkout", p["target"] == "repo:" + repo)
        ok("rm auto-gated", ids['readonly_prefixes "rm -rf"'][0] == "keep-gated")
        accept(res[0][1], cwd=t)
        _cache.clear()
        ok("accepted → allow in worktree", ap.evaluate(cmd, wt).get("decision") == "allow")
        ok("overlay excluded from git",
           subprocess.run(["git", "-C", repo, "check-ignore", "-q", ".agent-policy.json"]).returncode == 0)
        try:
            accept(ids['readonly_prefixes "rm -rf"'][1], cwd=t)
            ok("gated cannot be accepted", False)
        except SystemExit:
            ok("gated cannot be accepted", True)

        sib = os.path.join(t, "shared")
        os.makedirs(sib)
        r2 = add([{"key": "directories.read", "value": sib, "target": "scope:selftest",
                   "evidence": {"prompts": 4, "session": "s1"}}], t)
        accept(r2[0][1], match=[os.path.join(t, "proj*")], cwd=t)
        _cache.clear()
        ok("scope matches worktree", any(n == "selftest" for _, n, _ in matching_scopes(os.path.join(wt, "sub"))))
        ok("scope ignores others", not matching_scopes(sib))
        sync(repo, all_worktrees=True)
        with open(os.path.join(wt, ".claude", "settings.local.json")) as f:
            dirs = json.load(f)["permissions"]["additionalDirectories"]
        ok("sync writes additionalDirectories", dirs == [sib])
        with open(os.path.join(wt, ".claude", "settings.local.json")) as f:
            ok("accept syncs scope checkouts", json.load(f)["permissions"]["additionalDirectories"] == [sib])

        r6 = add([{"key": "habit_hints", "target": "repo:" + repo,
                   "value": {"pattern": r"^zzqhint\b", "hint": "use zzqhint2"}}], t)
        accept(r6[0][1], cwd=t)
        _cache.clear()

        def run_hook(c):
            stdin, stdout = sys.stdin, sys.stdout
            sys.stdin = io.StringIO(json.dumps({"session_id": "st", "cwd": wt, "tool_name": "Bash",
                                                "tool_input": {"command": c}}))
            sys.stdout = buf = io.StringIO()
            try:
                habit_hook("claude")
            finally:
                sys.stdin, sys.stdout = stdin, stdout
            return buf.getvalue()

        first, second = run_hook("zzqhint go"), run_hook("zzqhint go")
        ok("habit hint denies once", '"deny"' in first and "use zzqhint2" in first)
        ok("habit hint never twice", "use zzqhint2" not in second)
        ok("hook passes through to agent-policy", '"allow"' in run_hook("git status"))

        os.remove(os.path.join(SCOPES, "selftest.json"))
        _cache.clear()
        sync(repo, all_worktrees=True)
        with open(os.path.join(wt, ".claude", "settings.local.json")) as f:
            ok("sync removes what it added", "additionalDirectories" not in json.load(f)["permissions"])

        r3 = add([{"key": "x", "value": "y"}], t)
        ok("unknown key skipped", r3[0][0] == "skip")
        r4 = add([{"key": "readonly_prefixes", "value": "zzqother ls", "target": "repo:" + repo}], t)
        decide(r4[0][1], "rejected", "not needed")
        r5 = add([{"key": "readonly_prefixes", "value": "zzqother ls", "target": "repo:" + repo}], t)
        ok("rejected stays rejected", r5[0][0] == "rejected")
    print("%d failure(s)" % fails)
    return 1 if fails else 0


# ----------------------------------------------------------------------------- cli
def opt(args, name, default=None, multi=False):
    vals = []
    while name in args:
        i = args.index(name)
        vals.append(args[i + 1])
        del args[i:i + 2]
    return vals if multi else (vals[-1] if vals else default)


def read_items(path):
    with (sys.stdin if path == "-" else open(path)) as f:
        text = f.read().strip()
    if text.startswith("["):
        return json.loads(text)
    return [json.loads(l) for l in text.splitlines() if l.strip()]


def main(argv):
    if not argv:
        return ap.main(argv)
    cmd, args = argv[0], list(argv[1:])
    if cmd == "hook":
        return habit_hook(args[0] if args else "claude")
    if cmd == "review-test":
        return self_test()
    if cmd == "sync":
        sync(opt(args, "--cwd", os.getcwd()), "--all-worktrees" in args, "--dry-run" in args, "--user" in args)
        return 0
    if cmd == "scopes":
        cwd = opt(args, "--cwd", os.getcwd())
        for depth, name, data in matching_scopes(cwd):
            print("%-20s match=%s" % (name, data.get("match")))
        return 0
    if cmd == "proposals":
        sub = args.pop(0) if args else "list"
        cwd = opt(args, "--cwd", os.getcwd())
        if sub == "add":
            for status, i, what in add(read_items(args[0] if args else "-"), cwd):
                print("%-10s %-9s %s" % (status, i or "-", what))
        elif sub == "list":
            st = None if "--all" in args else opt(args, "--status", "pending")
            list_(st, "--json" in args)
        elif sub == "show":
            show(args[0])
        elif sub == "accept":
            target, match = opt(args, "--target"), opt(args, "--match", multi=True)
            accept(args[0], target, match or None, cwd)
        elif sub in ("reject", "gate"):
            reason = opt(args, "--reason")
            decide(args[0], "rejected" if sub == "reject" else "keep-gated", reason)
        else:
            print(__doc__)
            return 2
        return 0
    if cmd in ("-h", "--help"):
        print(ap.__doc__)
        print(__doc__)
        return 0
    return ap.main(argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
