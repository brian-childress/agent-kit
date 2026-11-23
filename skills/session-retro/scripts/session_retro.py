#!/usr/bin/env python3
"""session_retro.py — mine a Claude Code session transcript for the points where a human had to step in.

Usage:
  session_retro.py [SESSION]        SESSION = a .jsonl path, a session id, or omitted (newest transcript
                                    of the project for the current directory)
  session_retro.py --cwd DIR ...    resolve the project from DIR instead of $PWD

Prints a markdown evidence report to stdout:
  1. Permission summary   - who approved each tool call (config / hook / human), by reason code
  2. Human approvals      - every call a human approved or refused, with the reason the harness asked
  3. Grouped candidates   - the same calls grouped into allow-rule candidates (command prefix / path root)
  4. Human turns          - every genuine user message, flagged when the agent had just asked a question
  5. AskUserQuestion      - structured questions the agent asked
  6. Refusals and errors  - tool results that refused, aborted or errored
Read-only: never edits settings. Bash calls are re-classified with `agent-policy check --json` when it is on PATH.
"""
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

HOME = str(Path.home())
TRUNC = 180


def project_dir(cwd):
    slug = re.sub(r"[^A-Za-z0-9]", "-", cwd)
    return Path(HOME) / ".claude" / "projects" / slug


def resolve(arg, cwd):
    if arg and arg.endswith(".jsonl") and Path(arg).exists():
        return Path(arg)
    pdir = project_dir(cwd)
    if arg:
        p = pdir / (arg + ".jsonl")
        if p.exists():
            return p
        sys.exit("session not found: %s (looked in %s)" % (arg, pdir))
    files = sorted(pdir.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        sys.exit("no transcripts in %s" % pdir)
    return files[0]


def short(s, n=TRUNC):
    s = re.sub(r"\s+", " ", str(s)).strip().replace("|", "\\|")
    s = s.replace(HOME, "~")
    return s if len(s) <= n else s[: n - 1] + "…"


def text_of(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(c.get("text", "") for c in content if isinstance(c, dict) and c.get("type") == "text")
    return ""


def describe(name, inp):
    if not isinstance(inp, dict):
        return str(inp)
    if name == "Bash":
        return inp.get("command", "")
    for k in ("file_path", "path", "pattern", "url", "query", "skill", "prompt"):
        if k in inp:
            return "%s=%s" % (k, inp[k])
    return json.dumps(inp)[:TRUNC]


SPLIT = re.compile(r"\s*(?:\|\||&&|\||;)\s*")
ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=\S*$")


def cmd_prefix(cmd, words=2):
    """First real segment of a shell command, reduced to its leading words (skips cd, env assignments)."""
    for seg in SPLIT.split(cmd.strip()):
        toks = [t for t in seg.split() if not ENV_ASSIGN.match(t)]
        if not toks or toks[0] in ("cd", "echo", "true", "set"):
            continue
        out = [toks[0]]
        for t in toks[1:words]:
            if t.startswith("-") or "/" in t or t.startswith(("'", '"', "$")):
                break
            out.append(t)
        return " ".join(out)
    return cmd.split()[0] if cmd.split() else ""


PATH_RE = re.compile(r"(?:~|/(?:Users|private|var|tmp|opt|Library|Applications|Volumes))[^\s'\"`;|&)<>]*")


def path_roots(s, depth=4):
    roots = set()
    for m in PATH_RE.findall(s):
        p = m.replace("~", HOME, 1) if m.startswith("~") else m
        p = re.split(r"[*?\[]", p, maxsplit=1)[0]    # a glob reads its parent directory
        parts = [x for x in p.split("/") if x]
        if parts and "." in parts[-1].lstrip("."):      # a file: never let the root be the file itself
            parts = parts[:-1]
        roots.add("/" + "/".join(parts[:depth]))
    return sorted(roots)


TEMP_ROOTS = ("/tmp", "/private/tmp", "/var/folders", "/private/var/folders")  # the kit already grants these
# Command shapes that trip Claude Code's built-in safety prompt even when agent-policy allows the command.
# (`cd X &&`, loops and path variables are already hinted by agent-policy itself.)
HABITS = [
    (r"\$\{[A-Za-z_][A-Za-z0-9_]*:[-+=?]",
     "Drop the `${VAR:+…}` / `${VAR:-…}` expansion: check the variable in its own call or write the literal value."),
    (r"\b(python3?|node|pwsh|ruby|bash|sh)\b[^|;&]*\s-?\s*<<-?\s*['\"]?\w+",
     "Don't feed a script to an interpreter through a heredoc: put a reusable script in the repo or kit and run it "
     "by path, or use the Read/Edit tools for file work."),
    (r"\bcat\s*>\s*\S+\s*<<|\btee\s+\S+\s*<<",
     "Write files with the Write tool, not `cat > file <<EOF`."),
]


def policy_parts(cmd, cwd):
    if not shutil.which("agent-policy"):
        return None
    try:
        out = subprocess.run(["agent-policy", "check", "--json", "--cwd", cwd or os.getcwd(), cmd],
                             capture_output=True, text=True, timeout=20)
        return json.loads(out.stdout)
    except Exception:
        return None


def is_genuine_user(rec):
    if rec.get("type") != "user" or rec.get("isMeta") or rec.get("isCompactSummary") or rec.get("toolUseResult") is not None:
        return False
    c = rec.get("message", {}).get("content")
    if isinstance(c, list) and any(isinstance(x, dict) and x.get("type") == "tool_result" for x in c):
        return False
    t = text_of(c).strip()
    if not t:
        return False
    return not t.startswith(("<command-", "<local-command", "<system-reminder>", "<task-notification>",
                             "Caveat:", "[Request interrupted"))


def main(argv):
    cwd, arg, proposals_out = os.getcwd(), None, None
    while argv:
        a = argv.pop(0)
        if a == "--cwd":
            cwd = argv.pop(0)
        elif a == "--proposals":
            proposals_out = argv.pop(0)
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            arg = a
    path = resolve(arg, cwd)
    recs = []
    with open(path) as fh:
        for line in fh:
            try:
                recs.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    tool_uses, last_assistant_text, modes = {}, "", Counter()
    decisions = Counter()
    human = []      # (rec, tool_use, decision)
    refusals = []
    asks = []
    turns = []
    hint_count = 0

    for rec in recs:
        if rec.get("permissionMode"):
            modes[rec["permissionMode"]] += 1
        if rec.get("type") == "attachment":
            s = json.dumps(rec.get("attachment", {}))
            hint_count += s.count("agent-policy rewrite hint")
        if rec.get("type") == "assistant":
            for c in rec.get("message", {}).get("content", []) or []:
                if c.get("type") == "tool_use":
                    tool_uses[c["id"]] = (c.get("name"), c.get("input", {}), rec.get("cwd"), rec.get("timestamp", ""))
                    if c.get("name") == "AskUserQuestion":
                        asks.append((rec.get("timestamp", ""), c.get("input", {})))
                elif c.get("type") == "text" and c.get("text", "").strip():
                    last_assistant_text = c["text"]
        if rec.get("type") == "user":
            pd = rec.get("permissionDecision")
            content = rec.get("message", {}).get("content")
            tr = next((x for x in content if isinstance(x, dict) and x.get("type") == "tool_result"), None) \
                if isinstance(content, list) else None
            tu = tool_uses.get(tr.get("tool_use_id")) if tr else None
            if pd:
                reason = pd.get("reasonCode") or pd.get("reasonType") or ""
                decisions[(pd.get("decision"), pd.get("source"), reason)] += 1
                if str(pd.get("source", "")).startswith("user"):
                    human.append((rec, tu, pd))
            if tr and tr.get("is_error"):
                body = tr.get("content")
                body = text_of(body) if not isinstance(body, str) else body
                if not body.startswith("Exit code") and \
                        re.search(r"doesn't want|declined|aborted|denied|blocked|rejected", body[:300], re.I):
                    refusals.append((rec.get("timestamp", ""), tu, body))
            if is_genuine_user(rec):
                turns.append((rec.get("timestamp", ""), text_of(content), last_assistant_text))
                last_assistant_text = ""

    o = []
    o.append("# Session retro evidence — `%s`\n" % path.name)
    o.append("- Transcript: `%s`" % short(str(path), 300))
    o.append("- Permission modes seen: %s" % (", ".join("%s ×%d" % kv for kv in modes.most_common()) or "unknown"))
    o.append("- Human approvals/refusals: **%d** of %d decided tool calls; agent-policy rewrite hints: %d\n"
             % (len(human), sum(decisions.values()), hint_count))

    o.append("## 1. Permission summary\n\n| count | decision | source | reason |\n|---:|---|---|---|")
    for (d, s, r), n in decisions.most_common():
        o.append("| %d | %s | %s | %s |" % (n, d, s, r))

    cands = {}

    def candidate(key, value, kind, reason, example, refused):
        if not value:
            return
        k = (key, json.dumps(value, sort_keys=True))
        c = cands.setdefault(k, {"key": key, "value": value, "kind": kind, "target": "repo:" + cwd,
                                 "evidence": {"prompts": 0, "session": path.stem, "reasons": {}, "examples": []}})
        e = c["evidence"]
        e["prompts"] += 1
        e["reasons"][reason] = e["reasons"].get(reason, 0) + 1
        if len(e["examples"]) < 5 and example not in e["examples"]:
            e["examples"].append(example[:400])
        if refused:
            c.update(status="keep-gated", reason="refused by the human in session %s" % path.stem)

    res = None
    o.append("\n## 2. Calls a human approved or refused\n")
    o.append("| # | time | tool | source / scope | reason | call | agent-policy (non-allow parts) |")
    o.append("|---:|---|---|---|---|---|---|")
    groups = defaultdict(lambda: {"n": 0, "reasons": Counter(), "examples": [], "rejected": 0})
    for i, (rec, tu, pd) in enumerate(human, 1):
        name, inp, tcwd, ts = tu if tu else ("?", {}, rec.get("cwd"), rec.get("timestamp", ""))
        call = describe(name, inp)
        reason = pd.get("reasonCode") or pd.get("reasonType") or ""
        pol, res = "", None
        if name == "Bash":
            res = policy_parts(call, tcwd)
            if res:
                bad = [p for p in res.get("parts", []) if p.get("decision") != "allow"]
                pol = "; ".join("%s: %s" % (p["decision"], short(p.get("reason", ""), 60)) for p in bad) or "allow"
            key = ("Bash", cmd_prefix(call))
        else:
            key = (name, "")
        if "outsideReads" in reason:
            for root in path_roots(call) or ["(no path found)"]:
                gk = ("dir", root)
                groups[gk]["n"] += 1
                groups[gk]["reasons"][reason] += 1
                if len(groups[gk]["examples"]) < 2:
                    groups[gk]["examples"].append(short(call, 90))
        g = groups[key]
        g["n"] += 1
        g["reasons"][reason] += 1
        g["rejected"] += pd.get("decision") != "accept"
        if len(g["examples"]) < 2:
            g["examples"].append(short(call, 90))
        o.append("| %d | %s | %s | %s / %s | %s | `%s` | %s |" % (
            i, ts[11:19], name, pd.get("source"), pd.get("grantScope", ""), reason, short(call, 140), short(pol, 120)))
        refused = pd.get("decision") != "accept"
        if "outsideReads" in reason:
            for root in path_roots(call):
                if not any(root == t or root.startswith(t + "/") for t in TEMP_ROOTS):
                    candidate("directories.read", root.replace(HOME, "~", 1), "directory", reason, call, refused)
        if name == "Bash" and res:
            for p in res.get("parts", []):
                if p.get("decision") == "defer":
                    candidate("readonly_prefixes", cmd_prefix(p["cmd"]), "prefix", reason, p["cmd"], refused)
        if name == "Bash" and "safetyCheck" in reason and not refused:
            for pattern, hint in HABITS:
                if re.search(pattern, call):
                    candidate("habit_hints", {"pattern": pattern, "hint": hint}, "habit", reason, call, False)

    o.append("\n## 3. Grouped allow-rule candidates\n")
    o.append("`dir` rows are path roots behind `outsideReadsBlocked` prompts (candidates for "
             "`permissions.additionalDirectories`); other rows are tool / command prefixes.\n")
    o.append("| prompts | refused | kind | key | reasons | examples |\n|---:|---:|---|---|---|---|")
    for (kind, key), g in sorted(groups.items(), key=lambda kv: -kv[1]["n"]):
        o.append("| %d | %d | %s | `%s` | %s | %s |" % (
            g["n"], g["rejected"], kind, short(key, 80),
            ", ".join("%s×%d" % kv for kv in g["reasons"].most_common()),
            " · ".join("`%s`" % e for e in g["examples"])))

    o.append("\n## 4. Human turns\n\n`ASKED` = the agent's last text before this turn ended in or contained a question.\n")
    for ts, t, prev in turns:
        asked = "?" in prev[-400:]
        o.append("- **%s** %s %s" % (ts[:19].replace("T", " "), "**ASKED** —" if asked else "", short(t, 300)))
        if asked:
            o.append("  - agent before: _%s_" % short(prev[-300:], 300))

    o.append("\n## 5. AskUserQuestion calls\n")
    o.extend("- %s %s" % (ts[:19], short(json.dumps([q.get("question") for q in inp.get("questions", [])]), 300))
             for ts, inp in asks)
    if not asks:
        o.append("- none")

    o.append("\n## 6. Refusals, aborts and blocks\n")
    for ts, tu, body in refusals:
        o.append("- %s `%s` → %s" % (ts[11:19], short(describe(tu[0], tu[1]) if tu else "?", 120), short(body, 160)))
    if not refusals:
        o.append("- none")
    print("\n".join(o))
    if proposals_out:
        with open(proposals_out, "w") as fh:
            json.dump(sorted(cands.values(), key=lambda c: -c["evidence"]["prompts"]), fh, indent=2)
        sys.stderr.write("wrote %d candidate proposals to %s\n" % (len(cands), proposals_out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
