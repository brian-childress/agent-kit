#!/usr/bin/env bash
# agent-kit installer — wires the shared policy, post-edit checks, commands and instructions into
# every agent harness found on this machine. Idempotent; backs up every file it changes.
#
# Usage: ./install.sh [--dry-run] [--uninstall] [--only claude,codex,cursor,opencode,pi,gemini]
# Portable: clone/copy ~/.agent-kit to another machine and run this script (needs bash, python3, git).
set -euo pipefail
KIT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
BIN_DIR="${AGENT_KIT_BIN_DIR:-$HOME/.local/bin}"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="$HOME/.agent-kit-backups/$STAMP"
DRY=0; UNINSTALL=0; ONLY=""
while [ $# -gt 0 ]; do case "$1" in
  --dry-run) DRY=1;; --uninstall) UNINSTALL=1;; --only) ONLY="$2"; shift;;
  -h|--help) sed -n '2,7p' "$0"; exit 0;; *) echo "unknown arg $1"; exit 2;; esac; shift; done

say() { printf '%-9s %s\n' "$1" "$2"; }
want() { [ -z "$ONLY" ] || case ",$ONLY," in *",$1,"*) return 0;; *) return 1;; esac; }
run() { if [ $DRY = 1 ]; then say dry-run "$*"; else "$@"; fi; }
backup() { [ -e "$1" ] || return 0; [ $DRY = 1 ] && return 0; mkdir -p "$BACKUP$(dirname "$1")"; cp -p "$1" "$BACKUP$1"; }
link() { # link <target> <linkpath>: create symlink unless a real (non-kit) file is in the way
  local target="$1" path="$2"
  if [ -L "$path" ] && [ "$(readlink "$path")" = "$target" ]; then say ok "$path"; return; fi
  if [ -e "$path" ] && [ ! -L "$path" ]; then say skip "$path exists (not a symlink); merge $target into it by hand"; return; fi
  run mkdir -p "$(dirname "$path")"; run ln -sfn "$target" "$path"; say linked "$path -> $target"
}
unlink_kit() { if [ -L "$1" ] && case "$(readlink "$1")" in "$KIT"/*) true;; *) false;; esac; then run rm "$1"; say removed "$1"; fi; }

# JSON hook editor: json_hooks <file> <format> <mode> [event matcher command timeout]...
#   format: claude (hooks.EVENT[] = {matcher, hooks:[{type,command,timeout}]}) | cursor (hooks.EVENT[] = {command,timeout})
#   mode:   add | remove   (remove drops every entry whose command references the kit)
json_hooks() {
  local file="$1"; shift
  backup "$file"
  [ $DRY = 1 ] && { say dry-run "update hooks in $file"; return; }
  python3 -I - "$file" "$KIT" "$@" <<'PY'
import json, os, sys
path, kit, fmt, mode, rest = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:]
data = json.load(open(path)) if os.path.exists(path) and os.path.getsize(path) else {}
hooks = data.setdefault("hooks", {})
if fmt == "cursor":
    data.setdefault("version", 1)
legacy = ("/.claude/hooks/pre-bash-guard.sh", "/.claude/hooks/post-edit-check.sh", "rtk hook")
def ours(cmd): return kit in cmd or any(l in cmd for l in legacy)
for ev in list(hooks):
    groups = []
    for g in hooks[ev]:
        if fmt == "claude":
            g["hooks"] = [h for h in g.get("hooks", []) if not ours(h.get("command", ""))]
            if g["hooks"]: groups.append(g)
        elif not ours(g.get("command", "")):
            groups.append(g)
    hooks[ev] = groups
    if not groups: del hooks[ev]
if mode == "add":
    for i in range(0, len(rest), 4):
        ev, matcher, cmd, timeout = rest[i:i + 4]
        entry = ({"matcher": matcher, "hooks": [{"type": "command", "command": cmd, "timeout": int(timeout)}]}
                 if fmt == "claude" else {"command": cmd, "timeout": int(timeout)})
        if fmt == "claude" and not matcher: entry.pop("matcher")
        hooks.setdefault(ev, []).insert(0, entry)
os.makedirs(os.path.dirname(path), exist_ok=True)
json.dump(data, open(path, "w"), indent=2); open(path, "a").write("\n")
PY
  say updated "$file ($1 hooks: $2)"
}

POLICY="$KIT/bin/agent-policy"; POST="$KIT/bin/agent-post-edit"
TMPD="${TMPDIR:-/tmp}"; TMPD="${TMPD%/}"

# ---------------------------------------------------------------- commands on PATH
if want commands || [ -z "$ONLY" ]; then
  for f in "$KIT"/bin/*; do
    n=$(basename "$f"); [ "$n" = _lib.sh ] && continue
    if [ $UNINSTALL = 1 ]; then unlink_kit "$BIN_DIR/$n"
    else
      cur=$(readlink "$BIN_DIR/$n" 2>/dev/null || true)
      case "$cur" in "$HOME/.claude/bin/"*) run rm "$BIN_DIR/$n";; esac  # migrate legacy ~/.claude/bin links
      link "$f" "$BIN_DIR/$n"
    fi
  done
  case ":$PATH:" in *":$BIN_DIR:"*) ;; *) say warn "$BIN_DIR is not on PATH; add it in your shell profile";; esac
fi

# ---------------------------------------------------------------- Claude Code
if want claude && [ -d "$HOME/.claude" ]; then
  S="$HOME/.claude/settings.json"
  if [ $UNINSTALL = 1 ]; then json_hooks "$S" claude remove
  else
    json_hooks "$S" claude add \
      PreToolUse Bash "$POLICY hook claude" 70 \
      PostToolUse "Edit|Write|MultiEdit" "$POST --hook claude" 130
    if [ $DRY = 0 ]; then
      python3 -I - "$S" "$KIT" "$TMPD" <<'PY'
import json, sys
p, kit, tmpd = sys.argv[1:]
s = json.load(open(p)); perm = s.setdefault("permissions", {})
dirs = perm.setdefault("additionalDirectories", [])
for d in (kit, "/tmp", "/private/tmp", tmpd):
    if d not in dirs: dirs.append(d)
json.dump(s, open(p, "w"), indent=2); open(p, "a").write("\n")
PY
      say updated "$S (additionalDirectories: kit + temp dirs)"
    fi
  fi
  C="$HOME/.claude/CLAUDE.md"; IMPORT="@$KIT/AGENTS.md"
  if [ $UNINSTALL = 1 ]; then
    if [ -f "$C" ] && grep -qF "$IMPORT" "$C"; then backup "$C"; [ $DRY = 1 ] || { grep -vF "$IMPORT" "$C" > "$C.tmp" && mv "$C.tmp" "$C"; }; say updated "$C (import removed)"; fi
  elif ! { [ -f "$C" ] && grep -qF "$IMPORT" "$C"; }; then
    backup "$C"
    if [ $DRY = 0 ]; then { printf '%s\n\n' "$IMPORT"; [ -f "$C" ] && cat "$C"; } > "$C.tmp" && mv "$C.tmp" "$C"; fi
    say updated "$C (imports AGENTS.md)"
  else say ok "$C"; fi
  # retire the pre-kit Claude-only copies (backed up first)
  for legacy in "$HOME/.claude/hooks/pre-bash-guard.sh" "$HOME/.claude/hooks/post-edit-check.sh" "$HOME/.claude/bin" "$HOME/.claude/templates"; do
    if [ $UNINSTALL = 0 ] && [ -e "$legacy" ]; then
      [ $DRY = 1 ] || { mkdir -p "$BACKUP$(dirname "$legacy")"; mv "$legacy" "$BACKUP$legacy"; }
      say retired "$legacy (moved to backup)"
    fi
  done
fi

# ---------------------------------------------------------------- Codex (hooks.json uses the Claude protocol)
if want codex && [ -d "$HOME/.codex" ]; then
  if [ $UNINSTALL = 1 ]; then json_hooks "$HOME/.codex/hooks.json" claude remove; unlink_kit "$HOME/.codex/AGENTS.md"
  else json_hooks "$HOME/.codex/hooks.json" claude add PreToolUse Bash "$POLICY hook codex" 70
       link "$KIT/AGENTS.md" "$HOME/.codex/AGENTS.md"; fi
fi

# ---------------------------------------------------------------- Cursor (agent + CLI hooks)
if want cursor && [ -d "$HOME/.cursor" ]; then
  if [ $UNINSTALL = 1 ]; then json_hooks "$HOME/.cursor/hooks.json" cursor remove
  else json_hooks "$HOME/.cursor/hooks.json" cursor add \
         beforeShellExecution "" "$POLICY hook cursor" 70 \
         afterFileEdit "" "$POST --hook cursor" 130
       say note "Cursor has no global instructions file; add AGENTS.md content to Cursor Settings > Rules"; fi
fi

# ---------------------------------------------------------------- opencode
if want opencode && [ -d "$HOME/.config/opencode" ]; then
  if [ $UNINSTALL = 1 ]; then unlink_kit "$HOME/.config/opencode/plugins/agent-kit.js"; unlink_kit "$HOME/.config/opencode/AGENTS.md"
  else link "$KIT/adapters/opencode/agent-kit.js" "$HOME/.config/opencode/plugins/agent-kit.js"
       link "$KIT/AGENTS.md" "$HOME/.config/opencode/AGENTS.md"; fi
fi

# ---------------------------------------------------------------- Pi
if want pi && [ -d "$HOME/.pi/agent" ]; then
  if [ $UNINSTALL = 1 ]; then unlink_kit "$HOME/.pi/agent/extensions/agent-kit.ts"; unlink_kit "$HOME/.pi/agent/AGENTS.md"
  else link "$KIT/adapters/pi/agent-kit.ts" "$HOME/.pi/agent/extensions/agent-kit.ts"
       link "$KIT/AGENTS.md" "$HOME/.pi/agent/AGENTS.md"; fi
fi

# ---------------------------------------------------------------- Gemini CLI (instructions only)
if want gemini && [ -d "$HOME/.gemini" ]; then
  if [ $UNINSTALL = 1 ]; then unlink_kit "$HOME/.gemini/GEMINI.md"
  else link "$KIT/AGENTS.md" "$HOME/.gemini/GEMINI.md"; fi
fi

[ $DRY = 0 ] && [ -d "$BACKUP" ] && say backup "$BACKUP"
if [ $UNINSTALL = 0 ] && [ $DRY = 0 ]; then "$POLICY" test >/dev/null && say ok "agent-policy self-test passed"; fi
say "done" "restart running agent sessions to pick up hook changes"
