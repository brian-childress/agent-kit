# shellcheck shell=bash
# Shared helpers for agent-kit bin scripts. Source, don't execute.
# bash 3.2 compatible (macOS /bin/bash).

export KIT_HOME="${AGENT_KIT_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

repo_root() { git -C "${1:-.}" rev-parse --show-toplevel 2>/dev/null || (cd "${1:-.}" && pwd); }

# Per-project env for the kit commands (harness-neutral): <repo>/.agent/env, KEY=value lines.
load_project_env() {
  local f
  f="$(repo_root "${1:-.}")/.agent/env"
  # shellcheck disable=SC1090
  if [ -f "$f" ]; then set -a; . "$f"; set +a; fi
  return 0
}
load_project_env .

# Walk up from $1 (a dir) to $2 (stop dir, inclusive) looking for relative path $3. Print first hit.
find_up() {
  local d="$1" stop="$2" rel="$3"
  while [ -n "$d" ]; do
    [ -e "$d/$rel" ] && { printf '%s\n' "$d/$rel"; return 0; }
    { [ "$d" = "$stop" ] || [ "$d" = "/" ]; } && return 1
    d=$(dirname "$d")
  done
  return 1
}

# Package manager for a JS project root.
js_pm() {
  local r="$1"
  if [ -f "$r/pnpm-lock.yaml" ]; then echo pnpm
  elif [ -f "$r/bun.lock" ] || [ -f "$r/bun.lockb" ]; then echo bun
  elif [ -f "$r/yarn.lock" ]; then echo yarn
  else echo npm; fi
}

# Does package.json in $1 define script $2?
has_script() { [ -f "$1/package.json" ] && jq -e --arg s "$2" '.scripts[$s] // empty' "$1/package.json" >/dev/null 2>&1; }

# Truncate long output for agent consumption.
tail_lines() { tail -n "${1:-40}"; }
