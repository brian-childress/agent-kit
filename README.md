# agent-kit

**Stop babysitting your coding agent.** agent-kit is one harness-neutral layer that auto-approves the shell
commands that are actually safe, blocks the few that never should run, and leaves everything else to your
harness's normal prompts, across Claude Code, Codex, Cursor, opencode, Pi and Gemini CLI.

At its core is `agent-policy`, a stdlib-Python policy engine that parses whole shell commands (chains, pipes,
loops, `$(…)`, `bash -c`, heredocs) and decides **allow**, **deny** or **defer** for every part. One policy file,
every agent, every machine.

- **Fewer prompts**: `git log | head`, `cat a b | grep x`, `pnpm test`, `terraform plan` run without asking.
- **Real guardrails**: no AI co-author trailers, no secrets committed (gitleaks), no `sed -i` file edits behind
  your editor's back.
- **Self-correcting agents**: instead of a prompt, the agent gets a concrete rewrite hint and retries on its own.
- **Explainable**: `agent-policy check '<cmd>'` shows exactly why a command was allowed, denied or deferred.
- **Zero dependencies**: Python 3 and a POSIX shell. No daemon, no network, no telemetry.

## Install

Requires Python 3 and macOS or Linux. Optional: `gitleaks`, `lefthook`, `jq`.

```sh
git clone https://github.com/brian-childress/agent-kit ~/.agent-kit && ~/.agent-kit/install.sh
~/.agent-kit/install.sh --dry-run | --uninstall | --only claude,cursor
agent-policy test            # self-test
agent-policy check 'cd repo && git log | head'
```

The installer symlinks `bin/` onto your PATH (`~/.local/bin`), registers the hooks for each harness it finds, and
links `AGENTS.md` as each harness's global instructions. It never overwrites a real file you own; `--uninstall`
removes only what it added. `AGENTS.md` is an example set of instructions: edit it to taste.

## Layers (strongest/most portable first)

| Layer | What | Works in |
|---|---|---|
| Git hooks | `templates/project/lefthook.yml` via `project-checks-init`: biome, tsc, terraform fmt, tflint, openspec, shellcheck, gitleaks, no AI trailers | every harness + humans |
| Commands | `bin/`: `verify`, `wait-for`, `smoke`, `tf-check`, `ecs-deploy-status`, `project-checks-init` | anything with a shell |
| Policy engine | `bin/agent-policy` (`policy/agent_policy.py`, stdlib Python): allow/deny/defer for shell commands, including chains, pipes, loops, `$(…)`, `bash -c` | via adapters below |
| Post-edit checks | `bin/agent-post-edit`: project biome/prettier, terraform fmt, shellcheck, py_compile, openspec validate | via adapters below |
| Instructions | `AGENTS.md` | linked/imported into each harness |

## Adapters

| Harness | Shell policy | Post-edit | Instructions |
|---|---|---|---|
| Claude Code | `settings.json` PreToolUse → `agent-policy hook claude` (allow/deny) | PostToolUse → `agent-post-edit --hook claude` | `CLAUDE.md` imports `AGENTS.md` |
| Codex | `hooks.json` PreToolUse → `agent-policy hook codex` | — (apply_patch not hookable) | `~/.codex/AGENTS.md` |
| Cursor | `hooks.json` beforeShellExecution → `agent-policy hook cursor` | afterFileEdit (formats only) | Cursor Settings > Rules (manual) |
| opencode | plugin `adapters/opencode/agent-kit.js` (deny + auto-answer bash permission) | plugin, appended to tool output | `~/.config/opencode/AGENTS.md` |
| Pi | extension `adapters/pi/agent-kit.ts` (deny) | extension, appended to tool result | `~/.pi/agent/AGENTS.md` |
| Gemini CLI | — | — | `~/.gemini/GEMINI.md` |

## Decisions

- **allow**: every part is read-only (`config/policy.json` lists) or a permitted local write (git add/commit/switch,
  formatters, installs, writes under temp dirs or `write_allow_globs`).
- **deny**: AI attribution trailers in commits/PRs; gitleaks findings before `git commit`; file edits via the shell
  (`sed -i`, `perl -i`, script heredocs writing files, `cat > file <<EOF`) outside temp dirs.
- **defer**: everything else, so the harness's own rules and prompts apply unchanged.
- **rewrite hint** (Claude only): Claude Code prompts for `cd X && …` chains and loops even when the hook allows
  them, so the hook denies those once with a concrete rewrite and the agent retries on its own. The same command is
  never hinted twice, and after `rewrite_hints.max_consecutive` (2) hints in a row the normal prompt appears.
  Disable with `"rewrite_hints": {"enabled": false}` in an overlay or `AGENT_REWRITE_HINTS=0`.

Explain a decision: `agent-policy check 'cd repo && git log | head'`. Self-test: `agent-policy test`.

## Per-project configuration

- `.agent-policy.json`: overlay on `config/policy.json` (lists append, scalars override; `deny_prefixes` win over any
  allow). Local dev setup, never committed: keep it in the repo's main checkout and list `/.agent-policy.json` in
  `.git/info/exclude` (shared by all worktrees). Linked worktrees inherit it from the
  main checkout; a worktree's own file is layered on top. `project-checks-init` sets this up. Template in `templates/project`.
- `.agent/env`: KEY=value env for the kit commands. `.agent/verify`, `.agent/smoke/<env>.txt`: command overrides.
- User-wide overlay: `~/.config/agent-kit/policy.json`.
- Env: `AGENT_ALLOW_SHELL_EDITS=1`, `AGENT_SKIP_GITLEAKS=1`, `AGENT_POST_EDIT=0`.

## Scopes, reviewed proposals and directory sync (`policy/policy_review.py`)

`bin/agent-policy` runs `policy/policy_review.py`, which wraps `agent_policy.py` unchanged and adds:

- **Scopes**: `config/scopes/<name>.json` = `{"match": ["~/path/glob*"], …policy keys}`. Applies when the working
  directory or a parent matches; only widens (lists append, `directories` merge). Order: base → user overlay →
  scopes (broadest first) → main-checkout `.agent-policy.json`. `agent-policy scopes` shows what applies here.
- **Policy keys it adds**: `directories.read` / `directories.write` (folders the harness may touch outside the
  working folder) and `habit_hints` (`{pattern, hint}`: the Claude hook denies a matching command once with the
  hint, for shapes that trip Claude's built-in safety prompt even when the policy allows them).
- **Proposal queue** (machine-local, `state/`, git-ignored): a session-retro step (e.g. an agent skill that reviews where a session needed a human) queues candidates; nothing reaches a
  policy file until accepted. `agent-policy proposals list [--all]`, `show ID`, `accept ID [--target
  repo[:path]|scope:NAME|user|base] [--match GLOB]`, `reject ID --reason …`, `gate ID --reason …`. Destructive,
  publishing and credential/over-broad entries are auto-gated and cannot be accepted; `accept` re-checks the recorded
  example commands and shows each decision before → after. Decisions log to `state/decisions.jsonl`.
- **Sync**: `agent-policy sync [--cwd DIR] [--all-worktrees] | --user [--dry-run]` writes `directories` into
  Claude Code `additionalDirectories` (`<checkout>/.claude/settings.local.json`, or `~/.claude/settings.json` for
  base + user). It removes only what it added. `accept` syncs automatically.
- Self-test: `agent-policy review-test`.
