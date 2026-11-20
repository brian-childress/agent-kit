# agent-kit

One harness-neutral layer that makes coding agents deterministic and cuts approval prompts, across
Claude Code, Codex, Cursor, opencode, Pi and Gemini, on any machine.

```
git clone <your remote> ~/.agent-kit && ~/.agent-kit/install.sh      # or copy the folder
~/.agent-kit/install.sh --dry-run | --uninstall | --only claude,cursor
```

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
  `.git/info/exclude` (shared by all worktrees). Linked worktrees, including v2c's `.worktrees/`, inherit it from the
  main checkout; a worktree's own file is layered on top. `project-checks-init` sets this up. Template in `templates/project`.
- `.agent/env`: KEY=value env for the kit commands. `.agent/verify`, `.agent/smoke/<env>.txt`: command overrides.
- User-wide overlay: `~/.config/agent-kit/policy.json`.
- Env: `AGENT_ALLOW_SHELL_EDITS=1`, `AGENT_SKIP_GITLEAKS=1`, `AGENT_POST_EDIT=0`.
