# Global agent instructions (agent-kit)

Shared by every coding agent on this machine (Claude Code, Codex, Cursor, opencode, Pi, Gemini).
Source of truth: `~/.agent-kit/AGENTS.md`. Edit it there; each harness links or imports it.

## Response rules

- End-of-turn summaries: what changed and what's next only. No "Note:" explanations or implementation rationale unless the user asks.

## Git

- Never add authorship or co-authorship lines to commits or PRs: no `Co-Authored-By:` / `Co-authored-by:` trailers and no "Generated with Claude Code" footers. (Enforced by agent-policy.)

## Tool use (deterministic, low-prompt)

A policy hook (`agent-policy`) auto-approves shell commands whose every part is read-only or a safe local
write, blocks a few unsafe patterns, and leaves everything else to the normal approval flow.

- Edit files only with your edit/write tools. Never use `sed -i`, `perl -pi`, script heredocs that write files, or `cat > file <<EOF` (blocked; writing under /tmp or $TMPDIR is fine).
- Use absolute paths or `git -C`/`--dir`/`--prefix`/`-chdir`/`make -C` flags instead of `cd X && …`, and pass several paths to one command instead of writing `for`/`while` loops. Pipes and `&&` chains of read-only commands are auto-approved, so don't contort commands to avoid them.
- If a command is blocked with an "agent-policy rewrite hint", retry it rewritten as the hint says; don't ask the user.
- Never write `sleep`/`until`/`while` polling loops. Use `wait-for`, `gh run watch --exit-status`, `gh pr checks --watch`, `aws ecs wait services-stable`, `aws cloudfront wait …`, `docker compose up --wait`.
- Don't put paths or commands in shell variables (`S=~/x; ls $S`, `V=…/bin/v2c; $V step`). Write the literal absolute path every time and call CLIs by name (`v2c step`). Claude Code prompts for variable expansion even when the policy allows the command.
- Use `--query`/`--jq`/`--output text` on aws/gh instead of piping into python. Read JSON files with `jq`, not `python3 -c "import json…"`.
- Commands in the policy's `bare_commands` (today: `v2c`) run bare: exactly `v2c <subcommand> <args>`, one per call, no pipe, redirect, chain, `$VAR`, `python3` or `jq`. Their output is already compact and sized for the harness. Pass text input as a heredoc.
- Tests and checks are part of development: run them through `v2c gate`/`v2c step`, the repo's `.agent/v2c/test.sh` and `.agent/v2c/checks.sh`, `.agent/verify`, or the package's test runner (`pnpm --dir <pkg> exec vitest run …`, `npx --prefix <pkg> vitest run …`, `node --test …`, `dotnet test …`). These run without a prompt; don't wrap them in `$VAR`, `$(…)` or `echo exit=$?`.
- Don't write throwaway scripts into /tmp to run repeatedly; if a multi-step command will be reused, propose a repo script or an agent-kit command instead.
- Formatting/lint of edited files runs automatically after each edit (`agent-post-edit`). Fix what it reports; don't re-run formatters by hand.
- `agent-policy check '<cmd>'` explains how a command would be classified.

## Global commands (on PATH, auto-approved)

- `verify [--quick] [--only js,tf,dotnet,openspec,secrets]` — the one way to check work before reporting done or committing. Honors a repo's `.agent/verify` or package.json `verify` script.
- `wait-for url|port|file|gone|cmd …` — wait on a condition.
- `smoke [env]` — HTTP checks from `.agent/smoke/<env>.txt`.
- `tf-check [dir]` — terraform fmt + validate (+ tflint) without touching backend/state.
- `ecs-deploy-status [--wait] [--sha SHA]` — ECS stability + deployed image tag (uses `ECS_CLUSTER`/`ECS_SERVICES`).
- `project-checks-init` — only when asked: copies lefthook.yml and `.agent/` templates into a repo, and creates a git-ignored `.agent-policy.json` in its main checkout.
- Prefer an existing repo script (package.json, Makefile, `.agent/*`, `.claude/scripts/*`) over composing commands.

## Per-project configuration (harness-neutral)

- `<main checkout>/.agent-policy.json` — extra allow/deny prefixes, write globs, guard toggles, `post_edit`, `project_scripts`. Local dev setup, never committed: ignored via `.git/info/exclude`, and every worktree of the repo inherits it.
- `<repo>/.agent/env` — env for the kit commands (VERIFY_SKIP, ECS_CLUSTER, AWS_PROFILE, ...). No secrets.
- `<repo>/.agent/verify`, `<repo>/.agent/smoke/<env>.txt` — project overrides for `verify` / `smoke`.
- `<repo>/lefthook.yml` — git hooks; they run for every harness and for humans.
