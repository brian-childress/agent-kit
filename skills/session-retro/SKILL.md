---
name: session-retro
description: Review the whole current (or a named) Claude Code session for every point where a human had to step in — permission prompts, refusals, questions the agent asked — and queue reviewed agent-policy proposals (command prefixes, folder access, habit hints) so every future session and harness needs fewer. Use when the user says "session retro", "review this session", "what needed my input", "reduce permission prompts", or "improve the allowed list".
---

# Session retro — where did the human have to step in?

Everything lands in **agent-policy** (`~/.agent-kit`), the one policy every harness uses — never in a
harness's own settings by hand. Nothing is applied blindly: this skill **queues proposals**; the human
accepts or rejects each one (`agent-policy proposals …`). Decisions are remembered, so a rejected or
keep-gated item is never proposed again.

Reads Claude Code transcripts (`~/.claude/projects/<slug>/<session>.jsonl`); the proposals it queues apply
to every harness. Ships with agent-kit (`skills/session-retro`); `install.sh` links it into `~/.claude/skills`.

## 1. Gather the evidence and raw candidates (deterministic)

```bash
python3 -I ~/.agent-kit/skills/session-retro/scripts/session_retro.py --cwd <repo> --proposals /tmp/session-retro-proposals.json [SESSION] > /tmp/session-retro.md
```

- `SESSION` = a session id, a `.jsonl` path, or omitted (newest transcript for `--cwd`'s project = this session).
- Read `/tmp/session-retro.md` in full: the permission summary, every human-approved/refused call with the
  harness `reasonCode` and the `agent-policy check` verdict, grouped candidates, human turns (`ASKED` = the
  agent had just asked a question), AskUserQuestion calls, refusals.
- Every tool decision is recorded in the transcript as `permissionDecision.source`: `config` / `hook` cost
  nothing; `user_temporary` / `user_permanent` / `user_reject` / `user_abort` are the human interventions.
- Then read the queue so you don't re-propose decided items: `agent-policy proposals list --all`.

## 2. Classify each intervention by root cause

| reasonCode | Cause | Proposal |
|---|---|---|
| `bashMiss:no-rule-match` / agent-policy `defer` | No rule covers the command | `readonly_prefixes` (read-only) or `local_write_prefixes` (safe local write) — the hook then auto-approves it in every harness |
| `outsideReadsBlocked` | Path outside the session's working folders | `directories.read` / `directories.write` — `agent-policy sync` renders it into each harness (Claude `additionalDirectories`) |
| `safetyCheck` | Claude's built-in safety prompt; fires even when agent-policy says allow | `habit_hints` `{pattern, hint}` — the hook denies a matching command once with the rewrite, so the agent retries in a shape that doesn't prompt |
| `user_reject` / `user_abort` | The human refused | Queue the prefix with `"status": "keep-gated"` so it is never allow-listed |
| `rule:*` | An `ask` rule matched | Intended; no proposal |

Human turns: an `ASKED` turn whose answer was derivable from code, memory or an obvious default is a
**feedback memory** candidate (not a policy entry). A genuine decision (scope, destructive, outward-facing) was
right to ask — list it as such.

## 3. Curate the raw candidates — this is the review the human relies on

The `--proposals` file is deliberately noisy. Build a curated JSON list (Write tool, e.g.
`/tmp/session-retro-curated.json`), one object per proposal:

```json
{"key": "readonly_prefixes", "value": "docker volume ls", "target": "user",
 "rationale": "why this is safe and how often it recurs",
 "evidence": {"prompts": 2, "session": "<id>", "reasons": {"safetyCheck": 2}, "examples": ["docker volume ls"]}}
```

- **Narrowest value**: `docker volume ls`, not `docker`; a project folder, not its parent. Bare interpreters
  and wrappers (`python3`, `pnpm`, `rtk proxy`, `cat`) are refused by the tool — name the read-only subcommand.
- **Right target** (where the access belongs):
  - `repo` / `repo:<path>` → that repo's main-checkout `.agent-policy.json` (git-ignored; every worktree inherits it).
  - `scope:<name>` → `~/.agent-kit/config/scopes/<name>.json`: broader access for a folder tree, matched by
    path globs (e.g. every `~/code/myapp*` checkout). Give `--match` when the human accepts a new scope.
  - `user` → `~/.config/agent-kit/policy.json`: machine-wide tools (`docker volume ls`) and habit hints.
  - `base` only for changes that belong in the kit for every machine.
- **Drop**: one-off investigations (say so in the rationale if you keep them as "recommend reject"),
  folders the harness already grants (check `~/.claude/settings.json` `additionalDirectories`), temp dirs,
  anything already in the queue.
- **Never propose as allow**: deletes/prunes, `git push`/reset, terraform apply, cloud writes, PR/issue/Linear
  writes, credential folders, `~`/`~/Library`-wide access. The tool auto-gates these; queue refusals as
  `"status": "keep-gated", "reason": "…"`.

Queue them: `agent-policy proposals add /tmp/session-retro-curated.json --cwd <repo>`

## 4. Report (the deliverable)

Write `session-retro-<YYYY-MM-DD>.md` to the repo's git-ignored scratch folder (e.g. `.artifacts/`; else
`/tmp`) and show the summary in chat:

1. **Headline** — N human interventions of M decided tool calls; the top causes by count.
2. **Queued proposals** — the `agent-policy proposals list` table, each with its rationale and how many
   prompts it would have saved; mark the ones you recommend accepting vs. rejecting.
3. **Keep prompting** — what was gated and why.
4. **Questions** — the ones that should not have been asked (with the memory that would prevent them) and the
   ones that were right to ask.
5. **How to review**: `agent-policy proposals show <id>`, `accept <id> [--target …] [--match GLOB]`,
   `reject <id> --reason …`, `gate <id> --reason …`.

## 5. Apply only what the human accepts

Run `agent-policy proposals accept <id>` only for ids the human named. `accept` refuses unsafe entries,
writes the overlay, proves the recorded example commands now classify `allow`, and syncs directory entries
into the harness configs (`agent-policy sync`). Directory changes take effect in the next session. Write
approved feedback memories per the memory instructions.
