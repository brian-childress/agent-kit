// agent-kit adapter for Pi. Installed by <agent-kit>/install.sh (symlinked into ~/.pi/agent/extensions).
// bash tool calls → agent-policy: deny blocks the call (Pi has no approval prompt of its own to auto-answer).
// edit/write      → agent-post-edit: failures are appended to the tool result so the model sees them.
const { spawnSync } = require("node:child_process");
const { homedir } = require("node:os");
const { join } = require("node:path");

const KIT = process.env.AGENT_KIT_HOME || join(homedir(), ".agent-kit");

export default function (pi): void {
  pi.on("tool_call", async (event, ctx) => {
    if (event.toolName !== "bash" || typeof event.input?.command !== "string") return undefined;
    const r = spawnSync(join(KIT, "bin", "agent-policy"), ["check", "--json", "--cwd", ctx?.cwd || process.cwd()], {
      input: event.input.command, encoding: "utf8", timeout: 70000,
    });
    let res = { decision: "defer", reason: "" };
    try { res = JSON.parse(r.stdout); } catch {}
    if (res.decision === "deny") return { block: true, reason: res.reason };
    return undefined;
  });

  pi.on("tool_result", async (event) => {
    if (event.toolName !== "edit" && event.toolName !== "write") return undefined;
    const file = event.input?.path;
    if (typeof file !== "string") return undefined;
    const r = spawnSync(join(KIT, "bin", "agent-post-edit"), [file], { encoding: "utf8", timeout: 130000 });
    if (r.status !== 2 || !r.stderr) return undefined;
    return { content: [...(event.content || []), { type: "text", text: `\n[agent-kit post-edit]\n${r.stderr}` }] };
  });
}
