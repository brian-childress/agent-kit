// agent-kit adapter for opencode. Installed by <agent-kit>/install.sh (symlinked into ~/.config/opencode/plugins).
// Shell commands  → agent-policy: deny blocks the call; allow auto-answers opencode's bash permission prompt.
// Edit/Write      → agent-post-edit: failures are appended to the tool output so the model sees them.
import { spawnSync } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";

const KIT = process.env.AGENT_KIT_HOME || join(homedir(), ".agent-kit");
const decisions = new Map(); // callID -> decision

function policy(command, cwd) {
  const r = spawnSync(join(KIT, "bin", "agent-policy"), ["check", "--json", "--cwd", cwd || process.cwd()], {
    input: command, encoding: "utf8", timeout: 70000,
  });
  try { return JSON.parse(r.stdout); } catch { return { decision: "defer", reason: "agent-policy unavailable" }; }
}

export const AgentKitPlugin = async ({ directory }) => ({
  "tool.execute.before": async (input, output) => {
    if (input.tool !== "bash" || !output?.args?.command) return;
    const res = policy(output.args.command, output.args.workdir || directory);
    decisions.set(input.callID, res.decision);
    if (res.decision === "deny") throw new Error(res.reason);
  },
  "permission.ask": async (input, output) => {
    if (input.type !== "bash") return;
    let d = input.callID && decisions.get(input.callID);
    const cmd = input.metadata?.command;
    if (!d && typeof cmd === "string") d = policy(cmd, directory).decision;
    if (d === "allow") output.status = "allow";
    if (d === "deny") output.status = "deny";
  },
  "tool.execute.after": async (input, output) => {
    if (!["edit", "write", "multiedit", "patch"].includes(input.tool)) return;
    const file = input.args?.filePath || input.args?.file_path || input.args?.path;
    if (!file) return;
    const r = spawnSync(join(KIT, "bin", "agent-post-edit"), [file], { encoding: "utf8", timeout: 130000 });
    if (r.status === 2 && r.stderr) output.output = `${output.output ?? ""}\n\n[agent-kit post-edit]\n${r.stderr}`;
  },
});
