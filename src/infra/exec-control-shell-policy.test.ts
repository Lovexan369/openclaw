import { describe, expect, it } from "vitest";
import {
  inspectControlShellCommand,
  type ControlShellPolicyDecision,
} from "./exec-control-shell-policy.js";

async function inspect(command: string): Promise<ControlShellPolicyDecision> {
  return await inspectControlShellCommand({ command });
}

describe("exec control shell policy", () => {
  it.each([
    "/approve abc allow-always",
    "bash -lc '/approve abc deny'",
    "sh -c '/approve abc allow-once'",
    "env -S '/approve abc deny'",
    "sudo -EH bash -lc '/approve abc allow-once'",
    "command /approve abc deny",
    "npm exec -c '/approve abc deny'",
    "npm exec -c 'echo ok; /approve abc deny'",
    "npm exec -w app -c '/approve abc deny'",
    "npm --workspace app exec -c '/approve abc deny'",
    "npm x -c '/approve abc deny'",
    "npx -c '/approve abc deny'",
  ])("denies approval commands through exec policy: %s", async (command) => {
    await expect(inspect(command)).resolves.toMatchObject({
      kind: "deny",
      message: expect.stringContaining("exec cannot run /approve commands"),
    });
  });

  it.each([
    "openclaw channels login --channel whatsapp",
    "openclaw channel login --channel whatsapp",
    "openclaw --config ./openclaw.json channels login --channel whatsapp",
    "openclaw --config=./openclaw.json channels login --channel whatsapp",
    "openclaw channels --profile rescue login --channel whatsapp",
    "openclaw channels --dev login --channel whatsapp",
    "npm exec -- openclaw channels login --channel whatsapp",
    "npm x -c 'openclaw channels login --channel whatsapp'",
    "npm exec -- openclaw@latest channels login --channel whatsapp",
    "npm x openclaw channels login --channel whatsapp",
    "npm exec --package openclaw openclaw channels login --channel whatsapp",
    "npm exec --package=openclaw -- openclaw channels login --channel whatsapp",
    "npm exec -p openclaw openclaw channels login --channel whatsapp",
    "npm exec -c 'echo ok; openclaw channels login --channel whatsapp'",
    "npm --yes exec openclaw channels login --channel whatsapp",
    "npm --workspace app exec openclaw channels login --channel whatsapp",
    "pnpm exec -- openclaw channels login --channel whatsapp",
    "pnpm x openclaw channels login --channel whatsapp",
    "pnpm dlx openclaw@latest channels login --channel whatsapp",
    "pnpm --silent dlx openclaw channels login --channel whatsapp",
    "pnpm -w openclaw channels login --channel whatsapp",
    "pnpm -F app exec openclaw channels login --channel whatsapp",
    "pnpm -w exec -- openclaw channels login --channel whatsapp",
    "pnpm --dir . openclaw channels login --channel whatsapp",
    "pnpm --filter x openclaw channels login --channel whatsapp",
    "pnpm exec --package openclaw openclaw channels login --channel whatsapp",
    "yarn exec -- openclaw channels login --channel whatsapp",
    "yarn --silent exec openclaw channels login --channel whatsapp",
    "yarn --cwd . exec openclaw channels login --channel whatsapp",
    "sudo -u openclaw bash -lc 'openclaw channels login --channel whatsapp'",
    "bash -lc 'openclaw --profile rescue channels login --channel=whatsapp'",
    "env -S 'openclaw channels' login --channel whatsapp",
  ])("denies interactive channel login commands: %s", async (command) => {
    await expect(inspect(command)).resolves.toMatchObject({
      kind: "deny",
      message: expect.stringContaining(
        "exec cannot run interactive OpenClaw channel login commands",
      ),
    });
  });

  it("denies shell-wrapper payloads when parsed segments are provided", async () => {
    await expect(
      inspectControlShellCommand({
        command: "bash -lc 'openclaw channels login --channel whatsapp'",
        parsedSegments: [
          {
            argv: ["bash", "-lc", "openclaw channels login --channel whatsapp"],
          },
        ],
      }),
    ).resolves.toMatchObject({
      kind: "deny",
      message: expect.stringContaining(
        "exec cannot run interactive OpenClaw channel login commands",
      ),
    });
  });

  it.each([
    "openclaw config get security.audit.suppressions",
    "openclaw --profile rescue config get security.audit.suppressions",
    "openclaw config schema security.audit.suppressions",
    "openclaw config validate",
  ])("allows read-only security audit suppression inspection: %s", async (command) => {
    await expect(inspect(command)).resolves.toEqual({ kind: "allow" });
  });

  it.each([
    "openclaw config set security.audit.suppressions '[]'",
    "openclaw config get security.audit.suppressions; openclaw config set security.audit.suppressions '[]'",
    "bash -lc 'openclaw config set security.audit.suppressions []'",
    `openclaw config patch --stdin <<'EOF'
{"security":{"audit":{"suppressions":[]}}}
EOF`,
  ])("requires approval for security audit suppression mutations: %s", async (command) => {
    await expect(inspect(command)).resolves.toMatchObject({
      kind: "requires-approval",
      warning: expect.stringContaining(
        "security audit suppression changes require explicit approval",
      ),
    });
  });

  it("returns requires-approval without knowing whether yolo mode is active", async () => {
    await expect(inspect("openclaw config set security.audit.suppressions '[]'")).resolves.toEqual({
      kind: "requires-approval",
      warning:
        "Warning: security audit suppression changes require explicit approval unless exec is running in yolo mode.",
    });
  });
});
