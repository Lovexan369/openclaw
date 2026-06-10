import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { planShellAuthorization } from "../infra/exec-authorization-plan.js";
import { resolveSystemRunExecArgv } from "./invoke-system-run-allowlist.js";

function planSegments(plan: Awaited<ReturnType<typeof planShellAuthorization>>) {
  return plan.ok
    ? plan.groups.flatMap((group) => group.candidates.map((candidate) => candidate.sourceSegment))
    : [];
}

describe("resolveSystemRunExecArgv", () => {
  it.runIf(process.platform !== "win32")(
    "enforces POSIX shell allowlist commands before execution",
    async () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-node-host-allowlist-"));
      const git = path.join(dir, "git");
      fs.writeFileSync(git, "");
      fs.chmodSync(git, 0o755);
      const env = { PATH: dir };
      const shellCommand = "git status";
      const plan = await planShellAuthorization({ command: shellCommand, env });
      expect(plan.ok).toBe(true);
      if (!plan.ok) {
        throw new Error(plan.reason);
      }

      const result = resolveSystemRunExecArgv({
        plannedAllowlistArgv: undefined,
        argv: ["/bin/sh", "-lc", shellCommand],
        security: "allowlist",
        isWindows: false,
        policy: {
          approvedByAsk: false,
          analysisOk: true,
          allowlistSatisfied: true,
        },
        shellCommand,
        segments: planSegments(plan),
        segmentSatisfiedBy: ["allowlist"],
        segmentAllowlistEntries: [{ pattern: fs.realpathSync(git) }],
        authorizationPlan: plan,
        cwd: undefined,
        env,
      });

      expect(result).not.toEqual(["/bin/sh", "-lc", shellCommand]);
      expect(result?.[2]).toContain(fs.realpathSync(git));
    },
  );

  it.runIf(process.platform !== "win32")(
    "preserves shell-expanded allowlist arguments while pinning the executable",
    async () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-node-host-allowlist-"));
      const git = path.join(dir, "git");
      fs.writeFileSync(git, "");
      fs.chmodSync(git, 0o755);
      const env = { PATH: dir };
      const shellCommand = "git -C ~/repo status";
      const plan = await planShellAuthorization({ command: shellCommand, env });
      expect(plan.ok).toBe(true);
      if (!plan.ok) {
        throw new Error(plan.reason);
      }

      const result = resolveSystemRunExecArgv({
        plannedAllowlistArgv: undefined,
        argv: ["/bin/sh", "-lc", shellCommand],
        security: "allowlist",
        isWindows: false,
        policy: {
          approvedByAsk: false,
          analysisOk: true,
          allowlistSatisfied: true,
        },
        shellCommand,
        segments: planSegments(plan),
        segmentSatisfiedBy: ["allowlist"],
        segmentAllowlistEntries: [{ pattern: fs.realpathSync(git) }],
        authorizationPlan: plan,
        cwd: undefined,
        env,
      });

      expect(result?.[2]).toContain(fs.realpathSync(git));
      expect(result?.[2]).toContain(" -C ~/repo status");
      expect(result?.[2]).not.toContain("'~/repo'");
    },
  );

  it.runIf(process.platform !== "win32")(
    "quotes argPattern allowlist arguments before execution",
    async () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-node-host-allowlist-"));
      const tool = path.join(dir, "tool");
      fs.writeFileSync(tool, "");
      fs.chmodSync(tool, 0o755);
      const env = { PATH: dir };
      const shellCommand = "tool *.txt";
      const plan = await planShellAuthorization({ command: shellCommand, env });
      expect(plan.ok).toBe(true);
      if (!plan.ok) {
        throw new Error(plan.reason);
      }

      const result = resolveSystemRunExecArgv({
        plannedAllowlistArgv: undefined,
        argv: ["/bin/sh", "-lc", shellCommand],
        security: "allowlist",
        isWindows: false,
        policy: {
          approvedByAsk: false,
          analysisOk: true,
          allowlistSatisfied: true,
        },
        shellCommand,
        segments: planSegments(plan),
        segmentSatisfiedBy: ["allowlist"],
        segmentAllowlistEntries: [
          { pattern: fs.realpathSync(tool), argPattern: "^\\*\\.txt\x00$" },
        ],
        authorizationPlan: plan,
        cwd: undefined,
        env,
      });

      expect(result?.[2]).toContain(fs.realpathSync(tool));
      expect(result?.[2]).toContain("'*.txt'");
    },
  );

  it.runIf(process.platform !== "win32")("rejects a stale POSIX authorization plan", async () => {
    const env = { PATH: "/usr/bin:/bin" };
    const plan = await planShellAuthorization({ command: "echo nope", env });
    expect(plan.ok).toBe(true);
    if (!plan.ok) {
      throw new Error(plan.reason);
    }

    const result = resolveSystemRunExecArgv({
      plannedAllowlistArgv: undefined,
      argv: ["/bin/sh", "-lc", "head -c 16"],
      security: "allowlist",
      isWindows: false,
      policy: {
        approvedByAsk: false,
        analysisOk: true,
        allowlistSatisfied: true,
      },
      shellCommand: "head -c 16",
      segments: planSegments(plan),
      segmentSatisfiedBy: ["safeBins"],
      segmentAllowlistEntries: [null],
      authorizationPlan: plan,
      cwd: undefined,
      env,
    });

    expect(result).toBeNull();
  });
});
