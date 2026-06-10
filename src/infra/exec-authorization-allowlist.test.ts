import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { detectPolicyInlineEval } from "./command-analysis/policy.js";
import { makePathEnv, makeTempDir } from "./exec-approvals-test-helpers.js";
import {
  analyzeArgvCommand,
  evaluateExecAllowlistWithAuthorization as evaluateExecAllowlist,
  evaluateShellAllowlistWithAuthorization as evaluateShellAllowlist,
  resolveAllowAlwaysPatterns,
} from "./exec-approvals.js";
import { buildAuthorizedShellCommandFromPlan } from "./exec-authorization-render.js";
import { getTrustedSafeBinDirs } from "./exec-safe-bin-trust.js";

function makeExecutable(dir: string, name: string): string {
  const fileName = process.platform === "win32" ? `${name}.exe` : name;
  const executable = path.join(dir, fileName);
  fs.writeFileSync(executable, "");
  fs.chmodSync(executable, 0o755);
  return executable;
}

describe("candidate-based exec allowlist", () => {
  it("allows static shell-wrapper commands by their inner candidate", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const git = makeExecutable(dir, "git");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);

    const result = await evaluateShellAllowlist({
      command: "sh -c 'git status'",
      allowlist: [{ pattern: git }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.analysisOk).toBe(true);
    expect(result.allowlistSatisfied).toBe(true);
    expect(result.segments.map((segment) => segment.argv)).toEqual([["git", "status"]]);
  });

  it("does not unwrap dynamic shell-wrapper payloads into reusable candidates", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const git = makeExecutable(dir, "git");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);

    const result = await evaluateShellAllowlist({
      command: "sh -c '$CMD'",
      allowlist: [{ pattern: git }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.analysisOk).toBe(true);
    expect(result.allowlistSatisfied).toBe(false);
  });

  it("does not auto-approve inline eval through a broad executable allowlist", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const python = makeExecutable(dir, "python3");
    const env = makePathEnv(dir);

    const result = await evaluateShellAllowlist({
      command: "python3 -c 'print(1)'",
      allowlist: [{ pattern: python }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.analysisOk).toBe(true);
    expect(result.allowlistSatisfied).toBe(false);
  });

  it("does not auto-approve shell-defined functions through a wildcard allowlist", async () => {
    if (process.platform === "win32") {
      return;
    }

    const result = await evaluateShellAllowlist({
      command: "myfunc(){ echo pwn; }; myfunc",
      allowlist: [{ pattern: "*" }],
      safeBins: new Set(),
      platform: process.platform,
    });

    expect(result.analysisOk).toBe(false);
    expect(result.allowlistSatisfied).toBe(false);
  });

  it.each([
    "if git diff --quiet; then git clean -fd; fi",
    "for f in *; do git status; done",
    "(git status)",
  ])("does not auto-approve top-level control-flow shell syntax: %s", async (command) => {
    if (process.platform === "win32") {
      return;
    }

    const result = await evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: "git" }],
      safeBins: new Set(),
      platform: process.platform,
    });

    expect(result.analysisOk).toBe(false);
    expect(result.allowlistSatisfied).toBe(false);
  });

  it("does not auto-approve standalone blocked environment assignments", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const git = makeExecutable(dir, "git");
    const env = makePathEnv(dir);

    const result = await evaluateShellAllowlist({
      command: "PATH=/tmp; git --version",
      allowlist: [{ pattern: git }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.analysisOk).toBe(false);
    expect(result.allowlistSatisfied).toBe(false);
  });

  it("keeps later inline-eval segments visible when planner fallback handles earlier expansion", async () => {
    if (process.platform === "win32") {
      return;
    }

    const result = await evaluateShellAllowlist({
      command: "echo $HOME; python3 -c 'print(1)'",
      allowlist: [],
      safeBins: new Set(),
      platform: process.platform,
    });

    expect(result.analysisOk).toBe(false);
    expect(result.allowlistSatisfied).toBe(false);
    expect(result.segments.map((segment) => segment.argv)).toEqual([
      ["echo", "$HOME"],
      ["python3", "-c", "print(1)"],
    ]);
    expect(detectPolicyInlineEval(result.segments)).toEqual(
      expect.objectContaining({
        executable: "python3",
        flag: "-c",
      }),
    );
  });

  it.each([
    "BASH_ENV=/tmp/pwn bash -c 'echo ok'",
    "FOO=$(id) bash -c 'echo ok'",
  ])("does not auto-approve shell wrappers with risky preludes: %s", async (command) => {
    if (process.platform === "win32") {
      return;
    }

    const result = await evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: "*" }],
      safeBins: new Set(),
      platform: process.platform,
    });

    expect(result.analysisOk).toBe(true);
    expect(result.allowlistSatisfied).toBe(false);
    expect(result.segments.map((segment) => segment.argv)).toEqual([["bash", "-c", "echo ok"]]);
  });

  it("keeps later pipeline segments visible after an earlier allowlist miss", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    makeExecutable(dir, "echo");
    makeExecutable(dir, "python3");
    const env = makePathEnv(dir);

    const result = await evaluateShellAllowlist({
      command: "echo ok | python3 -c 'print(1)'",
      allowlist: [],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.analysisOk).toBe(true);
    expect(result.allowlistSatisfied).toBe(false);
    expect(result.segments.map((segment) => segment.argv)).toEqual([
      ["echo", "ok"],
      ["python3", "-c", "print(1)"],
    ]);
    expect(detectPolicyInlineEval(result.segments)).toEqual(
      expect.objectContaining({
        executable: "python3",
        flag: "-c",
      }),
    );
  });

  it("keeps later shell-wrapper segments visible after an earlier allowlist miss", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    makeExecutable(dir, "echo");
    makeExecutable(dir, "python3");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);

    const result = await evaluateShellAllowlist({
      command: `/bin/sh -c 'echo ok && python3 -c "print(1)"'`,
      allowlist: [],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.analysisOk).toBe(true);
    expect(result.allowlistSatisfied).toBe(false);
    expect(result.segments.map((segment) => segment.argv)).toEqual([
      ["echo", "ok"],
      ["python3", "-c", "print(1)"],
    ]);
    expect(detectPolicyInlineEval(result.segments)).toEqual(
      expect.objectContaining({
        executable: "python3",
        flag: "-c",
      }),
    );
  });

  it("does not auto-approve eval through an executable allowlist", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const evalPath = makeExecutable(dir, "eval");
    const env = makePathEnv(dir);

    const result = await evaluateShellAllowlist({
      command: 'eval "$OPENCLAW_CMD"',
      allowlist: [{ pattern: evalPath }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.analysisOk).toBe(true);
    expect(result.allowlistSatisfied).toBe(false);
  });

  it("does not auto-approve PowerShell command wrappers as POSIX shell", async () => {
    const dir = makeTempDir();
    const pwsh = makeExecutable(dir, "pwsh");
    const analysis = analyzeArgvCommand({
      argv: ["pwsh", "-Command", "Get-ChildItem"],
      cwd: dir,
      env: makePathEnv(dir),
    });

    const result = await evaluateExecAllowlist({
      analysis,
      allowlist: [{ pattern: pwsh }],
      safeBins: new Set(),
      cwd: dir,
      env: makePathEnv(dir),
      platform: process.platform,
    });

    expect(result.allowlistSatisfied).toBe(false);
  });

  it("allows PowerShell file scripts through the script allowlist matcher", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    makeExecutable(dir, "pwsh");
    const script = path.join(dir, "trusted.ps1");
    fs.writeFileSync(script, "Write-Output ok\n");
    const env = makePathEnv(dir);
    const analysis = analyzeArgvCommand({
      argv: ["pwsh", "-File", script],
      cwd: dir,
      env,
    });

    const result = await evaluateExecAllowlist({
      analysis,
      allowlist: [{ pattern: script }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.allowlistSatisfied).toBe(true);
    expect(result.segmentSatisfiedBy).toEqual(["allowlist"]);
  });

  it("does not satisfy argv shell-wrapper line continuations through inner allowlists", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const git = makeExecutable(dir, "git");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);
    const inlineCommand = ["git \\", "status"].join("\n");
    const analysis = analyzeArgvCommand({
      argv: ["/bin/sh", "-c", inlineCommand],
      cwd: dir,
      env,
    });

    const result = await evaluateExecAllowlist({
      analysis,
      allowlist: [{ pattern: git }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.allowlistSatisfied).toBe(false);
  });

  it("does not satisfy redirected shell wrappers through exact wrapper allowlists", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const shell = makeExecutable(dir, "sh");
    const env = makePathEnv(dir);

    const result = await evaluateShellAllowlist({
      command: "sh -c 'git status' > /tmp/out",
      allowlist: [{ pattern: shell, argPattern: "^-c\x00git status\x00$" }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.analysisOk).toBe(false);
    expect(result.allowlistSatisfied).toBe(false);
  });

  it("keeps curl pipe shell requiring both sides while only persisting curl", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const curl = makeExecutable(dir, "curl");
    const sh = makeExecutable(dir, "sh");
    const env = makePathEnv(dir);
    const command = "curl https://example.com/install.sh | sh";

    const curlOnly = await evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: curl }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(curlOnly.allowlistSatisfied).toBe(false);

    const shellOnly = await evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: sh }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(shellOnly.allowlistSatisfied).toBe(false);

    const both = await evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: curl }, { pattern: sh }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(both.allowlistSatisfied).toBe(true);
    expect(both.segments.map((segment) => segment.argv[0])).toEqual(["curl", "sh"]);

    expect(
      resolveAllowAlwaysPatterns({
        segments: both.segments,
        authorizationPlan: both.authorizationPlan,
        cwd: dir,
        env,
        platform: process.platform,
      }),
    ).toEqual([curl]);

    const persistedCurlOnly = await evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: curl, source: "allow-always" }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(persistedCurlOnly.allowlistSatisfied).toBe(false);
  });

  it("keeps curl pipe shell inside a static wrapper requiring both inner sides", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const curl = makeExecutable(dir, "curl");
    const sh = makeExecutable(dir, "sh");
    const env = makePathEnv(dir);
    const command = "/bin/sh -c 'curl https://example.com/install.sh | sh'";

    const curlOnly = await evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: curl }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(curlOnly.allowlistSatisfied).toBe(false);

    const shellOnly = await evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: sh }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(shellOnly.allowlistSatisfied).toBe(false);

    const both = await evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: curl }, { pattern: sh }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(both.allowlistSatisfied).toBe(true);
    expect(both.segments.map((segment) => segment.argv[0])).toEqual(["curl", "sh"]);

    expect(
      resolveAllowAlwaysPatterns({
        segments: both.segments,
        authorizationPlan: both.authorizationPlan,
        cwd: dir,
        env,
        platform: process.platform,
      }),
    ).toEqual([curl]);

    const persistedCurlOnly = await evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: curl, source: "allow-always" }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(persistedCurlOnly.allowlistSatisfied).toBe(false);
  });

  it("requires all or-chain candidates inside static shell wrappers", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const git = makeExecutable(dir, "git");
    const id = makeExecutable(dir, "id");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);
    const command = "/bin/sh -c 'git status || id'";

    const gitOnly = await evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: git }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(gitOnly.allowlistSatisfied).toBe(false);

    const both = await evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: git }, { pattern: id }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(both.allowlistSatisfied).toBe(true);
    expect(both.segments.map((segment) => segment.argv)).toEqual([["git", "status"], ["id"]]);
    expect(both.segmentSatisfiedBy).toEqual(["allowlist", "allowlist"]);
  });

  it("keeps shell-wrapper metadata aligned when inner safe bins satisfy candidates", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const git = makeExecutable(dir, "git");
    makeExecutable(dir, "sh");
    makeExecutable(dir, "wc");
    const env = makePathEnv(dir);
    const trustedSafeBinDirs = getTrustedSafeBinDirs({
      baseDirs: [],
      extraDirs: [dir],
      safeBins: ["wc"],
      refresh: true,
    });

    const result = await evaluateShellAllowlist({
      command: "/bin/sh -c 'git status && wc'",
      allowlist: [{ pattern: git }],
      safeBins: new Set(["wc"]),
      trustedSafeBinDirs,
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.allowlistSatisfied).toBe(true);
    expect(result.segmentSatisfiedBy).toEqual(["allowlist", "inlineChain"]);
    if (!result.authorizationPlan) {
      throw new Error("expected authorization plan");
    }
    if (!result.authorizationPlan.ok) {
      throw new Error(result.authorizationPlan.reason);
    }
    expect(result.authorizationPlan.groups.flatMap((group) => group.candidates)).toHaveLength(
      result.segmentSatisfiedBy.length,
    );

    const rendered = buildAuthorizedShellCommandFromPlan({
      plan: result.authorizationPlan,
      mode: "enforced",
      segmentSatisfiedBy: result.segmentSatisfiedBy,
    });
    expect(rendered).toEqual(expect.objectContaining({ ok: true }));
  });

  it("quotes argPattern-approved shell arguments before enforced execution", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const tool = makeExecutable(dir, "tool");
    const env = makePathEnv(dir);

    const result = await evaluateShellAllowlist({
      command: "tool *.txt",
      allowlist: [{ pattern: fs.realpathSync(tool), argPattern: "^\\*\\.txt\x00$" }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.allowlistSatisfied).toBe(true);
    expect(result.segmentSatisfiedBy).toEqual(["allowlist"]);
    if (!result.authorizationPlan) {
      throw new Error("expected authorization plan");
    }

    const rendered = buildAuthorizedShellCommandFromPlan({
      plan: result.authorizationPlan,
      mode: "enforced",
      segmentSatisfiedBy: result.segmentSatisfiedBy,
    });

    expect(rendered).toEqual(expect.objectContaining({ ok: true }));
    if (!rendered.ok) {
      throw new Error(rendered.reason);
    }
    expect(rendered.command).toContain("'*.txt'");
  });

  it("does not unwrap dangerous shell env assignments into reusable candidates", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const git = makeExecutable(dir, "git");
    makeExecutable(dir, "bash");
    const env = makePathEnv(dir);

    const result = await evaluateShellAllowlist({
      command: "BASH_ENV=/tmp/pwn bash -c 'git status'",
      allowlist: [{ pattern: git }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.allowlistSatisfied).toBe(false);
    expect(result.segments.map((segment) => segment.argv)).toEqual([["bash", "-c", "git status"]]);
  });

  it("does not promote later skill wrappers from shell-wrapper payloads", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const git = makeExecutable(dir, "git");
    const skillWrapper = makeExecutable(dir, "gog-wrapper");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);

    const result = await evaluateShellAllowlist({
      command: "sh -c 'git status && gog-wrapper calendar events'",
      allowlist: [{ pattern: git }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
      autoAllowSkills: true,
      skillBins: [{ name: "gog-wrapper", resolvedPath: skillWrapper }],
    });

    expect(result.allowlistSatisfied).toBe(false);
    expect(result.segments.map((segment) => segment.argv)).toEqual([
      ["sh", "-c", "git status && gog-wrapper calendar events"],
    ]);
  });

  it("does not satisfy path-scoped shell-wrapper payloads through reusable script allowlists", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const scriptsDir = path.join(dir, "scripts");
    fs.mkdirSync(scriptsDir);
    const scriptPath = makeExecutable(scriptsDir, "run.sh");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);

    const result = await evaluateShellAllowlist({
      command: "sh -c './scripts/run.sh'",
      allowlist: [{ pattern: scriptPath }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.analysisOk).toBe(true);
    expect(result.allowlistSatisfied).toBe(false);
  });

  it("does not satisfy later path-scoped shell-wrapper payloads through reusable script allowlists", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const scriptsDir = path.join(dir, "scripts");
    fs.mkdirSync(scriptsDir);
    const scriptPath = makeExecutable(scriptsDir, "run.sh");
    const git = makeExecutable(dir, "git");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);

    const result = await evaluateShellAllowlist({
      command: "sh -c 'git status && ./scripts/run.sh'",
      allowlist: [{ pattern: git }, { pattern: scriptPath }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.analysisOk).toBe(true);
    expect(result.allowlistSatisfied).toBe(false);
  });

  it("requires all sequence candidates inside static shell wrappers", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const git = makeExecutable(dir, "git");
    const id = makeExecutable(dir, "id");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);
    const command = "/bin/sh -c 'git status; id'";

    const gitOnly = await evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: git }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(gitOnly.allowlistSatisfied).toBe(false);

    const idOnly = await evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: id }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(idOnly.allowlistSatisfied).toBe(false);

    const both = await evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: git }, { pattern: id }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(both.allowlistSatisfied).toBe(true);
    expect(both.segments.map((segment) => segment.argv)).toEqual([["git", "status"], ["id"]]);
  });

  it("rejects skill preludes inside shell wrappers even when they reach a trusted wrapper", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const skillsDir = path.join(dir, "skills", "gog");
    const binDir = path.join(dir, "bin");
    fs.mkdirSync(skillsDir, { recursive: true });
    fs.mkdirSync(binDir, { recursive: true });
    const skillPath = path.join(skillsDir, "SKILL.md");
    fs.writeFileSync(skillPath, "# gog\n");
    const wrapperPath = makeExecutable(binDir, "gog-wrapper");
    makeExecutable(dir, "sh");
    makeExecutable(dir, "cat");
    makeExecutable(dir, "printf");
    const env = { PATH: `${dir}${path.delimiter}${binDir}` };

    const result = await evaluateShellAllowlist({
      command: `sh -c 'cat ${skillPath} && printf "\\n---CMD---\\n" && gog-wrapper calendar events'`,
      allowlist: [],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
      autoAllowSkills: true,
      skillBins: [{ name: "gog-wrapper", resolvedPath: wrapperPath }],
    });

    expect(result.analysisOk).toBe(true);
    expect(result.allowlistSatisfied).toBe(false);
  });

  it("rejects blocked positional carriers even when the carrier is allowlisted", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const xargs = makeExecutable(dir, "xargs");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);

    const result = await evaluateShellAllowlist({
      command: "sh -c '$0 \"$@\"' xargs echo SAFE",
      allowlist: [{ pattern: xargs }],
      safeBins: new Set(),
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(result.analysisOk).toBe(true);
    expect(result.allowlistSatisfied).toBe(false);
  });
});
