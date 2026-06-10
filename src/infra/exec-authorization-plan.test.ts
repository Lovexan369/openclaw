import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeArgvCommand } from "./exec-approvals-analysis.js";
import { planExecAuthorization, planShellAuthorization } from "./exec-authorization-plan.js";
import { buildAuthorizedShellCommandFromPlan } from "./exec-authorization-render.js";

function plannedArgv(plan: Awaited<ReturnType<typeof planShellAuthorization>>): string[][] {
  return plan.ok
    ? plan.groups.flatMap((group) =>
        group.candidates.map((candidate) => candidate.sourceSegment.argv),
      )
    : [];
}

function makeExecutable(dir: string, name: string): string {
  const file = path.join(dir, name);
  fs.writeFileSync(file, "");
  fs.chmodSync(file, 0o755);
  return fs.realpathSync(file);
}

describe("exec authorization planner", () => {
  it("plans direct shell commands as direct candidates", async () => {
    const plan = await planShellAuthorization({ command: "git status" });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            sourceSegment: expect.objectContaining({ argv: ["git", "status"] }),
            transport: { kind: "direct" },
            trustMode: "executable",
          }),
        ],
      }),
    ]);
  });

  it("preserves pipeline candidates separately", async () => {
    const plan = await planShellAuthorization({ command: "git diff | cat" });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            sourceSegment: expect.objectContaining({ argv: ["git", "diff"] }),
          }),
          expect.objectContaining({ sourceSegment: expect.objectContaining({ argv: ["cat"] }) }),
        ],
      }),
    ]);
  });

  it("keeps chain groups distinct", async () => {
    const plan = await planShellAuthorization({ command: "git status && npm test; pwd" });

    expect(plan.ok).toBe(true);
    expect(plan.groups.map((group) => group.opToNext ?? null)).toEqual(["&&", ";", null]);
    expect(plannedArgv(plan)).toEqual([["git", "status"], ["npm", "test"], ["pwd"]]);
  });

  it("marks dynamic executable positions as not safe to plan", async () => {
    const plan = await planShellAuthorization({ command: "$(whoami) --help" });

    expect(plan).toEqual(
      expect.objectContaining({
        ok: false,
        dialect: "posix-shell",
        reason: "dynamic-executable",
      }),
    );
  });

  it("treats heredocs as unanalyzable shell topology", async () => {
    const plan = await planShellAuthorization({ command: "cat <<EOF\nhello\nEOF" });

    expect(plan).toEqual(
      expect.objectContaining({
        ok: false,
        dialect: "posix-shell",
        reason: "heredoc",
      }),
    );
  });

  it.each([
    { command: "echo $(whoami)", reason: "command-substitution" },
    { command: "echo `whoami`", reason: "command-substitution" },
    { command: "cat <(echo ok)", reason: "process-substitution" },
    { command: "myfunc(){ echo pwn; }; myfunc", reason: "function-definition" },
    { command: "echo $HOME", reason: "dynamic-argument" },
  ])("treats $reason as unanalyzable shell topology", async ({ command, reason }) => {
    const plan = await planShellAuthorization({ command });

    expect(plan).toEqual(
      expect.objectContaining({
        ok: false,
        dialect: "posix-shell",
        reason,
      }),
    );
  });

  it("preserves background shell operators in authorization plans", async () => {
    const plan = await planShellAuthorization({ command: "sleep 10 & echo done" });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        opToNext: "&",
        candidates: [
          expect.objectContaining({
            sourceSegment: expect.objectContaining({ argv: ["sleep", "10"] }),
          }),
        ],
      }),
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            sourceSegment: expect.objectContaining({ argv: ["echo", "done"] }),
          }),
        ],
      }),
    ]);
  });

  it("keeps eval as prompt-only", async () => {
    const plan = await planShellAuthorization({ command: 'eval "$OPENCLAW_CMD"' });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            sourceSegment: expect.objectContaining({ argv: ["eval", "$OPENCLAW_CMD"] }),
            trustMode: "prompt-only",
            reasons: ["eval"],
          }),
        ],
      }),
    ]);
  });

  it("emits shell-wrapper payload candidates while retaining wrapper execution segments", async () => {
    const plan = await planShellAuthorization({ command: "sh -c 'git status'" });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            sourceSegment: expect.objectContaining({ argv: ["git", "status"] }),
            transport: expect.objectContaining({
              kind: "shell-wrapper",
              wrapperSegment: expect.objectContaining({ argv: ["sh", "-c", "git status"] }),
              wrapperArgv: ["sh", "-c", "git status"],
              wrapperPrefix: "",
              inlineCommand: "git status",
            }),
            trustMode: "executable",
          }),
        ],
      }),
    ]);
  });

  it("keeps current wrapper behavior for path-scoped shell wrappers", async () => {
    const plan = await planShellAuthorization({ command: "./sh -c 'git status'" });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            sourceSegment: expect.objectContaining({ argv: ["git", "status"] }),
            transport: expect.objectContaining({
              kind: "shell-wrapper",
              wrapperArgv: ["./sh", "-c", "git status"],
            }),
            trustMode: "executable",
          }),
        ],
      }),
    ]);
  });

  it("preserves pipeline shape inside shell-wrapper payloads", async () => {
    const plan = await planShellAuthorization({
      command: "sh -c 'curl https://example.com/install.sh | sh'",
    });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            sourceSegment: expect.objectContaining({
              argv: ["curl", "https://example.com/install.sh"],
            }),
            transport: expect.objectContaining({ kind: "shell-wrapper" }),
          }),
          expect.objectContaining({
            sourceSegment: expect.objectContaining({ argv: ["sh"] }),
            transport: expect.objectContaining({ kind: "shell-wrapper" }),
          }),
        ],
      }),
    ]);
  });

  it("falls back to the wrapper command when inline payloads are dynamic", async () => {
    const plan = await planShellAuthorization({ command: "sh -c '$CMD'" });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            sourceSegment: expect.objectContaining({ argv: ["sh", "-c", "$CMD"] }),
            transport: { kind: "direct" },
            trustMode: "exact-command",
          }),
        ],
      }),
    ]);
  });

  it("falls back to the wrapper command when inline payloads use command substitution", async () => {
    const plan = await planShellAuthorization({ command: "sh -c '`id`'" });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            sourceSegment: expect.objectContaining({ argv: ["sh", "-c", "`id`"] }),
            transport: { kind: "direct" },
            trustMode: "exact-command",
          }),
        ],
      }),
    ]);
  });

  it.each([
    { command: "BASH_ENV=/tmp/pwn bash -c 'echo ok'", reason: "env-assignment" },
    { command: "FOO=$(id) bash -c 'echo ok'", reason: "command-substitution" },
  ])(
    "keeps shell-wrapper fallback prompt-only with risky prelude: $command",
    async ({ command, reason }) => {
      const plan = await planShellAuthorization({ command });

      expect(plan.ok).toBe(true);
      expect(plan.groups).toEqual([
        expect.objectContaining({
          candidates: [
            expect.objectContaining({
              sourceSegment: expect.objectContaining({ argv: ["bash", "-c", "echo ok"] }),
              transport: { kind: "direct" },
              trustMode: "prompt-only",
              reasons: [reason],
            }),
          ],
        }),
      ]);
    },
  );

  it("falls back to the wrapper command when argv inline payloads use line continuations", async () => {
    const inlineCommand = ["git \\", "status"].join("\n");
    const analysis = analyzeArgvCommand({ argv: ["/bin/sh", "-c", inlineCommand] });
    const plan = await planExecAuthorization({ analysis });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            sourceSegment: expect.objectContaining({ argv: ["/bin/sh", "-c", inlineCommand] }),
            transport: { kind: "direct" },
            trustMode: "exact-command",
          }),
        ],
      }),
    ]);
  });

  it("does not promote path-scoped shell-wrapper payloads into reusable inner candidates", async () => {
    const plan = await planShellAuthorization({ command: "sh -c './scripts/run.sh'" });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            sourceSegment: expect.objectContaining({ argv: ["sh", "-c", "./scripts/run.sh"] }),
            transport: { kind: "direct" },
            trustMode: "exact-command",
          }),
        ],
      }),
    ]);
  });

  it("does not promote later path-scoped shell-wrapper payload commands", async () => {
    const plan = await planShellAuthorization({
      command: "sh -c 'git status && ./scripts/run.sh'",
    });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            sourceSegment: expect.objectContaining({
              argv: ["sh", "-c", "git status && ./scripts/run.sh"],
            }),
            transport: { kind: "direct" },
            trustMode: "exact-command",
          }),
        ],
      }),
    ]);
  });

  it("does not promote shell-wrapper payloads with control flow", async () => {
    const plan = await planShellAuthorization({
      command: "sh -c 'if git diff --quiet; then git clean -fd; fi'",
    });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            sourceSegment: expect.objectContaining({
              argv: ["sh", "-c", "if git diff --quiet; then git clean -fd; fi"],
            }),
            transport: { kind: "direct" },
            trustMode: "exact-command",
          }),
        ],
      }),
    ]);
  });

  it("does not promote skill-wrapper payloads into reusable inner candidates", async () => {
    const plan = await planShellAuthorization({ command: "sh -c 'gog-wrapper calendar events'" });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            sourceSegment: expect.objectContaining({
              argv: ["sh", "-c", "gog-wrapper calendar events"],
            }),
            transport: { kind: "direct" },
            trustMode: "exact-command",
          }),
        ],
      }),
    ]);
  });

  it("keeps env -S shell wrappers policy blocked", async () => {
    const plan = await planShellAuthorization({ command: "env -S 'sh -c \"echo pwned\"' tr" });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            sourceSegment: expect.objectContaining({
              argv: ["env", "-S", 'sh -c "echo pwned"', "tr"],
            }),
            transport: { kind: "direct" },
            trustMode: "prompt-only",
          }),
        ],
      }),
    ]);
  });

  it("does not unwrap positional shell carriers as normal inline payloads", async () => {
    const plan = await planShellAuthorization({ command: "sh -c '$0 \"$@\"' xargs echo SAFE" });

    expect(plan.ok).toBe(true);
    expect(plan.groups).toEqual([
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            sourceSegment: expect.objectContaining({
              argv: ["sh", "-c", '$0 "$@"', "xargs", "echo", "SAFE"],
            }),
            transport: { kind: "direct" },
            trustMode: "exact-command",
          }),
        ],
      }),
    ]);
  });

  it("plans argv shell wrappers through the same candidate contract", async () => {
    const analysis = analyzeArgvCommand({ argv: ["sh", "-c", "whoami && ls"] });
    const plan = await planExecAuthorization({ analysis });

    expect(plan.ok).toBe(true);
    expect(plannedArgv(plan)).toEqual([["whoami"], ["ls"]]);
    expect(plan.groups.map((group) => group.opToNext ?? null)).toEqual(["&&", null]);
    expect(
      plan.groups.flatMap((group) => group.candidates.map((candidate) => candidate.transport.kind)),
    ).toEqual(["shell-wrapper", "shell-wrapper"]);
  });

  it("does not treat PowerShell wrappers as POSIX shell payloads", async () => {
    const analysis = analyzeArgvCommand({ argv: ["pwsh", "-Command", "Get-ChildItem"] });
    const plan = await planExecAuthorization({ analysis });

    expect(plan).toEqual(
      expect.objectContaining({
        ok: false,
        dialect: "powershell",
        reason: "non-POSIX command wrapper",
      }),
    );
  });

  it("does not treat Windows cmd wrappers as POSIX shell payloads", async () => {
    const analysis = analyzeArgvCommand({ argv: ["cmd", "/c", "dir"] });
    const plan = await planExecAuthorization({ analysis });

    expect(plan).toEqual(
      expect.objectContaining({
        ok: false,
        dialect: "windows-cmd",
        reason: "non-POSIX command wrapper",
      }),
    );
  });

  it("renders safe-bin replacements from authorization plan topology", async () => {
    const plan = await planShellAuthorization({
      command: "rg foo src/*.ts | head -n 5 && echo ok",
    });

    const rendered = buildAuthorizedShellCommandFromPlan({
      plan,
      mode: "safeBins",
      segmentSatisfiedBy: [null, "safeBins", null],
    });

    expect(rendered).toEqual(expect.objectContaining({ ok: true }));
    if (!rendered.ok) {
      throw new Error(rendered.reason);
    }
    expect(rendered.command).toContain("rg foo src/*.ts");
    expect(rendered.command).toContain("|");
    expect(rendered.command).toContain("&&");
    expect(rendered.command).toMatch(/\| '(?:\S+\/)?head' '-n' '5' &&/);
  });

  it("fails closed when render metadata does not match the plan candidates", async () => {
    const plan = await planShellAuthorization({
      command: "rg foo src/*.ts | head -n 5",
    });

    const rendered = buildAuthorizedShellCommandFromPlan({
      plan,
      mode: "safeBins",
      segmentSatisfiedBy: ["safeBins"],
    });

    expect(rendered).toEqual({ ok: false, reason: "segment metadata mismatch" });
  });

  it("renders enforced POSIX commands with literal argv", async () => {
    const plan = await planShellAuthorization({ command: "head -c 16 package.json" });

    const rendered = buildAuthorizedShellCommandFromPlan({
      plan,
      mode: "enforced",
    });

    expect(rendered).toEqual(expect.objectContaining({ ok: true }));
    if (!rendered.ok) {
      throw new Error(rendered.reason);
    }
    expect(rendered.command).toMatch(/^'(?:\S+\/)?head' '-c' '16' 'package\.json'$/);
  });

  it("pins POSIX executables while preserving shell-expanded arguments", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-exec-render-"));
    const git = makeExecutable(dir, "git");
    const plan = await planShellAuthorization({
      command: "git -C ~/repo status",
      env: { PATH: dir },
    });

    const rendered = buildAuthorizedShellCommandFromPlan({
      plan,
      mode: "executable",
      segmentSatisfiedBy: ["allowlist"],
    });

    expect(rendered).toEqual(expect.objectContaining({ ok: true }));
    if (!rendered.ok) {
      throw new Error(rendered.reason);
    }
    expect(rendered.command).toBe(`${git} -C ~/repo status`);
  });

  it("quotes forced allowlist argument matches in executable mode", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-exec-render-"));
    makeExecutable(dir, "tool");
    const plan = await planShellAuthorization({
      command: "tool *.txt",
      env: { PATH: dir },
    });

    const rendered = buildAuthorizedShellCommandFromPlan({
      plan,
      mode: "executable",
      segmentSatisfiedBy: ["allowlist"],
      forceRewriteSegments: [true],
    });

    expect(rendered).toEqual(expect.objectContaining({ ok: true }));
    if (!rendered.ok) {
      throw new Error(rendered.reason);
    }
    expect(rendered.command).toContain("'*.txt'");
  });

  it("renders transparent dispatch wrappers from the full planned argv", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-exec-render-"));
    const git = makeExecutable(dir, "git");
    const plan = await planShellAuthorization({
      command: "env git status",
      env: { PATH: dir },
    });

    const rendered = buildAuthorizedShellCommandFromPlan({
      plan,
      mode: "enforced",
    });

    expect(rendered).toEqual(expect.objectContaining({ ok: true }));
    if (!rendered.ok) {
      throw new Error(rendered.reason);
    }
    expect(rendered.command).toBe(`'${git}' 'status'`);
    expect(rendered.command).not.toContain(`${git} git status`);
  });

  it("preserves leading env assignments while enforcing executable paths", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-exec-render-"));
    const git = makeExecutable(dir, "git");
    const plan = await planShellAuthorization({
      command: "FOO=1 git status",
      env: { PATH: dir },
    });

    const rendered = buildAuthorizedShellCommandFromPlan({
      plan,
      mode: "enforced",
    });

    expect(rendered).toEqual(expect.objectContaining({ ok: true }));
    if (!rendered.ok) {
      throw new Error(rendered.reason);
    }
    expect(rendered.command).toBe(`FOO=1 '${git}' 'status'`);
  });

  it("preserves declaration command arguments while enforcing executable paths", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-exec-render-"));
    const echo = makeExecutable(dir, "echo");
    const plan = await planShellAuthorization({
      command: "export FOO=bar; echo ok",
      env: { PATH: dir },
    });

    const rendered = buildAuthorizedShellCommandFromPlan({
      plan,
      mode: "enforced",
      segmentSatisfiedBy: ["allowlist", "allowlist"],
    });

    expect(rendered).toEqual(expect.objectContaining({ ok: true }));
    if (!rendered.ok) {
      throw new Error(rendered.reason);
    }
    expect(rendered.command).toBe(`'export' 'FOO=bar'; '${echo}' 'ok'`);
  });

  it("renders shell-wrapper payloads by replacing the wrapper inline command", async () => {
    const plan = await planShellAuthorization({ command: "sh -c 'git status && head -c 16'" });

    const rendered = buildAuthorizedShellCommandFromPlan({
      plan,
      mode: "safeBins",
      segmentSatisfiedBy: [null, "safeBins"],
    });

    expect(rendered).toEqual(expect.objectContaining({ ok: true }));
    if (!rendered.ok) {
      throw new Error(rendered.reason);
    }
    expect(rendered.command).toMatch(/^'?sh'? '?-c'? /);
    expect(rendered.command).not.toContain("git status && head -c 16");
    expect(rendered.command).toContain("git status &&");
    expect(rendered.command).toContain("head");
    expect(rendered.command).toContain("-c");
    expect(rendered.command).not.toContain("'git'");
  });

  it("preserves attached shell command flags when rendering wrappers", async () => {
    const plan = await planShellAuthorization({ command: "sh -c'echo ok'" });

    const rendered = buildAuthorizedShellCommandFromPlan({
      plan,
      mode: "enforced",
    });

    expect(rendered).toEqual(expect.objectContaining({ ok: true }));
    if (!rendered.ok) {
      throw new Error(rendered.reason);
    }
    expect(rendered.command).toContain("'-c'");
    const output = execFileSync("/bin/sh", ["-c", rendered.command], { encoding: "utf8" });
    expect(output.trim()).toBe("ok");
  });

  it("renders shell-wrapper payloads when resolved executable paths need quotes", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw exec render "));
    const git = path.join(dir, "git");
    fs.writeFileSync(git, '#!/bin/sh\necho git-ran "$@"\n');
    fs.chmodSync(git, 0o755);
    const plan = await planShellAuthorization({
      command: "sh -c 'git status'",
      env: { PATH: `${dir}${path.delimiter}${process.env.PATH ?? ""}` },
    });

    const rendered = buildAuthorizedShellCommandFromPlan({
      plan,
      mode: "enforced",
      segmentSatisfiedBy: ["allowlist"],
    });

    expect(rendered).toEqual(expect.objectContaining({ ok: true }));
    if (!rendered.ok) {
      throw new Error(rendered.reason);
    }
    const output = execFileSync("/bin/sh", ["-c", rendered.command], {
      encoding: "utf8",
      env: { ...process.env, PATH: `${dir}${path.delimiter}${process.env.PATH ?? ""}` },
    });
    expect(output.trim()).toBe("git-ran status");
  });

  it("preserves shell-wrapper payload env assignments while enforcing executable paths", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-exec-render-"));
    const git = makeExecutable(dir, "git");
    const plan = await planShellAuthorization({
      command: "/bin/sh -c 'FOO=bar git status'",
      env: { PATH: dir },
    });

    const rendered = buildAuthorizedShellCommandFromPlan({
      plan,
      mode: "enforced",
    });

    expect(rendered).toEqual(expect.objectContaining({ ok: true }));
    if (!rendered.ok) {
      throw new Error(rendered.reason);
    }
    expect(rendered.command).toContain("FOO=bar ");
    expect(rendered.command).toContain(git);
    expect(rendered.command).toContain("status");
  });

  it("preserves leading env assignments before shell wrappers while enforcing payloads", async () => {
    const plan = await planShellAuthorization({
      command: "FOO=bar sh -c 'printenv FOO'",
    });

    const rendered = buildAuthorizedShellCommandFromPlan({
      plan,
      mode: "enforced",
    });

    expect(rendered).toEqual(expect.objectContaining({ ok: true }));
    if (!rendered.ok) {
      throw new Error(rendered.reason);
    }
    expect(rendered.command).toMatch(/^FOO=bar '?sh'? '?-c'? /);
    const output = execFileSync("/bin/sh", ["-c", rendered.command], { encoding: "utf8" });
    expect(output.trim()).toBe("bar");
  });

  it("preserves background operators while rendering rewritten commands", async () => {
    const plan = await planShellAuthorization({ command: "rg foo & head -n 5" });

    const rendered = buildAuthorizedShellCommandFromPlan({
      plan,
      mode: "safeBins",
      segmentSatisfiedBy: [null, "safeBins"],
    });

    expect(rendered).toEqual(expect.objectContaining({ ok: true }));
    if (!rendered.ok) {
      throw new Error(rendered.reason);
    }
    expect(rendered.command).toContain(" & ");
    expect(rendered.command).toMatch(/& '(?:\S+\/)?head' '-n' '5'/);
  });

  it("renders safe-bin rewrites with literal argv", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-exec-safe-render-"));
    const tr = path.join(dir, "tr");
    fs.writeFileSync(tr, '#!/bin/sh\nprintf "%s\\n" "$#|$1|$2|$3"\n');
    fs.chmodSync(tr, 0o755);
    const plan = await planShellAuthorization({
      command: "tr a{b,c} x",
      env: { PATH: dir },
    });

    const rendered = buildAuthorizedShellCommandFromPlan({
      plan,
      mode: "safeBins",
      segmentSatisfiedBy: ["safeBins"],
    });

    expect(rendered).toEqual(expect.objectContaining({ ok: true }));
    if (!rendered.ok) {
      throw new Error(rendered.reason);
    }
    const output = execFileSync("/bin/sh", ["-c", rendered.command], { encoding: "utf8" });
    expect(output.trim()).toBe("2|a{b,c}|x|");
  });

  it("preserves decoded shell-wrapper newline operators while rendering rewritten commands", async () => {
    const plan = await planShellAuthorization({
      command: String.raw`sh -c $'git status\necho ok'`,
    });

    const rendered = buildAuthorizedShellCommandFromPlan({
      plan,
      mode: "enforced",
    });

    expect(rendered).toEqual(expect.objectContaining({ ok: true }));
    if (!rendered.ok) {
      throw new Error(rendered.reason);
    }
    expect(rendered.command).toContain(";");
    expect(rendered.command).not.toContain("|");
  });
});
