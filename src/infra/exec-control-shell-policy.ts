import { splitShellArgs } from "../utils/shell-argv.js";
import { buildCommandPayloadCandidates } from "./command-analysis/risks.js";
import { explainShellCommand } from "./command-explainer/extract.js";

export type ControlShellPolicyDecision =
  | { kind: "allow" }
  | { kind: "deny"; message: string }
  | { kind: "requires-approval"; warning: string };

export type ControlShellParsedSegment = {
  argv: string[];
  raw?: string;
};

type ControlShellCandidate = {
  argv: string[];
  raw: string;
};

const INTERACTIVE_CHANNEL_LOGIN_DENY_MESSAGE = [
  "exec cannot run interactive OpenClaw channel login commands.",
  "Run `openclaw channels login` in a terminal on the gateway host, or use the channel-specific login agent tool when available (for WhatsApp: `whatsapp_login`).",
].join(" ");

const EXEC_APPROVAL_DENY_MESSAGE = [
  "exec cannot run /approve commands.",
  "Show the /approve command to the user as chat text, or route it through the approval command handler instead of shell execution.",
].join(" ");

const SECURITY_AUDIT_SUPPRESSION_WARNING =
  "Warning: security audit suppression changes require explicit approval unless exec is running in yolo mode.";

const OPENCLAW_FLAGS_WITH_VALUES = new Set([
  "--channel",
  "--config",
  "--container",
  "--log-level",
  "--profile",
]);

const OPENCLAW_VALUELESS_FLAGS = new Set(["--dev", "--no-color"]);
const PACKAGE_RUNNER_COMMANDS = new Set(["pnpm", "npm", "yarn"]);
const PACKAGE_RUNNER_VALUE_FLAGS = new Set([
  "-C",
  "-F",
  "-p",
  "--cwd",
  "--dir",
  "--filter",
  "--package",
  "--prefix",
  "--workspace",
]);
const PACKAGE_RUNNER_CALL_FLAGS = new Set(["-c", "--call"]);
const NPM_WORKSPACE_VALUE_FLAGS = new Set(["-w", "--workspace"]);

function normalizeCommandBaseName(token: string | undefined): string {
  if (!token) {
    return "";
  }
  const base = token.split(/[\\/]/u).at(-1)?.toLowerCase() ?? "";
  const normalized = base.replace(/\.(?:cmd|exe)$/u, "");
  return normalized === "openclaw" || normalized.startsWith("openclaw@") ? "openclaw" : normalized;
}

function stripOpenClawPackageRunner(argv: string[]): string[] {
  const commandName = normalizeCommandBaseName(argv[0]);
  if (commandName === "openclaw") {
    return argv;
  }
  if (PACKAGE_RUNNER_COMMANDS.has(commandName)) {
    const runnerCommandIndex = packageRunnerCommandIndex(argv, 1, commandName);
    if (normalizeCommandBaseName(argv[runnerCommandIndex]) === "openclaw") {
      return argv.slice(runnerCommandIndex);
    }
    const runnerCommand = argv[runnerCommandIndex] ?? "";
    if (
      runnerCommand === "exec" ||
      runnerCommand === "dlx" ||
      runnerCommand === "run" ||
      runnerCommand === "x"
    ) {
      const commandIndex = packageRunnerCommandIndex(argv, runnerCommandIndex + 1, commandName);
      if (normalizeCommandBaseName(argv[commandIndex]) === "openclaw") {
        return argv.slice(commandIndex);
      }
    }
  }
  if (commandName === "bun" && normalizeCommandBaseName(argv[1]) === "openclaw") {
    return argv.slice(1);
  }
  if (commandName === "npx" || commandName === "bunx") {
    const commandIndex = packageRunnerCommandIndex(argv, 1, commandName);
    if (normalizeCommandBaseName(argv[commandIndex]) === "openclaw") {
      return argv.slice(commandIndex);
    }
  }
  return argv;
}

function packageRunnerOptionConsumesValue(commandName: string, option: string): boolean {
  if (PACKAGE_RUNNER_VALUE_FLAGS.has(option)) {
    return true;
  }
  return (commandName === "npm" || commandName === "npx") && NPM_WORKSPACE_VALUE_FLAGS.has(option);
}

function packageRunnerCommandIndex(
  argv: string[],
  startIndex: number,
  commandName: string,
): number {
  let index = startIndex;
  while (index < argv.length) {
    const token = argv[index] ?? "";
    if (token === "--") {
      return index + 1;
    }
    if (!token.startsWith("-") || token === "-") {
      return index;
    }
    const name = optionName(token);
    index += 1;
    if (
      !token.includes("=") &&
      packageRunnerOptionConsumesValue(commandName, name) &&
      index < argv.length
    ) {
      index += 1;
    }
  }
  return index;
}

function optionName(token: string): string {
  return token.split("=", 1)[0] ?? token;
}

function optionInlineValue(token: string, option: string): string | null {
  if (token.startsWith(`${option}=`)) {
    return token.slice(option.length + 1);
  }
  if (option.length === 2 && token.startsWith(option) && token.length > option.length) {
    return token.slice(option.length);
  }
  return null;
}

function packageRunnerCallPayload(argv: string[]): string | null {
  const commandName = normalizeCommandBaseName(argv[0]);
  let index: number | null = null;
  if (PACKAGE_RUNNER_COMMANDS.has(commandName)) {
    const runnerCommandIndex = packageRunnerCommandIndex(argv, 1, commandName);
    const runnerCommand = argv[runnerCommandIndex] ?? "";
    if (runnerCommand === "exec" || runnerCommand === "dlx" || runnerCommand === "x") {
      index = runnerCommandIndex + 1;
    }
  } else if (commandName === "npx") {
    index = 1;
  }
  if (index === null) {
    return null;
  }
  while (index < argv.length) {
    const token = argv[index] ?? "";
    if (token === "--" || token === "-") {
      return null;
    }
    if (!token.startsWith("-")) {
      return null;
    }
    const name = optionName(token);
    if (PACKAGE_RUNNER_CALL_FLAGS.has(name)) {
      const inlineValue = optionInlineValue(token, name);
      const payload = inlineValue ?? argv[index + 1] ?? "";
      const trimmed = payload.trim();
      return trimmed.length > 0 ? trimmed : null;
    }
    index += 1;
    if (
      !token.includes("=") &&
      packageRunnerOptionConsumesValue(commandName, name) &&
      index < argv.length
    ) {
      index += 1;
    }
  }
  return null;
}

function packageRunnerExecPayloadArgv(argv: string[]): string[] | null {
  const commandName = normalizeCommandBaseName(argv[0]);
  let commandIndex: number | null = null;
  if (PACKAGE_RUNNER_COMMANDS.has(commandName)) {
    const runnerCommandIndex = packageRunnerCommandIndex(argv, 1, commandName);
    const runnerCommand = argv[runnerCommandIndex] ?? "";
    if (runnerCommand === "exec" || runnerCommand === "dlx" || runnerCommand === "x") {
      commandIndex = packageRunnerCommandIndex(argv, runnerCommandIndex + 1, commandName);
    }
  } else if (commandName === "npx" || commandName === "bunx") {
    commandIndex = packageRunnerCommandIndex(argv, 1, commandName);
  }
  if (commandIndex === null || commandIndex >= argv.length) {
    return null;
  }
  const payloadArgv = argv.slice(commandIndex);
  return payloadArgv.length > 0 ? payloadArgv : null;
}

function extractOpenClawWords(argv: string[]): string[] | null {
  const stripped = stripOpenClawPackageRunner(argv);
  if (normalizeCommandBaseName(stripped[0]) !== "openclaw") {
    return null;
  }
  const words: string[] = [];
  let index = 1;
  let optionsTerminated = false;
  while (index < stripped.length) {
    const token = stripped[index] ?? "";
    if (!optionsTerminated && token === "--") {
      optionsTerminated = true;
      index += 1;
      continue;
    }
    if (!optionsTerminated && OPENCLAW_VALUELESS_FLAGS.has(token)) {
      index += 1;
      continue;
    }
    if (!optionsTerminated && OPENCLAW_FLAGS_WITH_VALUES.has(token)) {
      index += 2;
      continue;
    }
    if (
      !optionsTerminated &&
      [...OPENCLAW_FLAGS_WITH_VALUES].some((flag) => token.startsWith(`${flag}=`))
    ) {
      index += 1;
      continue;
    }
    if (!optionsTerminated && token.startsWith("-") && token !== "-") {
      index += 1;
      continue;
    }
    words.push(token);
    index += 1;
  }
  return words;
}

function textMentionsSecurityAuditSuppressions(value: string): boolean {
  const normalized = value.toLowerCase();
  return (
    normalized.includes("security.audit.suppressions") ||
    /["']?security["']?[\s\S]{0,200}["']?audit["']?[\s\S]{0,200}["']?suppressions["']?/.test(
      normalized,
    )
  );
}

function candidateText(candidate: ControlShellCandidate): string {
  return `${candidate.raw} ${candidate.argv.join(" ")}`;
}

function removeCandidateText(
  command: string,
  candidates: readonly ControlShellCandidate[],
): string {
  let remaining = command;
  for (const candidate of candidates) {
    const raw = candidate.raw.trim();
    if (raw.length > 0) {
      remaining = remaining.replace(raw, " ");
    }
  }
  return remaining;
}

function isExecApprovalShellCommand(raw: string): boolean {
  return /^\/approve(?:@[^\s]+)?\s+[A-Za-z0-9][A-Za-z0-9._:-]*\s+(?:allow-once|allow-always|always|deny)\b/iu.test(
    raw.trimStart(),
  );
}

function isOpenClawChannelsLoginArgv(argv: string[]): boolean {
  const words = extractOpenClawWords(argv);
  return (
    words !== null && (words[0] === "channels" || words[0] === "channel") && words[1] === "login"
  );
}

function isReadOnlySecurityAuditSuppressionInspection(argv: string[]): boolean {
  const words = extractOpenClawWords(argv);
  return (
    words !== null &&
    words[0] === "config" &&
    (words[1] === "get" || words[1] === "schema" || words[1] === "validate")
  );
}

function requiresSecurityAuditSuppressionApproval(params: {
  command: string;
  candidates: readonly ControlShellCandidate[];
}): boolean {
  const mentioningCandidates = params.candidates.filter((candidate) =>
    textMentionsSecurityAuditSuppressions(candidateText(candidate)),
  );
  if (mentioningCandidates.length === 0) {
    return textMentionsSecurityAuditSuppressions(params.command);
  }
  if (
    mentioningCandidates.every((candidate) =>
      isReadOnlySecurityAuditSuppressionInspection(candidate.argv),
    )
  ) {
    return textMentionsSecurityAuditSuppressions(
      removeCandidateText(params.command, mentioningCandidates),
    );
  }
  return true;
}

export function parseOpenClawChannelsLoginShellCommand(raw: string): boolean {
  const argv = splitShellArgs(raw);
  return argv ? isOpenClawChannelsLoginArgv(argv) : false;
}

function appendCandidate(
  candidates: ControlShellCandidate[],
  seen: Set<string>,
  candidate: ControlShellCandidate,
): boolean {
  const key = `${candidate.raw}\0${candidate.argv.join("\0")}`;
  if (seen.has(key)) {
    return false;
  }
  seen.add(key);
  candidates.push(candidate);
  return true;
}

function candidateFromRaw(raw: string): ControlShellCandidate {
  return {
    argv: splitShellArgs(raw) ?? [],
    raw,
  };
}

async function appendShellCommandTextCandidates(params: {
  candidates: ControlShellCandidate[];
  seen: Set<string>;
  raw: string;
  depth: number;
}): Promise<void> {
  if (params.depth > 4) {
    return;
  }
  try {
    const explanation = await explainShellCommand(params.raw);
    if (explanation.ok) {
      for (const step of [...explanation.topLevelCommands, ...explanation.nestedCommands]) {
        appendCandidate(params.candidates, params.seen, {
          argv: step.argv,
          raw: step.text,
        });
        await appendPayloadCandidates({
          candidates: params.candidates,
          seen: params.seen,
          argv: step.argv,
          depth: params.depth + 1,
        });
      }
      return;
    }
  } catch {
    // Fall back to best-effort argv parsing below.
  }
  const candidate = candidateFromRaw(params.raw);
  if (appendCandidate(params.candidates, params.seen, candidate)) {
    await appendPayloadCandidates({
      candidates: params.candidates,
      seen: params.seen,
      argv: candidate.argv,
      depth: params.depth + 1,
    });
  }
}

async function appendPayloadCandidates(params: {
  candidates: ControlShellCandidate[];
  seen: Set<string>;
  argv: string[];
  depth?: number;
}): Promise<void> {
  const depth = params.depth ?? 0;
  if (depth > 4) {
    return;
  }
  for (const payload of buildCommandPayloadCandidates(params.argv)) {
    appendCandidate(params.candidates, params.seen, candidateFromRaw(payload));
  }
  const callPayload = packageRunnerCallPayload(params.argv);
  if (callPayload) {
    await appendShellCommandTextCandidates({
      candidates: params.candidates,
      seen: params.seen,
      raw: callPayload,
      depth: depth + 1,
    });
  }
  const execPayloadArgv = packageRunnerExecPayloadArgv(params.argv);
  if (execPayloadArgv) {
    const candidate = {
      argv: execPayloadArgv,
      raw: execPayloadArgv.join(" "),
    };
    if (appendCandidate(params.candidates, params.seen, candidate)) {
      await appendPayloadCandidates({
        candidates: params.candidates,
        seen: params.seen,
        argv: execPayloadArgv,
        depth: depth + 1,
      });
    }
  }
}

async function buildControlShellCandidates(params: {
  command: string;
  parsedSegments?: readonly ControlShellParsedSegment[];
}): Promise<ControlShellCandidate[]> {
  const candidates: ControlShellCandidate[] = [];
  const seen = new Set<string>();

  for (const segment of params.parsedSegments ?? []) {
    const candidate = {
      argv: segment.argv,
      raw: segment.raw ?? segment.argv.join(" "),
    };
    appendCandidate(candidates, seen, candidate);
    await appendPayloadCandidates({
      candidates,
      seen,
      argv: candidate.argv,
    });
  }

  try {
    const explanation = await explainShellCommand(params.command);
    if (explanation.ok) {
      for (const step of [...explanation.topLevelCommands, ...explanation.nestedCommands]) {
        appendCandidate(candidates, seen, {
          argv: step.argv,
          raw: step.text,
        });
        await appendPayloadCandidates({
          candidates,
          seen,
          argv: step.argv,
        });
      }
      return candidates;
    }
  } catch {
    // Fall back to best-effort line parsing below.
  }

  for (const line of params.command.split(/\r?\n/u)) {
    const raw = line.trim();
    if (raw.length === 0) {
      continue;
    }
    const fallback = candidateFromRaw(raw);
    appendCandidate(candidates, seen, fallback);
    await appendPayloadCandidates({
      candidates,
      seen,
      argv: fallback.argv,
    });
  }

  return candidates;
}

export async function inspectControlShellCommand(params: {
  command: string;
  parsedSegments?: readonly ControlShellParsedSegment[];
}): Promise<ControlShellPolicyDecision> {
  const command = params.command.trim();
  const candidates = await buildControlShellCandidates({
    command,
    parsedSegments: params.parsedSegments,
  });

  if (candidates.some((candidate) => isExecApprovalShellCommand(candidate.raw))) {
    return { kind: "deny", message: EXEC_APPROVAL_DENY_MESSAGE };
  }
  if (candidates.some((candidate) => isOpenClawChannelsLoginArgv(candidate.argv))) {
    return { kind: "deny", message: INTERACTIVE_CHANNEL_LOGIN_DENY_MESSAGE };
  }
  if (requiresSecurityAuditSuppressionApproval({ command, candidates })) {
    return { kind: "requires-approval", warning: SECURITY_AUDIT_SUPPRESSION_WARNING };
  }

  return { kind: "allow" };
}
