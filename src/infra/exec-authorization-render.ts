import type { CommandOperator } from "./command-explainer/types.js";
import type { ExecSegmentSatisfiedBy } from "./exec-approvals-allowlist.js";
import { resolvePlannedSegmentArgv } from "./exec-approvals-analysis.js";
import type {
  ExecAuthorizationCandidate,
  ExecAuthorizationPlan,
} from "./exec-authorization-plan.js";
import { resolveInlineCommandMatch } from "./shell-inline-command.js";
import { POSIX_INLINE_COMMAND_FLAGS } from "./shell-inline-command.js";

export type AuthorizedShellRenderMode = "safeBins" | "enforced" | "executable";

export type AuthorizedShellRenderResult =
  | { ok: true; command: string }
  | { ok: false; reason: string };

const PIPE_OPERATOR_TEXT: Record<string, string> = {
  pipe: "|",
  "stderr-pipe": "|&",
};

function shellEscapeSingleArg(value: string): string {
  const singleQuoteEscape = `'"'"'`;
  return `'${value.replace(/'/g, singleQuoteEscape)}'`;
}

function renderQuotedArgv(argv: readonly string[]): string {
  return argv.map((token) => shellEscapeSingleArg(token)).join(" ");
}

function renderExecutableToken(value: string): string {
  return /^[A-Za-z0-9_./:@%+=,-]+$/u.test(value) ? value : shellEscapeSingleArg(value);
}

function shouldRewriteCandidate(params: {
  mode: AuthorizedShellRenderMode;
  satisfiedBy: ExecSegmentSatisfiedBy | undefined;
  forceRewrite: boolean;
}): boolean {
  if (params.mode === "enforced" || params.mode === "executable") {
    return true;
  }
  return (
    params.forceRewrite || params.satisfiedBy === "safeBins" || params.satisfiedBy === "inlineChain"
  );
}

function renderCandidate(params: {
  candidate: ExecAuthorizationCandidate;
  mode: AuthorizedShellRenderMode;
  satisfiedBy: ExecSegmentSatisfiedBy | undefined;
  forceRewrite: boolean;
}): AuthorizedShellRenderResult {
  if (
    !shouldRewriteCandidate({
      mode: params.mode,
      satisfiedBy: params.satisfiedBy,
      forceRewrite: params.forceRewrite,
    })
  ) {
    return { ok: true, command: params.candidate.sourceSegment.raw.trim() };
  }
  const argv = resolvePlannedSegmentArgv(params.candidate.sourceSegment);
  if (!argv) {
    return { ok: false, reason: "segment execution plan unavailable" };
  }
  return { ok: true, command: renderQuotedArgv(argv) };
}

type SourceReplacement = {
  startIndex: number;
  endIndex: number;
  text: string;
};

type SourceReplacementResult = SourceReplacement | null | { ok: false; reason: string };

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function sourceReplacementForCandidate(params: {
  candidate: ExecAuthorizationCandidate;
  mode: AuthorizedShellRenderMode;
  satisfiedBy: ExecSegmentSatisfiedBy | undefined;
  forceRewrite: boolean;
  sourceLength: number;
  sourceOffset?: number;
}): SourceReplacementResult {
  if (
    !shouldRewriteCandidate({
      mode: params.mode,
      satisfiedBy: params.satisfiedBy,
      forceRewrite: params.forceRewrite,
    })
  ) {
    return null;
  }
  const argv = resolvePlannedSegmentArgv(params.candidate.sourceSegment);
  const executable = argv?.[0];
  if (!executable) {
    return { ok: false, reason: "segment execution plan unavailable" };
  }
  const replaceExecutableAndArgs =
    params.mode === "enforced" ||
    params.forceRewrite ||
    params.satisfiedBy === "safeBins" ||
    !sameStrings(params.candidate.sourceSegment.argv.slice(1), argv.slice(1));
  const sourceOffset = params.sourceOffset ?? 0;
  const rawSpan = replaceExecutableAndArgs
    ? {
        ...params.candidate.sourceStep.span,
        startIndex: params.candidate.sourceStep.executableSpan.startIndex,
        startPosition: params.candidate.sourceStep.executableSpan.startPosition,
      }
    : params.candidate.sourceStep.executableSpan;
  const span = {
    startIndex: rawSpan.startIndex - sourceOffset,
    endIndex: rawSpan.endIndex - sourceOffset,
  };
  if (
    span.startIndex < 0 ||
    span.endIndex <= span.startIndex ||
    span.endIndex > params.sourceLength
  ) {
    return {
      ok: false,
      reason: replaceExecutableAndArgs
        ? "candidate argument span unavailable"
        : "candidate executable span unavailable",
    };
  }
  return {
    startIndex: span.startIndex,
    endIndex: span.endIndex,
    text: replaceExecutableAndArgs ? renderQuotedArgv(argv) : renderExecutableToken(executable),
  };
}

function operatorAfterCandidate(params: {
  operators: readonly CommandOperator[];
  candidate: ExecAuthorizationCandidate;
}): string | null {
  const stepId = params.candidate.sourceStepId;
  if (!stepId) {
    return null;
  }
  const operator = params.operators.find((entry) => entry.fromCommandId === stepId);
  if (!operator) {
    return null;
  }
  if (operator.kind === "pipe" || operator.kind === "stderr-pipe") {
    return PIPE_OPERATOR_TEXT[operator.kind] ?? "|";
  }
  if (operator.kind === "and") {
    return "&&";
  }
  if (operator.kind === "or") {
    return "||";
  }
  if (operator.kind === "background") {
    return "&";
  }
  return ";";
}

function renderPlanGroups(params: {
  plan: Extract<ExecAuthorizationPlan, { ok: true }>;
  mode: AuthorizedShellRenderMode;
  segmentSatisfiedBy: readonly ExecSegmentSatisfiedBy[];
  forceRewrite: boolean;
}): AuthorizedShellRenderResult {
  const renderedParts: string[] = [];
  let candidateIndex = 0;
  for (const group of params.plan.groups) {
    for (const [index, candidate] of group.candidates.entries()) {
      const rendered = renderCandidate({
        candidate,
        mode: params.mode,
        satisfiedBy: params.segmentSatisfiedBy[candidateIndex],
        forceRewrite: params.forceRewrite,
      });
      if (!rendered.ok) {
        return rendered;
      }
      renderedParts.push(rendered.command);
      candidateIndex += 1;
      if (index < group.candidates.length - 1) {
        const operator = operatorAfterCandidate({ operators: params.plan.operators, candidate });
        renderedParts.push(operator ?? "|");
      }
    }
    if (group.opToNext) {
      renderedParts.push(group.opToNext);
    }
  }
  return { ok: true, command: renderedParts.join(" ") };
}

function applySourceReplacements(params: {
  source: string;
  replacements: SourceReplacement[];
}): AuthorizedShellRenderResult {
  const ordered = params.replacements.toSorted((left, right) => left.startIndex - right.startIndex);
  let cursor = 0;
  let command = "";
  for (const replacement of ordered) {
    if (replacement.startIndex < cursor) {
      return { ok: false, reason: "overlapping executable replacements" };
    }
    command += params.source.slice(cursor, replacement.startIndex);
    command += replacement.text;
    cursor = replacement.endIndex;
  }
  command += params.source.slice(cursor);
  return { ok: true, command };
}

function renderSourcePreservingPlan(params: {
  plan: Extract<ExecAuthorizationPlan, { ok: true }>;
  mode: AuthorizedShellRenderMode;
  segmentSatisfiedBy: readonly ExecSegmentSatisfiedBy[];
  forceRewriteSegments: readonly boolean[];
}): AuthorizedShellRenderResult {
  const candidateCount = params.plan.groups.reduce(
    (count, group) => count + group.candidates.length,
    0,
  );
  if (params.segmentSatisfiedBy.length > 0 && params.segmentSatisfiedBy.length !== candidateCount) {
    return { ok: false, reason: "segment metadata mismatch" };
  }
  if (
    params.forceRewriteSegments.length > 0 &&
    params.forceRewriteSegments.length !== candidateCount
  ) {
    return { ok: false, reason: "segment metadata mismatch" };
  }
  const replacements: SourceReplacement[] = [];
  let candidateIndex = 0;
  for (const group of params.plan.groups) {
    for (const candidate of group.candidates) {
      const replacement = sourceReplacementForCandidate({
        candidate,
        mode: params.mode,
        satisfiedBy: params.segmentSatisfiedBy[candidateIndex],
        forceRewrite: params.forceRewriteSegments[candidateIndex],
        sourceLength: params.plan.originalCommand.length,
      });
      if (replacement && "ok" in replacement) {
        return replacement;
      }
      if (replacement) {
        replacements.push(replacement);
      }
      candidateIndex += 1;
    }
  }
  return applySourceReplacements({
    source: params.plan.originalCommand,
    replacements,
  });
}

function candidatesHaveInlinePayloadSpans(params: {
  wrapper: Extract<ExecAuthorizationCandidate["transport"], { kind: "shell-wrapper" }>;
  candidates: readonly ExecAuthorizationCandidate[];
  sourceOffset: number;
}): boolean {
  return params.candidates.every(
    (candidate) =>
      candidate.sourceStep.span.startIndex >= params.sourceOffset &&
      candidate.sourceStep.span.endIndex - params.sourceOffset <=
        params.wrapper.inlineCommand.length &&
      candidate.sourceStep.executableSpan.startIndex >= params.sourceOffset &&
      candidate.sourceStep.executableSpan.endIndex - params.sourceOffset <=
        params.wrapper.inlineCommand.length,
  );
}

function resolveWrapperPayloadSourceOffset(params: {
  plan: Extract<ExecAuthorizationPlan, { ok: true }>;
  wrapper: Extract<ExecAuthorizationCandidate["transport"], { kind: "shell-wrapper" }>;
  candidates: readonly ExecAuthorizationCandidate[];
}): number | null {
  const directOffset = params.plan.originalCommand.indexOf(params.wrapper.inlineCommand);
  if (directOffset >= 0) {
    return directOffset;
  }
  for (const candidate of params.candidates) {
    const inlineStepOffset = params.wrapper.inlineCommand.indexOf(candidate.sourceSegment.raw);
    if (inlineStepOffset >= 0) {
      return candidate.sourceStep.span.startIndex - inlineStepOffset;
    }
  }
  return null;
}

function renderShellWrapperPayloadSourcePreservingPlan(params: {
  plan: Extract<ExecAuthorizationPlan, { ok: true }>;
  wrapper: Extract<ExecAuthorizationCandidate["transport"], { kind: "shell-wrapper" }>;
  mode: AuthorizedShellRenderMode;
  segmentSatisfiedBy: readonly ExecSegmentSatisfiedBy[];
  forceRewriteSegments: readonly boolean[];
  sourceOffset: number;
}): AuthorizedShellRenderResult {
  const candidateCount = params.plan.groups.reduce(
    (count, group) => count + group.candidates.length,
    0,
  );
  if (params.segmentSatisfiedBy.length > 0 && params.segmentSatisfiedBy.length !== candidateCount) {
    return { ok: false, reason: "segment metadata mismatch" };
  }
  if (
    params.forceRewriteSegments.length > 0 &&
    params.forceRewriteSegments.length !== candidateCount
  ) {
    return { ok: false, reason: "segment metadata mismatch" };
  }
  const replacements: SourceReplacement[] = [];
  let candidateIndex = 0;
  for (const group of params.plan.groups) {
    for (const candidate of group.candidates) {
      const replacement = sourceReplacementForCandidate({
        candidate,
        mode: params.mode,
        satisfiedBy: params.segmentSatisfiedBy[candidateIndex],
        forceRewrite: params.forceRewriteSegments[candidateIndex],
        sourceLength: params.wrapper.inlineCommand.length,
        sourceOffset: params.sourceOffset,
      });
      if (replacement && "ok" in replacement) {
        return replacement;
      }
      if (replacement) {
        replacements.push(replacement);
      }
      candidateIndex += 1;
    }
  }
  return applySourceReplacements({
    source: params.wrapper.inlineCommand,
    replacements,
  });
}

function commonShellWrapper(
  candidates: readonly ExecAuthorizationCandidate[],
): Extract<ExecAuthorizationCandidate["transport"], { kind: "shell-wrapper" }> | null {
  const wrappers = candidates.map((candidate) => candidate.transport);
  const first = wrappers[0];
  if (!first || first.kind !== "shell-wrapper") {
    return null;
  }
  return wrappers.every(
    (transport) =>
      transport.kind === "shell-wrapper" && transport.wrapperSegment === first.wrapperSegment,
  )
    ? first
    : null;
}

function renderShellWrapperCommand(params: {
  wrapper: Extract<ExecAuthorizationCandidate["transport"], { kind: "shell-wrapper" }>;
  payload: string;
}): AuthorizedShellRenderResult {
  const match = resolveInlineCommandMatch(params.wrapper.wrapperArgv, POSIX_INLINE_COMMAND_FLAGS, {
    allowCombinedC: true,
  });
  if (match.valueTokenIndex === null) {
    return { ok: false, reason: "wrapper inline command unavailable" };
  }
  const argv = [...params.wrapper.wrapperArgv];
  const valueToken = argv[match.valueTokenIndex];
  if (valueToken && match.command && valueToken !== match.command) {
    const flag = valueToken.endsWith(match.command)
      ? valueToken.slice(0, valueToken.length - match.command.length)
      : "";
    if (flag.length > 0) {
      argv.splice(match.valueTokenIndex, 1, flag, params.payload);
      return { ok: true, command: `${params.wrapper.wrapperPrefix}${renderQuotedArgv(argv)}` };
    }
  }
  argv[match.valueTokenIndex] = params.payload;
  return { ok: true, command: `${params.wrapper.wrapperPrefix}${renderQuotedArgv(argv)}` };
}

export function buildAuthorizedShellCommandFromPlan(params: {
  plan: ExecAuthorizationPlan;
  mode: AuthorizedShellRenderMode;
  segmentSatisfiedBy?: readonly ExecSegmentSatisfiedBy[];
  forceRewriteSegments?: readonly boolean[];
}): AuthorizedShellRenderResult {
  if (!params.plan.ok) {
    return { ok: false, reason: params.plan.reason };
  }
  if (params.plan.dialect !== "posix-shell" && params.plan.dialect !== "argv") {
    return { ok: false, reason: "unsupported command dialect" };
  }
  const segmentSatisfiedBy = params.segmentSatisfiedBy ?? [];
  const forceRewriteSegments = params.forceRewriteSegments ?? [];
  const candidates = params.plan.groups.flatMap((group) => group.candidates);
  const wrapper = commonShellWrapper(candidates);
  if (params.plan.dialect === "posix-shell") {
    const renderThroughWrapper =
      wrapper !== null &&
      (params.mode === "enforced" ||
        params.mode === "executable" ||
        forceRewriteSegments.some(Boolean) ||
        segmentSatisfiedBy.some((entry) => entry === "safeBins" || entry === "inlineChain"));
    if (renderThroughWrapper) {
      const payloadSourceOffset = resolveWrapperPayloadSourceOffset({
        plan: params.plan,
        wrapper,
        candidates,
      });
      const rendered =
        payloadSourceOffset !== null &&
        candidatesHaveInlinePayloadSpans({ wrapper, candidates, sourceOffset: payloadSourceOffset })
          ? renderShellWrapperPayloadSourcePreservingPlan({
              plan: params.plan,
              wrapper,
              mode: params.mode,
              segmentSatisfiedBy,
              forceRewriteSegments,
              sourceOffset: payloadSourceOffset,
            })
          : renderPlanGroups({
              plan: params.plan,
              mode: params.mode,
              segmentSatisfiedBy,
              forceRewrite:
                params.mode === "enforced" ||
                forceRewriteSegments.some(Boolean) ||
                segmentSatisfiedBy.some((entry) => entry === "inlineChain"),
            });
      if (!rendered.ok) {
        return rendered;
      }
      return renderShellWrapperCommand({ wrapper, payload: rendered.command });
    }
    return renderSourcePreservingPlan({
      plan: params.plan,
      mode: params.mode,
      segmentSatisfiedBy,
      forceRewriteSegments,
    });
  }
  const forceRewrite =
    params.mode === "enforced" ||
    forceRewriteSegments.some(Boolean) ||
    (wrapper !== null && segmentSatisfiedBy.some((entry) => entry === "inlineChain"));
  const rendered = renderPlanGroups({
    plan: params.plan,
    mode: params.mode,
    segmentSatisfiedBy,
    forceRewrite,
  });
  if (!rendered.ok || !wrapper) {
    return rendered;
  }
  return renderShellWrapperCommand({ wrapper, payload: rendered.command });
}
