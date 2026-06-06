/**
 * Resolves provider auth from static env vars and local auth evidence only.
 */
import fs from "node:fs";
import os from "node:os";
import { normalizeProviderIdForAuth } from "@openclaw/model-catalog-core/provider-id";
import { normalizeOptionalString as normalizeOptionalPathInput } from "@openclaw/normalization-core/string-coerce";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { getShellEnvAppliedKeys } from "../infra/shell-env.js";
import type { ProviderAuthEvidence } from "../secrets/provider-env-vars.js";
import { normalizeOptionalSecretInput } from "../utils/normalize-secret-input.js";
import { resolveProviderEnvAuthLookupMaps } from "./model-auth-env-vars.js";

export type EnvApiKeyResult = {
  apiKey: string;
  source: string;
};

export type EnvApiKeyLookupOptions = {
  config?: OpenClawConfig;
  workspaceDir?: string;
  aliasMap?: Readonly<Record<string, string>>;
  candidateMap?: Readonly<Record<string, readonly string[]>>;
  authEvidenceMap?: Readonly<Record<string, readonly ProviderAuthEvidence[]>>;
  skipSetupProviderFallback?: boolean;
};

export type StaticEnvApiKeyResolution = {
  result: EnvApiKeyResult | null;
  normalizedProvider: string;
  hasEnvCandidates: boolean;
};

function expandAuthEvidencePath(rawPath: string, env: NodeJS.ProcessEnv): string | undefined {
  const trimmed = rawPath.trim();
  if (!trimmed) {
    return undefined;
  }
  const homeDir = normalizeOptionalPathInput(env.HOME) ?? os.homedir();
  const appDataDir = normalizeOptionalPathInput(env.APPDATA);
  if (trimmed.includes("${APPDATA}") && !appDataDir) {
    return undefined;
  }
  return trimmed.replaceAll("${HOME}", homeDir).replaceAll("${APPDATA}", appDataDir ?? "");
}

function hasRequiredAuthEvidenceEnv(
  evidence: ProviderAuthEvidence,
  env: NodeJS.ProcessEnv,
): boolean {
  const hasEnv = (key: string) => Boolean(normalizeOptionalSecretInput(env[key]));
  if (evidence.requiresAnyEnv?.length && !evidence.requiresAnyEnv.some(hasEnv)) {
    return false;
  }
  if (evidence.requiresAllEnv?.length && !evidence.requiresAllEnv.every(hasEnv)) {
    return false;
  }
  return true;
}

function hasLocalFileAuthEvidence(evidence: ProviderAuthEvidence, env: NodeJS.ProcessEnv): boolean {
  if (evidence.fileEnvVar) {
    const explicitPath = normalizeOptionalPathInput(env[evidence.fileEnvVar]);
    if (explicitPath) {
      return fs.existsSync(explicitPath);
    }
  }
  for (const rawPath of evidence.fallbackPaths ?? []) {
    const expandedPath = expandAuthEvidencePath(rawPath, env);
    if (expandedPath && fs.existsSync(expandedPath)) {
      return true;
    }
  }
  return false;
}

function resolveAuthEvidence(
  evidence: readonly ProviderAuthEvidence[] | undefined,
  env: NodeJS.ProcessEnv,
): EnvApiKeyResult | null {
  for (const entry of evidence ?? []) {
    if (entry.type !== "local-file-with-env") {
      continue;
    }
    if (!hasRequiredAuthEvidenceEnv(entry, env) || !hasLocalFileAuthEvidence(entry, env)) {
      continue;
    }
    return {
      apiKey: entry.credentialMarker,
      source: entry.source ?? "local auth evidence",
    };
  }
  return null;
}

export function resolveStaticEnvApiKey(
  provider: string,
  env: NodeJS.ProcessEnv = process.env,
  options: EnvApiKeyLookupOptions = {},
): StaticEnvApiKeyResolution {
  const normalizedProvider = normalizeProviderIdForAuth(provider);
  const lookupParams = {
    config: options.config,
    workspaceDir: options.workspaceDir,
    env,
  };
  const lookupMaps =
    !options.aliasMap || !options.candidateMap || !options.authEvidenceMap
      ? resolveProviderEnvAuthLookupMaps(lookupParams)
      : undefined;
  const aliasMap = options.aliasMap ?? lookupMaps?.aliasMap ?? {};
  const normalized = aliasMap[normalizedProvider] ?? normalizedProvider;
  const candidateMap = options.candidateMap ?? lookupMaps?.envCandidateMap ?? {};
  const authEvidenceMap = options.authEvidenceMap ?? lookupMaps?.authEvidenceMap ?? {};
  const applied = new Set(getShellEnvAppliedKeys());
  const pick = (envVar: string): EnvApiKeyResult | null => {
    const value = normalizeOptionalSecretInput(env[envVar]);
    if (!value) {
      return null;
    }
    const source = applied.has(envVar) ? `shell env: ${envVar}` : `env: ${envVar}`;
    return { apiKey: value, source };
  };

  const candidates = Object.hasOwn(candidateMap, normalized) ? candidateMap[normalized] : undefined;
  if (Array.isArray(candidates)) {
    for (const envVar of candidates) {
      const resolved = pick(envVar);
      if (resolved) {
        return {
          result: resolved,
          normalizedProvider: normalized,
          hasEnvCandidates: true,
        };
      }
    }
  }

  const evidence = Object.hasOwn(authEvidenceMap, normalized)
    ? authEvidenceMap[normalized]
    : undefined;
  const authEvidence = resolveAuthEvidence(evidence, env);
  return {
    result: authEvidence,
    normalizedProvider: normalized,
    hasEnvCandidates: Array.isArray(candidates),
  };
}

/** Resolve an API key or auth-evidence marker without plugin setup fallback. */
export function resolveEnvApiKeyWithoutSetupFallback(
  provider: string,
  env: NodeJS.ProcessEnv = process.env,
  options: EnvApiKeyLookupOptions = {},
): EnvApiKeyResult | null {
  return resolveStaticEnvApiKey(provider, env, options).result;
}
