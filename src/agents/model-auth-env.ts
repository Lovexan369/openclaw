/**
 * Resolves model provider API keys from explicit environment variables.
 */
import { resolvePluginSetupProvider } from "../plugins/setup-registry.js";
import {
  resolveStaticEnvApiKey,
  type EnvApiKeyLookupOptions,
  type EnvApiKeyResult,
} from "./model-auth-env-core.js";
import { GCP_VERTEX_CREDENTIALS_MARKER } from "./model-auth-markers.js";

export type { EnvApiKeyLookupOptions, EnvApiKeyResult } from "./model-auth-env-core.js";

/** Resolve an API key or auth-evidence marker for a provider from environment state. */
export function resolveEnvApiKey(
  provider: string,
  env: NodeJS.ProcessEnv = process.env,
  options: EnvApiKeyLookupOptions = {},
): EnvApiKeyResult | null {
  const staticResolution = resolveStaticEnvApiKey(provider, env, options);
  if (staticResolution.result) {
    return staticResolution.result;
  }
  if (staticResolution.hasEnvCandidates) {
    return null;
  }
  if (options.skipSetupProviderFallback === true) {
    return null;
  }

  const setupProvider = resolvePluginSetupProvider({
    provider: staticResolution.normalizedProvider,
    config: options.config,
    workspaceDir: options.workspaceDir,
    env,
  });
  if (setupProvider?.resolveConfigApiKey) {
    const resolved = setupProvider.resolveConfigApiKey({
      provider: staticResolution.normalizedProvider,
      env,
    });
    if (resolved?.trim()) {
      return {
        apiKey: resolved,
        source: resolved === GCP_VERTEX_CREDENTIALS_MARKER ? "gcloud adc" : "env",
      };
    }
  }

  return null;
}
