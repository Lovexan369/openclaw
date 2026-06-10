// Check Codex App Server Protocol script supports OpenClaw repository automation.
import fs from "node:fs/promises";
import path from "node:path";
import {
  generateExperimentalCodexAppServerProtocolSource,
  normalizeCodexAppServerProtocolJsonText,
  selectedCodexAppServerJsonSchemas,
} from "./lib/codex-app-server-protocol-source.js";

const generatedRoot = path.resolve(
  process.cwd(),
  "extensions/codex/src/app-server/protocol-generated",
);

const checks: Array<{ file: string; snippets: string[] }> = [
  {
    file: "ServerRequest.ts",
    snippets: [
      '"item/commandExecution/requestApproval"',
      '"item/fileChange/requestApproval"',
      '"item/permissions/requestApproval"',
      '"item/tool/call"',
    ],
  },
  {
    file: "v2/ThreadItem.ts",
    snippets: [
      'type: "contextCompaction"',
      'type: "dynamicToolCall"',
      'type: "commandExecution"',
      'type: "mcpToolCall"',
    ],
  },
  {
    file: "v2/DynamicToolSpec.ts",
    snippets: ["name: string", "description: string", "inputSchema: JsonValue"],
  },
  {
    file: "v2/CommandExecutionApprovalDecision.ts",
    snippets: ['"accept"', '"acceptForSession"', '"decline"', '"cancel"'],
  },
  {
    file: "v2/Account.ts",
    snippets: ['type: "apiKey"', 'type: "chatgpt"', 'type: "amazonBedrock"'],
  },
  {
    file: "v2/ThreadStartParams.ts",
    snippets: [
      "permissions?: string | null",
      "dynamicTools?: Array<DynamicToolSpec> | null",
      "experimentalRawEvents",
    ],
  },
  {
    file: "v2/TurnStartParams.ts",
    snippets: ["permissions?: string | null", "serviceTier?: string | null"],
  },
  {
    file: "ReviewDecision.ts",
    snippets: ['"approved"', '"approved_for_session"', '"denied"', '"abort"'],
  },
  {
    file: "v2/PlanDeltaNotification.ts",
    snippets: ["itemId: string", "delta: string"],
  },
  {
    file: "v2/TurnPlanUpdatedNotification.ts",
    snippets: ["explanation: string | null", "plan: Array<TurnPlanStep>"],
  },
];

const failures: string[] = [];
await main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});

async function main(): Promise<void> {
  const source = await generateExperimentalCodexAppServerProtocolSource();

  try {
    await compareGeneratedProtocolMirror(source.jsonRoot);
    await compareGeneratedTypeScriptMirror(source.typescriptRoot);

    for (const check of checks) {
      const filePath = path.join(source.typescriptRoot, check.file);
      let text: string;
      try {
        text = await fs.readFile(filePath, "utf8");
      } catch (error) {
        failures.push(`${check.file}: missing (${String(error)})`);
        continue;
      }
      for (const snippet of check.snippets) {
        if (!text.includes(snippet)) {
          failures.push(`${check.file}: missing ${snippet}`);
        }
      }
    }
  } finally {
    await source.cleanup();
  }

  if (failures.length > 0) {
    console.error("Codex app-server generated protocol drift:");
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    console.error(
      `Run \`pnpm codex-app-server:protocol:sync\` after refreshing the Codex checkout at ${source.codexRepo}.`,
    );
    process.exit(1);
  }

  console.log(
    `Codex app-server generated protocol matches OpenClaw bridge assumptions: ${source.codexRepo}`,
  );
}

async function compareGeneratedTypeScriptMirror(sourceRoot: string): Promise<void> {
  const targetRoot = path.join(generatedRoot, "typescript");
  const sourceFiles = await listRelativeFiles(sourceRoot);
  const targetFiles = await listRelativeFiles(targetRoot).catch((error: unknown) => {
    failures.push(`protocol-generated/typescript: missing local mirror (${String(error)})`);
    return [];
  });
  const sourceFileSet = new Set(sourceFiles);
  const targetFileSet = new Set(targetFiles);

  for (const file of sourceFiles) {
    if (!targetFileSet.has(file)) {
      failures.push(`protocol-generated/typescript/${file}: missing local generated type`);
      continue;
    }
    const [source, target] = await Promise.all([
      fs.readFile(path.join(sourceRoot, file), "utf8"),
      fs.readFile(path.join(targetRoot, file), "utf8"),
    ]);
    if (source !== target) {
      failures.push(`protocol-generated/typescript/${file}: differs from generated source`);
    }
  }

  for (const file of targetFiles) {
    if (!sourceFileSet.has(file)) {
      failures.push(`protocol-generated/typescript/${file}: stale local generated type`);
    }
  }
}

async function listRelativeFiles(root: string): Promise<string[]> {
  const entries = await fs.readdir(root, { recursive: true, withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile())
    .map((entry) => path.relative(root, path.join(entry.parentPath, entry.name)))
    .toSorted();
}

async function compareGeneratedProtocolMirror(sourceJsonRoot: string): Promise<void> {
  for (const schema of selectedCodexAppServerJsonSchemas) {
    const sourcePath = path.join(sourceJsonRoot, schema);
    const targetPath = path.join(generatedRoot, "json", schema);
    let sourceValue: string;
    let target: string;
    try {
      sourceValue = await fs.readFile(sourcePath, "utf8");
    } catch (error) {
      failures.push(
        `protocol-generated/json/${schema}: missing upstream schema (${String(error)})`,
      );
      continue;
    }
    try {
      target = await fs.readFile(targetPath, "utf8");
    } catch (error) {
      failures.push(`protocol-generated/json/${schema}: missing local schema (${String(error)})`);
      continue;
    }
    if (normalizeJsonSchema(sourceValue) !== normalizeJsonSchema(target)) {
      failures.push(`protocol-generated/json/${schema}: differs from source schema`);
    }
  }
}

function normalizeJsonSchema(sourceLocal: string): string {
  return normalizeCodexAppServerProtocolJsonText(sourceLocal);
}
