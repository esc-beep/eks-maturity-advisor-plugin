#!/usr/bin/env node
import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getCatalogInfo, listControls } from "./catalog.js";
import { generateRemediationPlan } from "./remediation.js";
import { scanLiveCluster } from "./liveScanner.js";
import { scanRepository } from "./repositoryScanner.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../../..");

function valueAfter(args: string[], flag: string) {
  const index = args.indexOf(flag);
  return index === -1 ? null : args[index + 1];
}

function printJson(value: unknown) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function catalogImport(args: string[]) {
  const source = valueAfter(args, "--source");
  if (!source) throw new Error("catalog-import requires --source <EKS-Maturity-Model path>");
  const sourceSkill = path.resolve(source, "skills/eks-maturity-advisor/references");
  const destination = path.join(repoRoot, "references");
  if (!existsSync(path.join(sourceSkill, "catalog.json"))) throw new Error(`catalog.json not found under ${sourceSkill}`);
  mkdirSync(destination, { recursive: true });
  copyFileSync(path.join(sourceSkill, "catalog.json"), path.join(destination, "catalog.json"));
  copyFileSync(path.join(sourceSkill, "quick-wins-v1.md"), path.join(destination, "quick-wins-v1.md"));
  printJson({ ok: true, destination });
}

export function main(argv = process.argv.slice(2)) {
  const command = argv[0] ?? "help";
  if (command === "scan-repo") {
    printJson(scanRepository({ repoRoot: valueAfter(argv, "--repo-root") ?? process.cwd(), cwd: process.cwd() }));
    return;
  }
  if (command === "scan-live") {
    printJson(scanLiveCluster());
    return;
  }
  if (command === "catalog-info") {
    printJson(getCatalogInfo());
    return;
  }
  if (command === "list-controls") {
    printJson(listControls({ query: valueAfter(argv, "--query") ?? undefined }));
    return;
  }
  if (command === "remediation") {
    const json = valueAfter(argv, "--findings-json");
    if (!json) throw new Error("remediation requires --findings-json '<json>'");
    printJson(generateRemediationPlan({ findings: JSON.parse(json) }));
    return;
  }
  if (command === "catalog-import") {
    catalogImport(argv);
    return;
  }
  process.stdout.write("Usage: scan-repo --repo-root <dir> | scan-live | catalog-info | list-controls | remediation | catalog-import --source <dir>\n");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${(error as Error).message}\n`);
    process.exitCode = 1;
  }
}
