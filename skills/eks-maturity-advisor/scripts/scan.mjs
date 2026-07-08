#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pluginRoot = path.resolve(__dirname, "../../..");
const cliPath = path.join(pluginRoot, "packages/core/dist/cli.js");

if (!existsSync(cliPath)) {
  process.stderr.write("Core CLI is not built. Run `npm run build` from the plugin root first.\n");
  process.exit(1);
}

const result = spawnSync(process.execPath, [cliPath, ...process.argv.slice(2)], {
  cwd: pluginRoot,
  stdio: "inherit",
});

process.exit(result.status ?? 1);
