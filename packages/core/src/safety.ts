import { execFileSync } from "node:child_process";
import { existsSync, lstatSync, realpathSync, statSync } from "node:fs";
import path from "node:path";

const SHELL_META = /[;&|`$<>]/;
const SENSITIVE_PATH_SEGMENTS = new Set([".aws", ".kube", ".ssh", ".gnupg", ".docker"]);
const SECRET_NAME_PATTERN = /(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client-key-data)/i;
const MAX_BUFFER = 2 * 1024 * 1024;
const TIMEOUT_MS = 30_000;

export class ScannerCommandError extends Error {
  constructor(
    message: string,
    public readonly code: string,
  ) {
    super(message);
  }
}

function hasSensitiveSegment(inputPath: string): boolean {
  return inputPath.split(/[\\/]+/).some((segment) => SENSITIVE_PATH_SEGMENTS.has(segment));
}

export function validateScanPath({ cwd = process.cwd(), inputPath }: { cwd?: string; inputPath: string }): string {
  if (hasSensitiveSegment(inputPath)) {
    throw new Error(`Sensitive directory is not allowed for scanning: ${inputPath}`);
  }
  const base = realpathSync(cwd);
  const resolved = path.resolve(base, inputPath);

  if (!existsSync(resolved)) {
    throw new Error(`Scan path does not exist: ${inputPath}`);
  }
  const linkInfo = lstatSync(resolved);
  const real = realpathSync(resolved);
  if (!real.startsWith(`${base}${path.sep}`) && real !== base) {
    if (path.isAbsolute(inputPath)) throw new Error(`Scan path is outside the workspace: ${inputPath}`);
    if (linkInfo.isSymbolicLink()) throw new Error(`Scan path must not be a symlink root: ${inputPath}`);
    throw new Error(`Scan path resolves outside the workspace: ${inputPath}`);
  }
  if (linkInfo.isSymbolicLink()) {
    throw new Error(`Scan path must not be a symlink root: ${inputPath}`);
  }
  if (!statSync(real).isDirectory()) {
    throw new Error(`Scan path must be an existing directory: ${inputPath}`);
  }
  return real;
}

function rejectMeta(args: string[]) {
  for (const arg of args) {
    if (SHELL_META.test(arg)) throw new ScannerCommandError(`Command argument contains shell metacharacter: ${arg}`, "COMMAND_NOT_ALLOWED");
  }
}

export function assertAllowedCommand(command: string, args: string[]): void {
  rejectMeta(args);
  if (command === "kubectl") {
    const verb = args[0];
    if (verb === "config") {
      const action = args[1];
      if (action === "current-context") return;
      if (action === "view" && args.includes("--minify") && args.includes("-o") && args.includes("json")) return;
      throw new ScannerCommandError(`kubectl config command is not allowed: ${args.join(" ")}`, "COMMAND_NOT_ALLOWED");
    }
    if (verb !== "get") throw new ScannerCommandError(`kubectl verb is not allowed: ${verb}`, "COMMAND_NOT_ALLOWED");
    const resource = args[1] ?? "";
    if (/secrets?/i.test(resource)) throw new ScannerCommandError("kubectl secret reads are not allowed", "COMMAND_NOT_ALLOWED");
    const allowedResources = new Set([
      "pods",
      "networkpolicy",
      "networkpolicies",
      "namespaces",
      "storageclass",
      "storageclasses",
      "pvc",
      "pv",
      "roles,rolebindings",
      "clusterroles,clusterrolebindings",
      "deployments,statefulsets,daemonsets,jobs,cronjobs",
    ]);
    if (!allowedResources.has(resource)) throw new ScannerCommandError(`kubectl resource is not allowed: ${resource}`, "COMMAND_NOT_ALLOWED");
    if (!args.includes("-o") || !args.includes("json")) throw new ScannerCommandError("kubectl reads must request JSON output", "COMMAND_NOT_ALLOWED");
    return;
  }

  if (command === "aws") {
    const service = args[0] ?? "";
    const operation = args[1] ?? "";
    if (!["eks", "ec2", "inspector2"].includes(service)) {
      throw new ScannerCommandError(`aws service is not allowed: ${service}`, "COMMAND_NOT_ALLOWED");
    }
    if (!/^(describe|list|get)-/.test(operation)) {
      throw new ScannerCommandError(`aws operation is not allowed: ${operation}`, "COMMAND_NOT_ALLOWED");
    }
    return;
  }

  throw new ScannerCommandError(`Binary is not allowed: ${command}`, "COMMAND_NOT_ALLOWED");
}

export interface CommandRunner {
  (input: { command: string; args: string[] }): string;
}

export const defaultCommandRunner: CommandRunner = ({ command, args }) => {
  assertAllowedCommand(command, args);
  try {
    return execFileSync(command, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: TIMEOUT_MS,
      maxBuffer: MAX_BUFFER,
    });
  } catch (error) {
    const nodeError = error as NodeJS.ErrnoException;
    if (nodeError.code === "ENOENT") throw new ScannerCommandError(`${command} binary not found`, "BINARY_NOT_FOUND");
    if (String(nodeError.message).includes("maxBuffer")) throw new ScannerCommandError("Command output exceeded 2MB", "OUTPUT_TOO_LARGE");
    if (String(nodeError.message).includes("ETIMEDOUT") || (nodeError as { signal?: string }).signal === "SIGTERM") throw new ScannerCommandError("Command timed out", "COMMAND_TIMEOUT");
    throw new ScannerCommandError(nodeError.message, String(nodeError.code ?? "COMMAND_FAILED"));
  }
};

export function runReadOnlyCommand(commandRunner: CommandRunner, command: string, args: string[]): string {
  assertAllowedCommand(command, args);
  const output = commandRunner({ command, args });
  if (output.length > MAX_BUFFER) throw new ScannerCommandError("Command output exceeded 2MB", "OUTPUT_TOO_LARGE");
  return output;
}

export function sanitizeKubeConfig<T>(value: T): T {
  return sanitizeObject(value) as T;
}

export function sanitizeKubernetesObject<T>(value: T): T {
  return sanitizeObject(value) as T;
}

function sanitizeObject(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sanitizeObject);
  if (!value || typeof value !== "object") return value;
  const output: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) {
    if (SECRET_NAME_PATTERN.test(key) && typeof child === "string") {
      output[key] = "[REDACTED]";
      continue;
    }
    if (key === "value" && typeof child === "string") {
      output[key] = "[REDACTED]";
      continue;
    }
    output[key] = sanitizeObject(child);
  }
  return output;
}
