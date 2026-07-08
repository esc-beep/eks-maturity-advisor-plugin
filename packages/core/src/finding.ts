import { getCatalogInfo, metadataFor } from "./catalog.js";
import type { Finding, FindingStatus } from "./schemas.js";

const priorityOrder = new Map([
  ["P1", 0],
  ["P2", 1],
  ["P3", 2],
]);
const statusOrder = new Map([
  ["fail", 0],
  ["warn", 1],
  ["unavailable", 2],
  ["unknown", 3],
  ["pass", 4],
]);

export function priorityFor(status: FindingStatus, severity: Finding["severity"]): Finding["priority"] {
  if (status === "fail" && (severity === "critical" || severity === "high")) return "P1";
  if (status === "fail" && severity === "medium") return "P2";
  if (status === "warn" && (severity === "high" || severity === "medium")) return "P2";
  if (status === "unavailable") return "P2";
  return "P3";
}

export function makeFinding(
  item_id: string,
  status: FindingStatus,
  severity: Finding["severity"],
  evidence: string[],
  recommendation: string,
  verify_commands: string[] = [],
): Finding {
  const metadata = metadataFor(item_id);
  return {
    item_id,
    phase: metadata.phase ?? "Unknown",
    domain: metadata.domain ?? "미분류",
    status,
    severity,
    priority: priorityFor(status, severity),
    evidence,
    recommendation,
    verify_commands,
    catalog_version: getCatalogInfo().catalog_version,
    source_reference: metadata.source_reference ?? `references/catalog.json#${item_id}`,
  };
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const priority = (priorityOrder.get(a.priority) ?? 99) - (priorityOrder.get(b.priority) ?? 99);
    if (priority !== 0) return priority;
    const status = (statusOrder.get(a.status) ?? 99) - (statusOrder.get(b.status) ?? 99);
    if (status !== 0) return status;
    return a.item_id.localeCompare(b.item_id);
  });
}
