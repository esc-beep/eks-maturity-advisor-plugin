import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { CatalogInfo } from "./schemas.js";

export interface CatalogItem {
  item_id: string;
  phase: string;
  domain: string;
  title?: string;
  difficulty?: string;
  href?: string;
  checks?: string[];
  verify_commands?: string[];
  source_reference?: string;
}

export interface Catalog {
  catalog_version: string;
  snapshot_date: string;
  generated_from?: string[];
  items: CatalogItem[];
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../../..");
const catalogPath = path.join(repoRoot, "references/catalog.json");

let memoizedCatalog: Catalog | null = null;

export function loadCatalog(): Catalog {
  if (memoizedCatalog) return memoizedCatalog;
  const parsed = JSON.parse(readFileSync(catalogPath, "utf8")) as Partial<Catalog>;
  memoizedCatalog = {
    catalog_version: parsed.catalog_version ?? "snapshot-v1",
    snapshot_date: parsed.snapshot_date ?? "2026-07-08",
    generated_from: parsed.generated_from ?? [],
    items: parsed.items ?? [],
  };
  return memoizedCatalog;
}

export function getCatalogInfo(): CatalogInfo {
  const catalog = loadCatalog();
  return {
    scanner: "eks-maturity-advisor",
    catalog_version: catalog.catalog_version,
    snapshot_date: catalog.snapshot_date,
    control_count: catalog.items.length,
    phases: [...new Set(catalog.items.map((item) => item.phase))].sort(),
  };
}

export function listControls(input: { phase?: string; domain?: string; itemId?: string; query?: string; limit?: number } = {}) {
  const catalog = loadCatalog();
  const query = input.query?.toLowerCase();
  const controls = catalog.items.filter((item) => {
    if (input.phase && item.phase !== input.phase) return false;
    if (input.domain && item.domain !== input.domain) return false;
    if (input.itemId && item.item_id !== input.itemId) return false;
    if (query) {
      const haystack = [item.item_id, item.phase, item.domain, item.title, item.difficulty, ...(item.checks ?? [])].join(" ").toLowerCase();
      if (!haystack.includes(query)) return false;
    }
    return true;
  });

  return {
    scanner: "eks-maturity-advisor",
    catalog_version: catalog.catalog_version,
    snapshot_date: catalog.snapshot_date,
    controls: controls.slice(0, input.limit ?? 25),
  };
}

export function metadataFor(itemId: string): Pick<CatalogItem, "phase" | "domain" | "source_reference"> {
  const item = loadCatalog().items.find((entry) => entry.item_id === itemId);
  return {
    phase: item?.phase ?? "Unknown",
    domain: item?.domain ?? "미분류",
    source_reference: item?.source_reference ?? `references/catalog.json#${itemId}`,
  };
}
