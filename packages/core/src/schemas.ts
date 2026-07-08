import { z } from "zod";

export const FindingStatusSchema = z.enum(["fail", "warn", "unavailable", "unknown", "pass"]);
export const PrioritySchema = z.enum(["P1", "P2", "P3"]);

export const FindingSchema = z.object({
  item_id: z.string(),
  phase: z.string(),
  domain: z.string(),
  status: FindingStatusSchema,
  severity: z.enum(["critical", "high", "medium", "low"]),
  priority: PrioritySchema,
  evidence: z.array(z.string()),
  recommendation: z.string(),
  verify_commands: z.array(z.string()),
  catalog_version: z.string(),
  source_reference: z.string(),
});

export const ReportSchema = z.object({
  scanner: z.literal("eks-maturity-advisor"),
  mode: z.enum(["repo-only", "live-cluster"]),
  findings: z.array(FindingSchema),
}).passthrough();

export const CatalogInfoSchema = z.object({
  scanner: z.literal("eks-maturity-advisor"),
  catalog_version: z.string(),
  snapshot_date: z.string(),
  control_count: z.number(),
  phases: z.array(z.string()),
});

export const ListControlsInputSchema = z.object({
  phase: z.string().optional(),
  domain: z.string().optional(),
  itemId: z.string().optional(),
  query: z.string().optional(),
  limit: z.number().int().positive().max(100).optional(),
});

export const ScanRepositoryInputSchema = z.object({
  repoRoot: z.string().min(1),
});

export const ScanLiveClusterInputSchema = z.object({}).strict();

export const RemediationPlanInputSchema = z.object({
  findings: z.array(FindingSchema),
  targetFormat: z.enum(["kubernetes", "terraform", "helm", "mixed"]).optional(),
});

export const RemediationPlanSchema = z.object({
  summary: z.string(),
  changes: z.array(z.object({
    item_id: z.string(),
    priority: PrioritySchema,
    target: z.string(),
    action: z.string(),
    example: z.string(),
  })),
  examples: z.array(z.string()),
  verification: z.array(z.string()),
  non_goals: z.array(z.string()),
});

export type FindingStatus = z.infer<typeof FindingStatusSchema>;
export type Priority = z.infer<typeof PrioritySchema>;
export type Finding = z.infer<typeof FindingSchema>;
export type Report = z.infer<typeof ReportSchema>;
export type CatalogInfo = z.infer<typeof CatalogInfoSchema>;
export type RemediationPlan = z.infer<typeof RemediationPlanSchema>;
export type ListControlsInput = z.infer<typeof ListControlsInputSchema>;
export type ScanRepositoryInput = z.infer<typeof ScanRepositoryInputSchema>;
export type ScanLiveClusterInput = z.infer<typeof ScanLiveClusterInputSchema>;
export type RemediationPlanInput = z.infer<typeof RemediationPlanInputSchema>;
