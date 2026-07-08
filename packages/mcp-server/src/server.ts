#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import {
  generateRemediationPlan,
  getCatalogInfo,
  listControls,
  ListControlsInputSchema,
  RemediationPlanInputSchema,
  scanLiveCluster,
  ScanLiveClusterInputSchema,
  scanRepository,
  ScanRepositoryInputSchema,
} from "@k8rvis/eks-maturity-advisor-core";

const EmptyInputSchema = z.object({}).strict();

export const toolDefinitions = [
  {
    name: "eks_get_catalog_info",
    description: "Return the EKS maturity catalog snapshot metadata and control count.",
    inputSchema: zodToJsonSchema(EmptyInputSchema),
  },
  {
    name: "eks_list_controls",
    description: "List or search EKS maturity controls by phase, domain, item id, or query.",
    inputSchema: zodToJsonSchema(ListControlsInputSchema),
  },
  {
    name: "eks_scan_repository",
    description: "Read-only scan of a single local repository directory for EKS maturity findings.",
    inputSchema: zodToJsonSchema(ScanRepositoryInputSchema),
  },
  {
    name: "eks_scan_live_cluster",
    description: "Read-only scan of the current kubeconfig context using kubectl and AWS CLI describe/list/get calls.",
    inputSchema: zodToJsonSchema(ScanLiveClusterInputSchema),
  },
  {
    name: "eks_generate_remediation_plan",
    description: "Generate a read-only patch plan and examples from EKS maturity findings.",
    inputSchema: zodToJsonSchema(RemediationPlanInputSchema),
  },
];

export async function handleToolCall(name: string, args: unknown) {
  if (name === "eks_get_catalog_info") {
    EmptyInputSchema.parse(args ?? {});
    return getCatalogInfo();
  }
  if (name === "eks_list_controls") {
    return listControls(ListControlsInputSchema.parse(args ?? {}));
  }
  if (name === "eks_scan_repository") {
    const parsed = ScanRepositoryInputSchema.parse(args ?? {});
    return scanRepository({ repoRoot: parsed.repoRoot, cwd: process.cwd() });
  }
  if (name === "eks_scan_live_cluster") {
    ScanLiveClusterInputSchema.parse(args ?? {});
    return scanLiveCluster();
  }
  if (name === "eks_generate_remediation_plan") {
    return generateRemediationPlan(RemediationPlanInputSchema.parse(args ?? {}));
  }
  throw new Error(`Unknown tool: ${name}`);
}

export function createServer() {
  const server = new Server(
    {
      name: "eks-maturity-advisor",
      version: "0.1.0",
    },
    {
      capabilities: {
        tools: {},
      },
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: toolDefinitions }));
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const result = await handleToolCall(request.params.name, request.params.arguments ?? {});
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  });

  return server;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
