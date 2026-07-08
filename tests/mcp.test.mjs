import assert from "node:assert/strict";
import test from "node:test";

test("MCP tool handlers preserve core scanner results and expose schemas", async () => {
  const { toolDefinitions, handleToolCall } = await import("../packages/mcp-server/dist/server.js");
  const names = toolDefinitions.map((tool) => tool.name);

  assert.deepEqual(names.sort(), [
    "eks_generate_remediation_plan",
    "eks_get_catalog_info",
    "eks_list_controls",
    "eks_scan_live_cluster",
    "eks_scan_repository",
  ].sort());
  assert.ok(toolDefinitions.every((tool) => tool.inputSchema?.type === "object"));

  const result = await handleToolCall("eks_get_catalog_info", {});
  assert.equal(result.scanner, "eks-maturity-advisor");
  assert.ok(result.control_count > 0);

  await Promise.all([
    handleToolCall("eks_list_controls", { limit: 2 }),
    handleToolCall("eks_list_controls", { query: "network", limit: 2 }),
  ]);
});
