import type { Finding, RemediationPlan, RemediationPlanInput } from "./schemas.js";

function exampleFor(finding: Finding, targetFormat?: string) {
  if (finding.item_id === "quick-wins/non-root-containers") {
    return [
      "spec:",
      "  template:",
      "    spec:",
      "      securityContext:",
      "        runAsNonRoot: true",
      "        runAsUser: 1000",
      "      containers:",
      "        - name: app",
      "          securityContext:",
      "            readOnlyRootFilesystem: true",
    ].join("\n");
  }
  if (finding.item_id === "quick-wins/default-service-account") {
    return [
      "spec:",
      "  template:",
      "    spec:",
      "      serviceAccountName: app",
      "      automountServiceAccountToken: false",
    ].join("\n");
  }
  if (finding.item_id.includes("networkpolicy")) {
    return [
      "apiVersion: networking.k8s.io/v1",
      "kind: NetworkPolicy",
      "metadata:",
      "  name: default-deny",
      "spec:",
      "  podSelector: {}",
      "  policyTypes:",
      "    - Ingress",
      "    - Egress",
    ].join("\n");
  }
  if (targetFormat === "terraform") {
    return "# Add the corresponding Terraform resource/configuration and run terraform plan for review only.";
  }
  return "# Add the smallest Kubernetes or IaC change that satisfies this control; review before applying.";
}

export function generateRemediationPlan(input: RemediationPlanInput): RemediationPlan {
  const actionable = input.findings.filter((finding) => finding.status === "fail" || finding.status === "warn" || finding.status === "unavailable");
  const changes = actionable.map((finding) => ({
    item_id: finding.item_id,
    priority: finding.priority,
    target: finding.evidence[0]?.split(":")[0] ?? "repository or cluster configuration",
    action: finding.recommendation,
    example: exampleFor(finding, input.targetFormat),
  }));
  return {
    summary: `${changes.length}개 항목에 대한 read-only 개선 계획입니다. 실제 파일이나 클러스터 리소스는 수정하지 않습니다.`,
    changes,
    examples: changes.map((change) => `# ${change.item_id}\n${change.example}`),
    verification: [...new Set(actionable.flatMap((finding) => finding.verify_commands))],
    non_goals: [
      "Do not run kubectl apply, kubectl delete, helm upgrade, terraform apply, or aws update commands.",
      "Do not write files automatically; use this as a patch plan for human or agent review.",
    ],
  };
}
