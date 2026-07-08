import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

const root = path.resolve(new URL("..", import.meta.url).pathname);

function writeFixture(filePath, content) {
  const lines = content.replace(/^\n/, "").split("\n");
  const indentation = Math.min(
    ...lines.filter((line) => line.trim()).map((line) => line.match(/^\s*/)[0].length),
  );
  writeFileSync(filePath, `${lines.map((line) => line.slice(indationSafe(indentation))).join("\n").trimEnd()}\n`, "utf8");
}

function indationSafe(value) {
  return Number.isFinite(value) ? value : 0;
}

function byItem(findings, itemId) {
  return findings.find((finding) => finding.item_id === itemId);
}

function successfulLiveRunner(calls = []) {
  return ({ command, args }) => {
    calls.push([command, ...args].join(" "));
    const commandLine = [command, ...args].join(" ");

    if (commandLine === "kubectl config current-context") {
      return "arn:aws:eks:ap-northeast-2:123456789012:cluster/secure\n";
    }
    if (commandLine === "kubectl config view --minify -o json") {
      return JSON.stringify({
        users: [{ user: { token: "super-secret-token", exec: { args: ["--region", "ap-northeast-2", "eks", "get-token", "--cluster-name", "secure", "--output", "json"] } } }],
      });
    }
    if (commandLine.includes("aws eks describe-cluster")) {
      return JSON.stringify({ cluster: { resourcesVpcConfig: { endpointPublicAccess: false, endpointPrivateAccess: true }, accessConfig: { authenticationMode: "API_AND_CONFIG_MAP" } } });
    }
    if (commandLine.includes("aws eks list-nodegroups")) {
      return JSON.stringify({ nodegroups: ["system"] });
    }
    if (commandLine.includes("aws eks describe-nodegroup")) {
      return JSON.stringify({ nodegroup: { subnets: ["subnet-a"] } });
    }
    if (commandLine.includes("aws ec2 describe-subnets")) {
      return JSON.stringify({ Subnets: [{ SubnetId: "subnet-a", MapPublicIpOnLaunch: false }] });
    }
    if (commandLine.includes("aws eks list-access-entries")) {
      return JSON.stringify({ accessEntries: ["arn:aws:iam::123456789012:role/platform-admin"] });
    }
    if (commandLine.includes("aws inspector2 list-filters")) {
      return JSON.stringify({ filters: [{ name: "triage" }] });
    }
    if (commandLine.includes("aws inspector2 list-findings")) {
      return JSON.stringify({ findings: [] });
    }
    if (commandLine.includes("aws ec2 get-ebs-encryption-by-default")) {
      return JSON.stringify({ EbsEncryptionByDefault: true });
    }
    if (commandLine.includes("aws ec2 describe-volumes")) {
      return JSON.stringify({ Volumes: [{ VolumeId: "vol-123", Encrypted: true }] });
    }
    if (commandLine.includes("kubectl get namespaces")) {
      return JSON.stringify({ items: [{ metadata: { name: "team-a", labels: { "pod-security.kubernetes.io/enforce": "baseline" } } }] });
    }
    if (commandLine.includes("kubectl get pods -A")) {
      return JSON.stringify({ items: [{ metadata: { namespace: "team-a", name: "api" }, status: { phase: "Running" }, spec: { containers: [{ name: "api", securityContext: { privileged: false } }] } }] });
    }
    if (commandLine.includes("kubectl get networkpolicy")) {
      return JSON.stringify({ items: [{ metadata: { namespace: "team-a", name: "default-deny" }, spec: { podSelector: {}, policyTypes: ["Ingress", "Egress"] } }] });
    }
    if (commandLine.includes("kubectl get storageclass")) {
      return JSON.stringify({ items: [{ metadata: { name: "encrypted-gp3" }, provisioner: "ebs.csi.aws.com", parameters: { encrypted: "true" } }] });
    }
    if (commandLine.includes("kubectl get pvc -A")) {
      return JSON.stringify({ items: [{ metadata: { namespace: "team-a", name: "db" }, spec: { storageClassName: "encrypted-gp3", volumeName: "pv-db" }, status: { phase: "Bound" } }] });
    }
    if (commandLine.includes("kubectl get pv")) {
      return JSON.stringify({ items: [{ metadata: { name: "pv-db" }, spec: { csi: { driver: "ebs.csi.aws.com", volumeHandle: "vol-123" } } }] });
    }
    if (commandLine.includes("kubectl get roles,rolebindings")) {
      return JSON.stringify({ items: [{ kind: "RoleBinding", metadata: { namespace: "team-a", name: "reader" } }] });
    }
    if (commandLine.includes("kubectl get clusterroles,clusterrolebindings")) {
      return JSON.stringify({ items: [] });
    }
    if (commandLine.includes("kubectl get deployments,statefulsets,daemonsets,jobs,cronjobs")) {
      return JSON.stringify({ items: [{ kind: "Deployment", metadata: { namespace: "team-a", name: "api" }, spec: { template: { spec: { containers: [{ name: "api", env: [{ name: "DB_PASSWORD", value: "plaintext" }] }] } } } }] });
    }

    throw new Error(`unexpected command: ${commandLine}`);
  };
}

test("repo scanner reports Quick Wins failures for insecure manifests", async () => {
  const { scanRepository } = await import("../packages/core/dist/index.js");
  const repoRoot = mkdtempSync(path.join(tmpdir(), "eks-insecure-"));
  writeFixture(path.join(repoRoot, "app.yaml"), `
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: api
      namespace: team-a
    spec:
      template:
        spec:
          serviceAccountName: default
          automountServiceAccountToken: true
          containers:
            - name: api
              image: example/api:latest
              env:
                - name: DB_PASSWORD
                  value: plaintext-password
              securityContext:
                runAsUser: 0
    ---
    apiVersion: networking.k8s.io/v1
    kind: Ingress
    metadata:
      name: api
      namespace: team-a
    spec:
      rules: []
  `);

  const report = scanRepository({ repoRoot, cwd: path.dirname(repoRoot) });

  assert.equal(byItem(report.findings, "quick-wins/non-root-containers").status, "fail");
  assert.equal(byItem(report.findings, "quick-wins/default-service-account").status, "fail");
  assert.equal(byItem(report.findings, "quick-wins/aws-secret-manager-사용").status, "fail");
});

test("repo scanner reports pass and unknown without failing on parse errors", async () => {
  const { scanRepository } = await import("../packages/core/dist/index.js");
  const repoRoot = mkdtempSync(path.join(tmpdir(), "eks-secure-"));
  writeFixture(path.join(repoRoot, "secure.yaml"), `
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: api
      namespace: team-a
    spec:
      template:
        spec:
          serviceAccountName: api
          automountServiceAccountToken: false
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
          containers:
            - name: api
              image: example/api:v1
              securityContext:
                runAsNonRoot: true
                runAsUser: 1000
    ---
    apiVersion: v1
    kind: ResourceQuota
    metadata:
      name: quota
      namespace: team-a
    spec: {}
    ---
    apiVersion: v1
    kind: LimitRange
    metadata:
      name: limits
      namespace: team-a
    spec: {}
  `);
  writeFileSync(path.join(repoRoot, "bad.yaml"), "apiVersion: [", "utf8");

  const report = scanRepository({ repoRoot, cwd: path.dirname(repoRoot) });

  assert.equal(byItem(report.findings, "quick-wins/non-root-containers").status, "pass");
  assert.equal(byItem(report.findings, "quick-wins/ingress-load-balancer-tls").status, "unknown");
  assert.ok(byItem(report.findings, "quick-wins/non-root-containers").catalog_version);
});

test("validateScanPath rejects symlink roots and sensitive directories", async () => {
  const { validateScanPath } = await import("../packages/core/dist/index.js");
  const workspace = mkdtempSync(path.join(tmpdir(), "eks-path-"));
  symlinkSync("/etc", path.join(workspace, "etc-link"));

  assert.throws(() => validateScanPath({ cwd: workspace, inputPath: "etc-link" }), /symlink/i);
  assert.throws(() => validateScanPath({ cwd: workspace, inputPath: "/etc" }), /outside/i);
  assert.throws(() => validateScanPath({ cwd: workspace, inputPath: ".aws" }), /sensitive/i);
});

test("live scanner uses current-context, redacts sensitive values, and returns unavailable for disabled services", async () => {
  const { scanLiveCluster } = await import("../packages/core/dist/index.js");
  const calls = [];
  const report = scanLiveCluster({ commandRunner: successfulLiveRunner(calls) });
  const serialized = JSON.stringify(report);

  assert.equal(report.mode, "live-cluster");
  assert.equal(report.kubectl_context, "arn:aws:eks:ap-northeast-2:123456789012:cluster/secure");
  assert.equal(byItem(report.findings, "foundational/private-api-endpoint").status, "pass");
  assert.equal(byItem(report.findings, "foundational/workload-내-hardcoded-secret-제거").status, "fail");
  assert.match(serialized, /\[REDACTED\]/);
  assert.doesNotMatch(serialized, /super-secret-token|plaintext/);
  assert.ok(calls.every((call) => !call.includes("--context")));
});

test("live scanner maps command failures and oversized output to unavailable findings", async () => {
  const { scanLiveCluster } = await import("../packages/core/dist/index.js");
  const report = scanLiveCluster({
    commandRunner: ({ command, args }) => {
      const line = [command, ...args].join(" ");
      if (line === "kubectl config current-context") return "current\n";
      if (line === "kubectl config view --minify -o json") return JSON.stringify({ users: [] });
      if (line.includes("aws inspector2")) throw Object.assign(new Error("Inspector is not enabled"), { code: "SERVICE_DISABLED" });
      return "x".repeat(2 * 1024 * 1024 + 1);
    },
  });

  assert.equal(byItem(report.findings, "foundational/container-image-취약점-관리").status, "unavailable");
  assert.ok(report.findings.some((finding) => finding.status === "unavailable"));
});

test("catalog info and remediation plan are structured", async () => {
  const { getCatalogInfo, generateRemediationPlan } = await import("../packages/core/dist/index.js");
  const info = getCatalogInfo();
  const plan = generateRemediationPlan({
    findings: [{
      item_id: "quick-wins/non-root-containers",
      phase: "Quick Wins",
      domain: "Pod 보안",
      status: "fail",
      severity: "high",
      priority: "P1",
      evidence: ["app.yaml: container runs as root"],
      recommendation: "Run as non-root.",
      verify_commands: ["kubectl get pods -A -o json"],
      catalog_version: info.catalog_version,
      source_reference: "references/catalog.json#quick-wins/non-root-containers",
    }],
  });

  assert.ok(info.control_count > 0);
  assert.ok(plan.changes.some((change) => change.item_id === "quick-wins/non-root-containers"));
  assert.ok(plan.non_goals.some((entry) => entry.includes("apply")));
});
