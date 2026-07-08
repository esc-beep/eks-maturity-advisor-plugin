import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import yaml from "js-yaml";
import { makeFinding, sortFindings } from "./finding.js";
import type { Finding, Report } from "./schemas.js";
import { validateScanPath } from "./safety.js";

const WORKLOAD_KINDS = new Set(["Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod"]);
const SECRET_NAME_PATTERN = /(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)/i;

interface Entry {
  file: string;
  doc: any;
}

function listYamlFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    if (["node_modules", ".git", "dist", ".aws", ".kube", ".ssh"].includes(entry.name)) return [];
    const current = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (statSync(current).isSymbolicLink()) return [];
      return listYamlFiles(current);
    }
    return /\.(ya?ml)$/.test(entry.name) ? [current] : [];
  });
}

function loadDocuments(repoRoot: string): Entry[] {
  return listYamlFiles(repoRoot).flatMap((file) => {
    const relative = path.relative(repoRoot, file);
    try {
      return yaml.loadAll(readFileSync(file, "utf8"))
        .filter((doc) => doc && typeof doc === "object")
        .map((doc) => ({ file: relative, doc }));
    } catch (error) {
      return [{ file: relative, doc: { kind: "__ParseError", message: (error as Error).message } }];
    }
  });
}

function namespaceOf(doc: any) {
  return doc?.metadata?.namespace || "default";
}

function podSpecFor(doc: any) {
  if (!WORKLOAD_KINDS.has(doc.kind)) return null;
  if (doc.kind === "Pod") return doc.spec ?? null;
  if (doc.kind === "CronJob") return doc.spec?.jobTemplate?.spec?.template?.spec ?? null;
  return doc.spec?.template?.spec ?? null;
}

function containersFor(podSpec: any) {
  return [...(podSpec?.containers ?? []), ...(podSpec?.initContainers ?? [])];
}

function checkNonRoot(entries: Entry[]): Finding {
  const workloads = entries.map(({ file, doc }) => ({ file, doc, podSpec: podSpecFor(doc) })).filter((entry) => entry.podSpec);
  if (workloads.length === 0) {
    return makeFinding("quick-wins/non-root-containers", "unknown", "medium", ["Kubernetes 워크로드 매니페스트를 찾지 못했습니다."], "Deployment, StatefulSet, DaemonSet, Job, CronJob 또는 Pod 매니페스트를 추가한 뒤 non-root 실행을 평가하세요.");
  }
  const failures: string[] = [];
  for (const { file, doc, podSpec } of workloads) {
    const podContext = podSpec.securityContext ?? {};
    for (const container of containersFor(podSpec)) {
      const context = container.securityContext ?? {};
      const runAsUser = context.runAsUser ?? podContext.runAsUser;
      const runAsNonRoot = context.runAsNonRoot ?? podContext.runAsNonRoot;
      if (runAsUser === 0 || runAsNonRoot !== true) {
        failures.push(`${file}: ${doc.kind}/${doc.metadata?.name ?? "<unnamed>"}의 컨테이너 ${container.name ?? "<unnamed>"}가 runAsNonRoot=true를 설정하지 않았거나 UID 0으로 실행됩니다.`);
      }
    }
  }
  return makeFinding(
    "quick-wins/non-root-containers",
    failures.length > 0 ? "fail" : "pass",
    failures.length > 0 ? "high" : "low",
    failures.length > 0 ? failures : [`${workloads.length}개 워크로드 매니페스트가 non-root 실행을 선언합니다.`],
    "Pod 또는 컨테이너 securityContext에 runAsNonRoot=true와 0이 아닌 runAsUser를 설정하고, 가능하면 readOnlyRootFilesystem 같은 컨테이너 강화 설정을 추가하세요.",
    ["kubectl get pods -A -o json"],
  );
}

function checkServiceAccounts(entries: Entry[]): Finding {
  const workloads = entries.map(({ file, doc }) => ({ file, doc, podSpec: podSpecFor(doc) })).filter((entry) => entry.podSpec);
  if (workloads.length === 0) {
    return makeFinding("quick-wins/default-service-account", "unknown", "medium", ["Kubernetes 워크로드 매니페스트를 찾지 못했습니다."], "ServiceAccount 사용 여부를 평가하려면 먼저 워크로드 매니페스트를 추가하세요.");
  }
  const failures: string[] = [];
  for (const { file, doc, podSpec } of workloads) {
    const serviceAccountName = podSpec.serviceAccountName ?? "default";
    const automount = podSpec.automountServiceAccountToken;
    if (serviceAccountName === "default" || automount !== false) {
      failures.push(`${file}: ${doc.kind}/${doc.metadata?.name ?? "<unnamed>"}가 ServiceAccount ${serviceAccountName}를 사용하며 automountServiceAccountToken=${String(automount)}입니다.`);
    }
  }
  return makeFinding(
    "quick-wins/default-service-account",
    failures.length > 0 ? "fail" : "pass",
    failures.length > 0 ? "high" : "low",
    failures.length > 0 ? failures : [`${workloads.length}개 워크로드 매니페스트가 default ServiceAccount 토큰 자동 마운트를 피하고 있습니다.`],
    "워크로드별 ServiceAccount를 사용하고, Kubernetes API 접근이 필요한 경우가 아니라면 automountServiceAccountToken=false를 설정하세요.",
    ["kubectl get pods -A -o json"],
  );
}

function ingressHasTls(doc: any) {
  const annotations = doc.metadata?.annotations ?? {};
  const listenPorts = annotations["alb.ingress.kubernetes.io/listen-ports"] ?? "";
  const hasAlbTls = Boolean(annotations["alb.ingress.kubernetes.io/certificate-arn"]) && /HTTPS/.test(listenPorts);
  return (doc.spec?.tls ?? []).length > 0 || hasAlbTls;
}

function checkIngressTls(entries: Entry[]): Finding {
  const ingresses = entries.filter(({ doc }) => doc.kind === "Ingress");
  if (ingresses.length === 0) {
    return makeFinding("quick-wins/ingress-load-balancer-tls", "unknown", "medium", ["Ingress 매니페스트를 찾지 못했습니다."], "Ingress 또는 Load Balancer 매니페스트가 생긴 뒤 TLS 설정을 평가하세요.");
  }
  const failures = ingresses
    .filter(({ doc }) => !ingressHasTls(doc))
    .map(({ file, doc }) => `${file}: Ingress/${doc.metadata?.name ?? "<unnamed>"}에 spec.tls 또는 ALB HTTPS 인증서 annotation이 없습니다.`);
  return makeFinding(
    "quick-wins/ingress-load-balancer-tls",
    failures.length > 0 ? "fail" : "pass",
    failures.length > 0 ? "high" : "low",
    failures.length > 0 ? failures : [`${ingresses.length}개 Ingress 매니페스트가 TLS termination을 선언합니다.`],
    "Kubernetes Ingress에는 spec.tls를 선언하고, AWS Load Balancer Controller를 쓰는 경우 HTTPS listener, ACM certificate ARN, SSL redirect annotation을 설정하세요.",
    ["kubectl get networkpolicy -A -o json"],
  );
}

function checkQuotaAndLimits(entries: Entry[]): Finding {
  const workloadNamespaces = new Set(entries.filter(({ doc }) => podSpecFor(doc)).map(({ doc }) => namespaceOf(doc)));
  const quotaNamespaces = new Set(entries.filter(({ doc }) => doc.kind === "ResourceQuota").map(({ doc }) => namespaceOf(doc)));
  const limitNamespaces = new Set(entries.filter(({ doc }) => doc.kind === "LimitRange").map(({ doc }) => namespaceOf(doc)));
  if (workloadNamespaces.size === 0) {
    return makeFinding("quick-wins/resource-quota-limitrange", "unknown", "medium", ["워크로드 네임스페이스를 찾지 못했습니다."], "네임스페이스 quota와 기본 limit을 평가하려면 먼저 워크로드 매니페스트를 추가하세요.");
  }
  const failures = [...workloadNamespaces].flatMap((namespace) => {
    const missing = [];
    if (!quotaNamespaces.has(namespace)) missing.push("ResourceQuota");
    if (!limitNamespaces.has(namespace)) missing.push("LimitRange");
    return missing.length > 0 ? [`네임스페이스 ${namespace}에 ${missing.join(" 및 ")}가 없습니다.`] : [];
  });
  return makeFinding(
    "quick-wins/resource-quota-limitrange",
    failures.length > 0 ? "fail" : "pass",
    failures.length > 0 ? "medium" : "low",
    failures.length > 0 ? failures : [`${workloadNamespaces.size}개 네임스페이스에 ResourceQuota와 LimitRange가 있습니다.`],
    "모든 애플리케이션 네임스페이스에 ResourceQuota와 LimitRange를 정의해 워크로드 request/limit이 경계 안에서 관리되도록 하세요.",
    ["kubectl get namespaces -o json"],
  );
}

export function hasHardcodedSecret(obj: unknown): boolean {
  if (Array.isArray(obj)) return obj.some(hasHardcodedSecret);
  if (!obj || typeof obj !== "object") return false;
  const record = obj as Record<string, unknown>;
  if (typeof record.name === "string" && Object.hasOwn(record, "value") && typeof record.value === "string") {
    return SECRET_NAME_PATTERN.test(record.name) && record.value.length > 0;
  }
  return Object.values(record).some(hasHardcodedSecret);
}

function checkHardcodedSecrets(entries: Entry[]): Finding {
  const failures = entries
    .filter(({ doc }) => hasHardcodedSecret(doc))
    .map(({ file, doc }) => `${file}: ${doc.kind ?? "Document"}/${doc.metadata?.name ?? "<unnamed>"}에 env 형식의 Secret literal 값이 포함되어 있습니다.`);
  return makeFinding(
    "quick-wins/aws-secret-manager-사용",
    failures.length > 0 ? "fail" : "pass",
    failures.length > 0 ? "high" : "low",
    failures.length > 0 ? failures : ["Secret처럼 보이는 이름의 env[].value literal 항목을 찾지 못했습니다."],
    "literal Secret 값은 AWS Secrets Manager 또는 승인된 외부 Secret 저장소로 옮기고, ESO, CSI, 애플리케이션 런타임 조회 방식으로 참조하세요.",
    ["kubectl get deployments,statefulsets,daemonsets,jobs,cronjobs -A -o json"],
  );
}

export function scanRepository({ repoRoot = process.cwd(), cwd = process.cwd() }: { repoRoot?: string; cwd?: string } = {}): Report & { repo_root: string } {
  const absoluteRoot = validateScanPath({ cwd, inputPath: repoRoot });
  const entries = loadDocuments(absoluteRoot);
  const findings = [
    checkNonRoot(entries),
    checkServiceAccounts(entries),
    checkIngressTls(entries),
    checkQuotaAndLimits(entries),
    checkHardcodedSecrets(entries),
  ];
  return {
    scanner: "eks-maturity-advisor",
    mode: "repo-only",
    repo_root: absoluteRoot,
    findings: sortFindings(findings),
  };
}
