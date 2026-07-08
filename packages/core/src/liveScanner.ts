import { makeFinding, sortFindings } from "./finding.js";
import { hasHardcodedSecret } from "./repositoryScanner.js";
import type { Finding, Report } from "./schemas.js";
import { defaultCommandRunner, runReadOnlyCommand, sanitizeKubeConfig, sanitizeKubernetesObject, type CommandRunner } from "./safety.js";

const SYSTEM_NAMESPACES = new Set(["kube-system", "kube-public", "kube-node-lease"]);

interface ReadResult<T> {
  ok: boolean;
  data?: T;
  text?: string;
  error?: string;
  code?: string;
}

interface LiveConfig {
  context?: string | null;
  clusterName?: string | null;
  region?: string | null;
  sanitizedKubeconfig?: unknown;
}

interface LiveOptions extends LiveConfig {
  commandRunner: CommandRunner;
}

function readText(commandRunner: CommandRunner, command: string, args: string[]): ReadResult<never> {
  try {
    return { ok: true, text: runReadOnlyCommand(commandRunner, command, args) };
  } catch (error) {
    const err = error as Error & { code?: string };
    return { ok: false, error: err.message, code: err.code };
  }
}

function readJson<T = any>(commandRunner: CommandRunner, command: string, args: string[], sanitizer?: (input: T) => T): ReadResult<T> {
  try {
    const output = runReadOnlyCommand(commandRunner, command, args);
    const parsed = JSON.parse(output || "{}") as T;
    return { ok: true, data: sanitizer ? sanitizer(parsed) : parsed };
  } catch (error) {
    const err = error as Error & { code?: string };
    return { ok: false, error: err.message, code: err.code };
  }
}

function unavailable(itemId: string, error: string | undefined, recommendation: string, verifyCommands: string[]): Finding {
  return makeFinding(itemId, "unavailable", "medium", [`read-only 명령 실행 또는 입력 감지가 불가능합니다: ${error ?? "unknown error"}`], recommendation, verifyCommands);
}

function missing(itemId: string, missingValues: string[], verifyCommands: string[]): Finding {
  return makeFinding(itemId, "unavailable", "medium", [`live scan 입력값이 부족합니다: ${missingValues.join(", ")}.`], "현재 kubeconfig context와 read-only AWS/Kubernetes 자격 증명을 확인한 뒤 다시 실행하세요.", verifyCommands);
}

function kubectlArgs(args: string[]) {
  return args;
}

function awsArgs(service: string, operation: string, args: string[], region?: string | null) {
  return [service, operation, ...args, ...(region ? ["--region", region] : []), "--output", "json"];
}

function parseEksContextArn(context?: string | null) {
  const match = /^arn:aws[^:]*:eks:([^:]+):\d+:cluster\/(.+)$/.exec(context ?? "");
  if (!match) return {};
  return { region: match[1], clusterName: match[2] };
}

function valueAfter(args: unknown[], flag: string) {
  const index = args.indexOf(flag);
  return index === -1 ? null : String(args[index + 1]);
}

export function detectLiveConfig({ commandRunner = defaultCommandRunner }: { commandRunner?: CommandRunner } = {}): LiveConfig {
  const current = readText(commandRunner, "kubectl", ["config", "current-context"]);
  if (!current.ok) return { context: null, clusterName: null, region: null };

  const context = current.text?.trim() ?? "";
  const fromContext = parseEksContextArn(context);
  const config = readJson<any>(commandRunner, "kubectl", ["config", "view", "--minify", "-o", "json"], sanitizeKubeConfig);
  const execConfig = config.ok ? config.data?.users?.[0]?.user?.exec ?? {} : {};
  const execArgs = execConfig.args ?? [];

  return {
    context,
    clusterName: valueAfter(execArgs, "--cluster-name") ?? fromContext.clusterName ?? null,
    region: valueAfter(execArgs, "--region") ?? fromContext.region ?? null,
    sanitizedKubeconfig: config.ok ? config.data : undefined,
  };
}

function applicationNamespacesFromPods(pods: any) {
  return new Set((pods.items ?? []).map((pod: any) => pod.metadata?.namespace ?? "default").filter((namespace: string) => !SYSTEM_NAMESPACES.has(namespace)));
}

function isEmptySelector(selector: any) {
  return selector && typeof selector === "object" && Object.keys(selector).length === 0;
}

function containersForPod(pod: any) {
  return [...(pod.spec?.containers ?? []), ...(pod.spec?.initContainers ?? [])];
}

function workloadPodSpecForLive(item: any) {
  if (item.kind === "Pod") return item.spec ?? null;
  if (item.kind === "CronJob") return item.spec?.jobTemplate?.spec?.template?.spec ?? null;
  return item.spec?.template?.spec ?? null;
}

function checkPrivateApiEndpoint(options: LiveOptions): Finding {
  const verify = ["aws eks describe-cluster --name <cluster-name> --region <region> --output json"];
  if (!options.clusterName || !options.region) return missing("foundational/private-api-endpoint", ["clusterName", "region"].filter((key) => !(options as any)[key]), verify);
  const result = readJson<any>(options.commandRunner, "aws", awsArgs("eks", "describe-cluster", ["--name", options.clusterName], options.region));
  if (!result.ok) return unavailable("foundational/private-api-endpoint", result.error, "read-only AWS 자격 증명으로 EKS cluster endpoint 조회를 실행하세요.", verify);
  const config = result.data?.cluster?.resourcesVpcConfig ?? {};
  const passes = config.endpointPublicAccess === false && config.endpointPrivateAccess === true;
  return makeFinding(
    "foundational/private-api-endpoint",
    passes ? "pass" : "fail",
    passes ? "low" : "high",
    [`current-context=${options.context ?? "<unknown>"}`, `endpointPublicAccess=${String(config.endpointPublicAccess)}, endpointPrivateAccess=${String(config.endpointPrivateAccess)}`],
    "운영 클러스터는 private-only EKS API endpoint를 사용하고 승인된 private 네트워크 경로를 통해서만 접근하도록 구성하세요.",
    verify,
  );
}

function checkPrivateSubnets(options: LiveOptions): Finding {
  const verify = ["aws eks list-nodegroups --cluster-name <cluster-name> --region <region> --output json", "aws ec2 describe-subnets --subnet-ids <subnet-ids> --region <region> --output json"];
  if (!options.clusterName || !options.region) return missing("foundational/private-subnets", ["clusterName", "region"].filter((key) => !(options as any)[key]), verify);
  const nodegroups = readJson<any>(options.commandRunner, "aws", awsArgs("eks", "list-nodegroups", ["--cluster-name", options.clusterName], options.region));
  if (!nodegroups.ok) return unavailable("foundational/private-subnets", nodegroups.error, "read-only AWS 자격 증명으로 EKS managed nodegroup 목록을 조회하세요.", verify);
  const subnetIds = new Set<string>();
  for (const nodegroupName of nodegroups.data?.nodegroups ?? []) {
    const nodegroup = readJson<any>(options.commandRunner, "aws", awsArgs("eks", "describe-nodegroup", ["--cluster-name", options.clusterName, "--nodegroup-name", nodegroupName], options.region));
    if (!nodegroup.ok) return unavailable("foundational/private-subnets", nodegroup.error, `read-only AWS 자격 증명으로 nodegroup ${nodegroupName} 상세 정보를 조회하세요.`, verify);
    for (const subnetId of nodegroup.data?.nodegroup?.subnets ?? []) subnetIds.add(subnetId);
  }
  if (subnetIds.size === 0) return makeFinding("foundational/private-subnets", "unknown", "medium", ["EKS managed nodegroup subnet 정보가 반환되지 않았습니다."], "self-managed nodegroup, Fargate profile 또는 Terraform output에서 node 배치 정보를 확인하세요.", verify);
  const subnets = readJson<any>(options.commandRunner, "aws", awsArgs("ec2", "describe-subnets", ["--subnet-ids", ...subnetIds], options.region));
  if (!subnets.ok) return unavailable("foundational/private-subnets", subnets.error, "read-only EC2 권한으로 nodegroup subnet 상세 정보를 조회하세요.", verify);
  const publicSubnets = (subnets.data?.Subnets ?? []).filter((subnet: any) => subnet.MapPublicIpOnLaunch === true);
  return makeFinding(
    "foundational/private-subnets",
    publicSubnets.length > 0 ? "fail" : "pass",
    publicSubnets.length > 0 ? "high" : "low",
    publicSubnets.length > 0 ? publicSubnets.map((subnet: any) => `${subnet.SubnetId}가 인스턴스 시작 시 public IP를 자동 할당합니다.`) : [`${subnetIds.size}개 nodegroup subnet이 public IP를 자동 할당하지 않습니다.`],
    "Worker node와 Pod 네트워킹은 private subnet에 배치하고 통제된 egress 경로를 사용하세요.",
    verify,
  );
}

function checkDefaultDenyNetworkPolicy(options: LiveOptions): Finding {
  const verify = ["kubectl get pods -A -o json", "kubectl get networkpolicy -A -o json"];
  if (!options.context) return missing("efficient/default-deny-networkpolicy", ["context"], verify);
  const pods = readJson<any>(options.commandRunner, "kubectl", kubectlArgs(["get", "pods", "-A", "-o", "json"]), sanitizeKubernetesObject);
  if (!pods.ok) return unavailable("efficient/default-deny-networkpolicy", pods.error, "선택한 context로 kubectl을 사용해 Pod 목록을 조회하세요.", verify);
  const workloadNamespaces = applicationNamespacesFromPods(pods.data);
  if (workloadNamespaces.size === 0) return makeFinding("efficient/default-deny-networkpolicy", "unknown", "medium", ["애플리케이션 워크로드 네임스페이스를 찾지 못했습니다."], "워크로드가 생성된 뒤 다시 점검하세요.", verify);
  const policies = readJson<any>(options.commandRunner, "kubectl", kubectlArgs(["get", "networkpolicy", "-A", "-o", "json"]), sanitizeKubernetesObject);
  if (!policies.ok) return unavailable("efficient/default-deny-networkpolicy", policies.error, "kubectl을 사용해 NetworkPolicy 객체를 조회하세요.", verify);
  const protectedNamespaces = new Set((policies.data?.items ?? []).filter((policy: any) => isEmptySelector(policy.spec?.podSelector) && (policy.spec?.policyTypes ?? []).some((type: string) => type === "Ingress" || type === "Egress")).map((policy: any) => policy.metadata?.namespace ?? "default"));
  const missingNamespaces = [...workloadNamespaces].filter((namespace) => !protectedNamespaces.has(namespace));
  return makeFinding(
    "efficient/default-deny-networkpolicy",
    missingNamespaces.length > 0 ? "fail" : "pass",
    missingNamespaces.length > 0 ? "high" : "low",
    missingNamespaces.length > 0 ? missingNamespaces.map((namespace) => `네임스페이스 ${namespace}에 default deny NetworkPolicy가 없습니다.`) : [`${workloadNamespaces.size}개 워크로드 네임스페이스에 default deny NetworkPolicy가 적용되어 있습니다.`],
    "명시적인 워크로드 허용 정책을 추가하기 전에 네임스페이스 수준 default deny NetworkPolicy를 적용하세요.",
    verify,
  );
}

function checkPodSecurityBaseline(options: LiveOptions): Finding {
  const verify = ["kubectl get namespaces -o json", "kubectl get pods -A -o json"];
  if (!options.context) return missing("foundational/pod-실행-권한-최소화", ["context"], verify);
  const namespaces = readJson<any>(options.commandRunner, "kubectl", kubectlArgs(["get", "namespaces", "-o", "json"]), sanitizeKubernetesObject);
  const pods = readJson<any>(options.commandRunner, "kubectl", kubectlArgs(["get", "pods", "-A", "-o", "json"]), sanitizeKubernetesObject);
  if (!namespaces.ok) return unavailable("foundational/pod-실행-권한-최소화", namespaces.error, "namespace label을 조회하세요.", verify);
  if (!pods.ok) return unavailable("foundational/pod-실행-권한-최소화", pods.error, "Pod spec을 조회하세요.", verify);
  const workloadNamespaces = applicationNamespacesFromPods(pods.data);
  const labelsByNamespace = new Map((namespaces.data?.items ?? []).map((namespace: any) => [namespace.metadata?.name, namespace.metadata?.labels ?? {}]));
  const failures: string[] = [];
  for (const namespace of workloadNamespaces) {
    const enforce = (labelsByNamespace.get(namespace) as any)?.["pod-security.kubernetes.io/enforce"];
    if (enforce !== "baseline" && enforce !== "restricted") failures.push(`네임스페이스 ${namespace}가 PSS baseline 또는 restricted를 enforce하지 않습니다.`);
  }
  for (const pod of pods.data?.items ?? []) {
    const namespace = pod.metadata?.namespace ?? "default";
    if (!workloadNamespaces.has(namespace)) continue;
    for (const container of containersForPod(pod)) {
      if (container.securityContext?.privileged === true) failures.push(`${namespace}/${pod.metadata?.name ?? "<unnamed>"}의 컨테이너 ${container.name ?? "<unnamed>"}가 privileged로 실행됩니다.`);
    }
  }
  return makeFinding("foundational/pod-실행-권한-최소화", failures.length > 0 ? "fail" : "pass", failures.length > 0 ? "high" : "low", failures.length > 0 ? failures : [`${workloadNamespaces.size}개 워크로드 네임스페이스가 PSS baseline/restricted를 enforce합니다.`], "Pod Security Standards를 최소 baseline 이상으로 enforce하고 privileged 컨테이너 실행을 제거하세요.", verify);
}

function checkIamK8sMapping(options: LiveOptions): Finding {
  const verify = ["aws eks describe-cluster --name <cluster-name> --region <region> --output json", "aws eks list-access-entries --cluster-name <cluster-name> --region <region> --output json"];
  if (!options.clusterName || !options.region) return missing("foundational/iam-k8s-mapping", ["clusterName", "region"].filter((key) => !(options as any)[key]), verify);
  const cluster = readJson<any>(options.commandRunner, "aws", awsArgs("eks", "describe-cluster", ["--name", options.clusterName], options.region));
  const entries = readJson<any>(options.commandRunner, "aws", awsArgs("eks", "list-access-entries", ["--cluster-name", options.clusterName], options.region));
  if (!cluster.ok) return unavailable("foundational/iam-k8s-mapping", cluster.error, "EKS access configuration을 조회하세요.", verify);
  if (!entries.ok) return unavailable("foundational/iam-k8s-mapping", entries.error, "EKS access entry 목록을 조회하세요.", verify);
  const authenticationMode = cluster.data?.cluster?.accessConfig?.authenticationMode ?? "unknown";
  const accessEntries = entries.data?.accessEntries ?? [];
  const usesApi = String(authenticationMode).includes("API");
  const passes = usesApi && accessEntries.length > 0;
  return makeFinding("foundational/iam-k8s-mapping", passes ? "pass" : usesApi ? "warn" : "fail", passes ? "low" : usesApi ? "medium" : "high", [`authenticationMode=${authenticationMode}, accessEntries=${accessEntries.length}`], "클러스터 접근은 EKS Access Entries로 관리하고 IAM-to-Kubernetes 접근 매핑을 명시적이고 리뷰 가능한 상태로 유지하세요.", verify);
}

function checkContainerImageTriage(options: LiveOptions): Finding {
  const verify = ["aws inspector2 list-filters --action SUPPRESS --region <region> --output json", "aws inspector2 list-findings --region <region> --output json"];
  if (!options.region) return missing("foundational/container-image-취약점-관리", ["region"], verify);
  const filters = readJson<any>(options.commandRunner, "aws", awsArgs("inspector2", "list-filters", ["--action", "SUPPRESS"], options.region));
  const findings = readJson<any>(options.commandRunner, "aws", awsArgs("inspector2", "list-findings", ["--filter-criteria", '{"resourceType":[{"comparison":"EQUALS","value":"AWS_ECR_CONTAINER_IMAGE"}],"findingStatus":[{"comparison":"EQUALS","value":"ACTIVE"}],"severity":[{"comparison":"EQUALS","value":"CRITICAL"},{"comparison":"EQUALS","value":"HIGH"}]}'], options.region));
  if (!filters.ok || !findings.ok) return unavailable("foundational/container-image-취약점-관리", filters.error ?? findings.error, "Inspector2가 활성화되어 있는지 확인하고 read-only 권한으로 list-filters/list-findings를 실행하세요.", verify);
  const suppressFilters = filters.data?.filters ?? [];
  const activeFindings = findings.data?.findings ?? [];
  const status = activeFindings.length > 0 ? "fail" : suppressFilters.length > 0 ? "pass" : "warn";
  return makeFinding("foundational/container-image-취약점-관리", status, activeFindings.length > 0 ? "high" : status === "warn" ? "medium" : "low", [`${suppressFilters.length}개 Inspector suppression filter를 찾았습니다.`, `${activeFindings.length}개 활성 Critical/High ECR finding을 찾았습니다.`], "문서화된 Inspector triage suppression filter를 유지하고 활성 Critical/High ECR finding은 SLA 안에 조치하세요.", verify);
}

function checkEbsStorageProtection(options: LiveOptions): Finding {
  const verify = ["aws ec2 get-ebs-encryption-by-default --region <region> --output json", "kubectl get storageclass -o json", "kubectl get pvc -A -o json", "kubectl get pv -o json"];
  if (!options.region || !options.context) return missing("foundational/ebs-기반-workload-storage-data-보호", ["region", "context"].filter((key) => !(options as any)[key]), verify);
  const defaultEncryption = readJson<any>(options.commandRunner, "aws", awsArgs("ec2", "get-ebs-encryption-by-default", [], options.region));
  const storageClasses = readJson<any>(options.commandRunner, "kubectl", kubectlArgs(["get", "storageclass", "-o", "json"]), sanitizeKubernetesObject);
  const pvcs = readJson<any>(options.commandRunner, "kubectl", kubectlArgs(["get", "pvc", "-A", "-o", "json"]), sanitizeKubernetesObject);
  const pvs = readJson<any>(options.commandRunner, "kubectl", kubectlArgs(["get", "pv", "-o", "json"]), sanitizeKubernetesObject);
  if (!defaultEncryption.ok) return unavailable("foundational/ebs-기반-workload-storage-data-보호", defaultEncryption.error, "EBS 기본 암호화 상태를 조회하세요.", verify);
  if (!storageClasses.ok || !pvcs.ok || !pvs.ok) return unavailable("foundational/ebs-기반-workload-storage-data-보호", storageClasses.error ?? pvcs.error ?? pvs.error, "kubectl로 storageclass/pvc/pv 객체를 조회하세요.", verify);
  const failures: string[] = [];
  if (defaultEncryption.data?.EbsEncryptionByDefault !== true) failures.push("이 리전에서 AWS EBS 기본 암호화가 활성화되어 있지 않습니다.");
  const classByName = new Map((storageClasses.data?.items ?? []).map((storageClass: any) => [storageClass.metadata?.name, storageClass]));
  for (const storageClass of storageClasses.data?.items ?? []) {
    if ((storageClass.provisioner === "ebs.csi.aws.com" || storageClass.provisioner === "kubernetes.io/aws-ebs") && String(storageClass.parameters?.encrypted).toLowerCase() !== "true") failures.push(`StorageClass ${storageClass.metadata?.name ?? "<unnamed>"}가 parameters.encrypted=true를 설정하지 않았습니다.`);
  }
  for (const pvc of pvcs.data?.items ?? []) {
    const storageClassName = pvc.spec?.storageClassName;
    if (!storageClassName || !classByName.has(storageClassName)) failures.push(`${pvc.metadata?.namespace ?? "default"}/${pvc.metadata?.name ?? "<unnamed>"} PVC가 확인된 암호화 StorageClass를 참조하지 않습니다.`);
  }
  return makeFinding("foundational/ebs-기반-workload-storage-data-보호", failures.length > 0 ? "fail" : "pass", failures.length > 0 ? "high" : "low", failures.length > 0 ? failures : ["EBS 기본 암호화, StorageClass 암호화, PVC 참조가 확인되었습니다."], "EBS 기본 암호화를 활성화하고, 암호화된 EBS CSI StorageClass를 요구하세요.", verify);
}

function checkHardcodedSecretRemoval(options: LiveOptions): Finding {
  const verify = ["kubectl get deployments,statefulsets,daemonsets,jobs,cronjobs -A -o json"];
  if (!options.context) return missing("foundational/workload-내-hardcoded-secret-제거", ["context"], verify);
  const workloads = readJson<any>(options.commandRunner, "kubectl", kubectlArgs(["get", "deployments,statefulsets,daemonsets,jobs,cronjobs", "-A", "-o", "json"]), sanitizeKubernetesObject);
  if (!workloads.ok) return unavailable("foundational/workload-내-hardcoded-secret-제거", workloads.error, "워크로드 env 구성을 조회하세요.", verify);
  const failures = (workloads.data?.items ?? []).filter((item: any) => hasHardcodedSecret(workloadPodSpecForLive(item))).map((item: any) => `${item.metadata?.namespace ?? "default"}/${item.kind ?? "Workload"}/${item.metadata?.name ?? "<unnamed>"}에 env 형식의 Secret literal이 포함되어 있습니다.`);
  return makeFinding("foundational/workload-내-hardcoded-secret-제거", failures.length > 0 ? "fail" : "pass", failures.length > 0 ? "high" : "low", failures.length > 0 ? failures : ["Secret처럼 보이는 literal env 값은 관측되지 않았습니다."], "런타임 Secret은 AWS Secrets Manager 또는 승인된 외부 Secret 경로로 옮기고 valueFrom, ESO, CSI 또는 런타임 조회 방식으로 참조하세요.", verify);
}

function checkRbac(options: LiveOptions): Finding {
  const verify = ["kubectl get roles,rolebindings -A -o json", "kubectl get clusterroles,clusterrolebindings -o json"];
  if (!options.context) return missing("foundational/cluster내-리소스-접근제어", ["context"], verify);
  const namespaced = readJson<any>(options.commandRunner, "kubectl", kubectlArgs(["get", "roles,rolebindings", "-A", "-o", "json"]), sanitizeKubernetesObject);
  const cluster = readJson<any>(options.commandRunner, "kubectl", kubectlArgs(["get", "clusterroles,clusterrolebindings", "-o", "json"]), sanitizeKubernetesObject);
  if (!namespaced.ok || !cluster.ok) return unavailable("foundational/cluster내-리소스-접근제어", namespaced.error ?? cluster.error, "kubectl로 RBAC 객체를 조회하세요.", verify);
  const items = [...(namespaced.data?.items ?? []), ...(cluster.data?.items ?? [])];
  const failures: string[] = [];
  for (const item of items) {
    const rules = item.rules ?? [];
    if ((item.kind === "Role" || item.kind === "ClusterRole") && rules.some((rule: any) => (rule.verbs ?? []).includes("*") || (rule.resources ?? []).includes("*"))) failures.push(`${item.kind}/${item.metadata?.name ?? "<unnamed>"}가 wildcard RBAC 권한을 사용합니다.`);
    if (item.kind === "ClusterRoleBinding" && item.roleRef?.name === "cluster-admin") failures.push(`ClusterRoleBinding/${item.metadata?.name ?? "<unnamed>"}가 cluster-admin을 바인딩합니다.`);
  }
  const roleBindings = items.filter((item: any) => item.kind === "RoleBinding").length;
  return makeFinding("foundational/cluster내-리소스-접근제어", failures.length > 0 ? "fail" : roleBindings > 0 ? "pass" : "warn", failures.length > 0 ? "high" : roleBindings > 0 ? "low" : "medium", failures.length > 0 ? failures : [`${roleBindings}개 RoleBinding 객체를 찾았고, wildcard RBAC 또는 cluster-admin 바인딩은 관측되지 않았습니다.`], "네임스페이스 RBAC를 명시적으로 유지하고 wildcard 권한을 피하세요.", verify);
}

export function scanLiveCluster({ commandRunner = defaultCommandRunner }: { commandRunner?: CommandRunner } = {}): Report & { kubectl_context: string | null; cluster_name: string | null; region: string | null; environment: { sanitized_kubeconfig?: unknown } } {
  const detected = detectLiveConfig({ commandRunner });
  const options: LiveOptions = {
    commandRunner,
    context: detected.context,
    clusterName: detected.clusterName,
    region: detected.region,
    sanitizedKubeconfig: detected.sanitizedKubeconfig,
  };
  const findings = [
    checkPrivateApiEndpoint(options),
    checkPrivateSubnets(options),
    checkDefaultDenyNetworkPolicy(options),
    checkPodSecurityBaseline(options),
    checkIamK8sMapping(options),
    checkContainerImageTriage(options),
    checkEbsStorageProtection(options),
    checkHardcodedSecretRemoval(options),
    checkRbac(options),
  ];
  return {
    scanner: "eks-maturity-advisor",
    mode: "live-cluster",
    kubectl_context: options.context ?? null,
    cluster_name: options.clusterName ?? null,
    region: options.region ?? null,
    environment: {
      sanitized_kubeconfig: options.sanitizedKubeconfig,
    },
    findings: sortFindings(findings),
  };
}
