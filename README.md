# EKS Maturity Advisor Plugin

EKS Maturity Advisor Plugin은 K8RVIS EKS 보안 성숙도 모델을 기준으로 Kubernetes 매니페스트와 현재 EKS 클러스터 상태를 읽기 전용으로 진단하는 Codex Plugin입니다.

이 레포는 기존 `eks-maturity-advisor` Skill을 확장해, Skill의 판단/리포팅 가이드와 MCP 서버의 구조화된 진단 API를 함께 제공합니다.

## MCP란?

MCP(Model Context Protocol)는 AI 클라이언트가 외부 도구를 일관된 방식으로 호출할 수 있게 해주는 프로토콜입니다.

이 프로젝트에서 MCP는 다음 역할을 합니다.

- EKS 성숙도 catalog 조회
- 로컬 repo와 Kubernetes YAML 정적 진단
- 현재 kubeconfig context 기반 live cluster 읽기 전용 진단
- 진단 결과를 기반으로 한 개선 계획 생성

Skill은 “언제 어떤 도구를 쓰고 어떻게 설명할지”를 담당하고, MCP는 “정해진 입력을 받아 안정적인 JSON 결과를 반환하는 도구 API”를 담당합니다.

## 제공 기능

MCP server는 다음 tool을 제공합니다.

| Tool | 설명 |
| --- | --- |
| `eks_get_catalog_info` | catalog version, snapshot date, control count 조회 |
| `eks_list_controls` | phase, domain, item id, query 기반 성숙도 통제 항목 검색 |
| `eks_scan_repository` | 단일 로컬 디렉토리의 Kubernetes YAML을 읽기 전용으로 스캔 |
| `eks_scan_live_cluster` | 현재 kubeconfig current-context를 `kubectl`/AWS CLI read-only 명령으로 스캔 |
| `eks_generate_remediation_plan` | findings를 기반으로 패치 계획, 예시 조각, 검증 명령 생성 |

`eks_render_report`는 제공하지 않습니다. Markdown 요약과 설명은 Skill/LLM 레이어가 담당합니다.

## 사용 방법

의존성을 설치하고 빌드합니다.

```bash
npm install
npm run build
```

테스트와 plugin validation을 실행합니다.

```bash
npm test
npm run validate:plugin
python3 /Users/esc/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/eks-maturity-advisor
```

로컬 repo를 스캔합니다.

```bash
npm --silent run scan:repo -- --repo-root .
```

현재 kubeconfig context의 live cluster를 읽기 전용으로 스캔합니다.

```bash
npm --silent run scan:live
```

MCP server를 stdio로 실행합니다.

```bash
npm run mcp:dev
```

Skill fallback wrapper를 직접 실행할 수도 있습니다.

```bash
node skills/eks-maturity-advisor/scripts/scan.mjs scan-repo --repo-root <repository-path>
node skills/eks-maturity-advisor/scripts/scan.mjs scan-live
node skills/eks-maturity-advisor/scripts/scan.mjs catalog-info
```

Codex Plugin 설정은 repo root의 `.codex-plugin/plugin.json`과 `.mcp.json`에 들어 있습니다. `.mcp.json`은 build된 server entrypoint인 `packages/mcp-server/dist/server.js`를 실행합니다.

## 안전 경계

이 도구는 v1에서 읽기 전용으로 동작합니다.

지원하지 않는 작업:

- `kubectl apply`
- `kubectl delete`
- `terraform apply`
- `helm upgrade`
- `aws eks update-*`
- 파일 자동 수정

live scan은 외부에서 `context`, `clusterName`, `region`을 받지 않고 현재 kubeconfig의 current-context만 대상으로 합니다. 외부 명령은 `child_process.execFile(binary, argsArray)`로 실행하며, shell string 실행은 사용하지 않습니다.

민감 정보 보호:

- `kubectl get secret`은 차단합니다.
- `kubectl config view`의 token, password, client key 계열 값은 redaction합니다.
- workload env의 literal secret-like value는 redaction합니다.
- command timeout은 30초, output buffer는 2MB로 제한합니다.

## 기술 선택의 이유

### Codex Plugin

Skill과 MCP를 한 배포 단위로 묶기 위해 Codex Plugin 형태를 선택했습니다. 이 구조에서는 Skill, MCP server, reference snapshot, fallback CLI가 같은 repo 안에서 함께 버전 관리됩니다.

### MCP Server

기존 Skill만으로도 진단은 가능했지만, 반복 가능한 스캔 로직을 자연어 지침 안에만 두면 입력/출력 계약과 테스트 경계가 약해집니다. MCP server로 분리하면 scanner 결과를 JSON API로 고정하고, Codex나 다른 MCP client가 같은 방식으로 호출할 수 있습니다.

### TypeScript Node

기존 scanner가 Node.js 기반이었기 때문에 이식 비용이 낮고, `@modelcontextprotocol/sdk`, `zod`, `zod-to-json-schema`를 통해 MCP schema와 TypeScript 타입을 함께 관리할 수 있습니다.

### npm workspaces

v1에서는 `pnpm`이나 `turborepo` 없이 npm workspaces만 사용합니다. 구조는 monorepo지만 tooling은 단순하게 유지합니다.

```text
packages/core        scanner, schemas, safety utilities, remediation planner
packages/mcp-server  MCP stdio server and tool handlers
skills/              Codex Skill instructions and fallback wrapper
references/          bundled maturity catalog snapshot
```

### zod

공통 타입과 런타임 validation을 한 곳에서 관리하기 위해 `zod`를 사용합니다. MCP input schema는 zod schema에서 JSON Schema로 변환합니다.

## 이전 Skill과의 차이점

기존 `EKS-Maturity-Model/skills/eks-maturity-advisor`는 Skill 중심 구조였습니다.

- `SKILL.md`가 workflow와 reporting 방식을 안내
- `scripts/scan_eks_maturity.mjs`가 repo/live scan을 수행
- reference catalog가 원본 문서 repo 안에 존재
- Codex가 Skill 지침을 읽고 필요 시 스크립트를 직접 실행

새 plugin 구조는 역할을 더 명확히 나눕니다.

| 항목 | 이전 Skill | 새 Plugin + MCP |
| --- | --- | --- |
| 배포 단위 | Skill folder | Codex Plugin repo |
| 실행 API | bundled script 중심 | MCP tools 중심 |
| Skill 역할 | 진단 흐름과 스크립트 사용 안내 | MCP 우선 호출, 결과 해석, fallback 안내 |
| Scanner 역할 | Skill 내부 script | `packages/core` TypeScript 모듈 |
| Client 연동 | Codex Skill 중심 | Codex Plugin + MCP stdio server |
| 테스트 경계 | script 테스트 중심 | core, safety, MCP handler, packaging 테스트 |
| 개선안 생성 | 응답 작성 중심 | `eks_generate_remediation_plan` 구조화 결과 |
| 안전 통제 | read-only 지침 | allowlist, path validation, redaction, timeout 테스트 포함 |

즉, 이전 Skill은 “Codex에게 어떻게 진단할지 알려주는 패키지”에 가까웠고, 새 구조는 “Codex가 호출할 수 있는 검증된 도구 API와 그 사용법을 함께 제공하는 플러그인”입니다.

## Catalog Snapshot

`references/catalog.json`과 `references/quick-wins-v1.md`는 현재 EKS Maturity Model에서 가져온 snapshot입니다.

원본 문서 repo에서 snapshot을 갱신하려면 다음 명령을 사용합니다.

```bash
npm run catalog:import -- --source /Users/esc/Desktop/K8RVIS/EKS-Maturity-Model
```

## 개발 명령

```bash
npm run build
npm test
npm run validate:plugin
npm run mcp:dev
npm --silent run scan:repo -- --repo-root .
npm --silent run scan:live
```

## 현재 범위

v1은 로컬 Codex Plugin 사용을 목표로 합니다. npm registry 배포, 원격 catalog 자동 동기화, cluster/resource 변경 자동화는 범위에 포함하지 않습니다.
