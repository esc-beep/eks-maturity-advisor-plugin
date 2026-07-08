---
name: eks-maturity-advisor
description: Assess Amazon EKS repositories, Kubernetes manifests, and the current kubeconfig context against K8RVIS EKS maturity controls. Use when Codex is asked to review EKS security posture, run read-only repo or live cluster scans, prioritize maturity gaps, or generate remediation plans without applying changes.
---

# EKS Maturity Advisor

## Safety Boundary

Operate read-only. Do not run `kubectl apply`, `kubectl delete`, `terraform apply`, `helm upgrade`, `aws eks update-*`, or any command that mutates a cluster, AWS account, or repository.

## Preferred Workflow

Use the MCP tools first:

1. Use `eks_get_catalog_info` when the user asks what catalog snapshot is being used.
2. Use `eks_list_controls` for conceptual questions or to find maturity items.
3. Use `eks_scan_repository` for local repository or manifest directory scans.
4. Use `eks_scan_live_cluster` only when the user asks for a live cluster check. It scans the current kubeconfig context only.
5. Use `eks_generate_remediation_plan` after findings exist and the user asks what to change.

Report findings in this order: `P1`, `P2`, `P3`; within the same priority, show `fail`, `warn`, `unavailable`, `unknown`, then `pass`.

For each failed, warned, or unavailable item, include item id, phase, domain, status, evidence, risk, recommended remediation, and read-only verification commands.

## Fallback CLI

If MCP tools are unavailable but this plugin repo is present, run the bundled fallback wrapper after `npm run build`:

```bash
node skills/eks-maturity-advisor/scripts/scan.mjs scan-repo --repo-root <repository-path>
node skills/eks-maturity-advisor/scripts/scan.mjs scan-live
node skills/eks-maturity-advisor/scripts/scan.mjs catalog-info
```

The fallback wrapper calls the built core CLI and preserves the same read-only safety boundary.

## References

- `references/catalog.json`: bundled maturity catalog snapshot.
- `references/quick-wins-v1.md`: scanner rules, limitations, and remediation notes.
