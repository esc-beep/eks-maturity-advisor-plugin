import assert from "node:assert/strict";
import test from "node:test";

test("command allowlist rejects injection and mutating commands", async () => {
  const { assertAllowedCommand } = await import("../packages/core/dist/index.js");
  const badCommands = [
    ["kubectl", ["get", "pods", ";", "cat", "/etc/passwd"]],
    ["kubectl", ["apply", "-f", "app.yaml"]],
    ["kubectl", ["delete", "pod", "api"]],
    ["kubectl", ["get", "secret", "-A", "-o", "json"]],
    ["aws", ["eks", "update-cluster-config", "--name", "prod"]],
    ["terraform", ["apply"]],
    ["helm", ["upgrade", "api", "."]],
    ["kubectl", ["get", "pods", "$(curl", "attacker)"]],
    ["kubectl", ["get", "pods", "|", "base64"]],
    ["kubectl", ["get", "pods", "`whoami`"]],
  ];

  for (const [command, args] of badCommands) {
    assert.throws(() => assertAllowedCommand(command, args), /not allowed|metacharacter|secret/i);
  }

  assert.doesNotThrow(() => assertAllowedCommand("kubectl", ["get", "pods", "-A", "-o", "json"]));
  assert.doesNotThrow(() => assertAllowedCommand("aws", ["eks", "describe-cluster", "--name", "secure", "--region", "ap-northeast-2", "--output", "json"]));
});

test("sanitizers redact kubeconfig secrets and literal env values", async () => {
  const { sanitizeKubeConfig, sanitizeKubernetesObject } = await import("../packages/core/dist/index.js");
  const kubeconfig = sanitizeKubeConfig({ users: [{ user: { token: "abc", password: "pw", "client-key-data": "key" } }] });
  const pod = sanitizeKubernetesObject({
    items: [{
      spec: {
        containers: [{
          env: [
            { name: "DB_PASSWORD", value: "plaintext" },
            { name: "TOKEN", valueFrom: { secretKeyRef: { name: "runtime", key: "token" } } },
          ],
        }],
      },
    }],
  });

  assert.equal(kubeconfig.users[0].user.token, "[REDACTED]");
  assert.equal(pod.items[0].spec.containers[0].env[0].value, "[REDACTED]");
  assert.equal(pod.items[0].spec.containers[0].env[1].valueFrom.secretKeyRef.name, "runtime");
});
