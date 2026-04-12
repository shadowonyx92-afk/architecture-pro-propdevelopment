#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NAMESPACE="secure-ops"
KUBECTL=(kubectl)

if [[ -n "${KUBECTL_CONTEXT:-}" ]]; then
  KUBECTL+=(--context "$KUBECTL_CONTEXT")
fi

kc() {
  "${KUBECTL[@]}" "$@"
}

kc create ns "$NAMESPACE" || true
kc create sa monitoring -n "$NAMESPACE" || true

kc create secret generic demo-secret -n "$NAMESPACE" \
  --from-literal=username=admin \
  --from-literal=password=supersecret \
  --dry-run=client -o yaml | kc apply -f -

kc run attacker-pod --image=alpine:3.20 -n "$NAMESPACE" --command -- sleep 3600 || true
kc wait --for=condition=Ready pod/attacker-pod -n "$NAMESPACE" --timeout=120s || true

kc auth can-i get secrets -n "$NAMESPACE" --as=system:serviceaccount:secure-ops:monitoring || true
kc get secret demo-secret -n "$NAMESPACE" --as=system:serviceaccount:secure-ops:monitoring || true

kc create configmap audit-policy -n "$NAMESPACE" \
  --from-file="$SCRIPT_DIR/audit-policy.yaml" \
  --dry-run=client -o yaml | kc apply -f -

cat <<'EOF' | kc apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: secure-ops
spec:
  containers:
    - name: pwn
      image: alpine:3.20
      command: ["sleep", "3600"]
      securityContext:
        privileged: true
  restartPolicy: Never
EOF

kc exec -n "$NAMESPACE" attacker-pod -- cat /etc/os-release || true

kc delete configmap audit-policy -n "$NAMESPACE" || true

cat <<'EOF' | kc apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: escalate-binding
  namespace: secure-ops
subjects:
  - kind: ServiceAccount
    name: monitoring
    namespace: secure-ops
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOF
