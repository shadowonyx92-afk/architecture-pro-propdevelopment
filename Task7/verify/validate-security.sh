#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

kubectl apply -f "$ROOT_DIR/01-create-namespace.yaml"

if ! kubectl get crd constrainttemplates.templates.gatekeeper.sh >/dev/null 2>&1; then
  echo "ERROR: Gatekeeper is not installed in the cluster"
  echo "Run full validation only in a cluster where Gatekeeper CRDs are already available"
  exit 1
fi

kubectl apply -f "$ROOT_DIR/gatekeeper/constraint-templates"

kubectl wait --for=create --timeout=60s crd/k8sdenyprivileged.constraints.gatekeeper.sh
kubectl wait --for=create --timeout=60s crd/k8sdenyhostpath.constraints.gatekeeper.sh
kubectl wait --for=create --timeout=60s crd/k8senforcenonrootreadonly.constraints.gatekeeper.sh

kubectl apply -f "$ROOT_DIR/gatekeeper/constraints"

ENFORCE_LEVEL="$(kubectl get ns audit-zone -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')"
if [[ "$ENFORCE_LEVEL" != "restricted" ]]; then
  echo "ERROR: audit-zone is not labeled with PodSecurity restricted"
  exit 1
fi

kubectl get -f "$ROOT_DIR/gatekeeper/constraint-templates/privileged.yaml" >/dev/null
kubectl get -f "$ROOT_DIR/gatekeeper/constraint-templates/hostpath.yaml" >/dev/null
kubectl get -f "$ROOT_DIR/gatekeeper/constraint-templates/runasnonroot.yaml" >/dev/null

kubectl get -f "$ROOT_DIR/gatekeeper/constraints/privileged.yaml" >/dev/null
kubectl get -f "$ROOT_DIR/gatekeeper/constraints/hostpath.yaml" >/dev/null
kubectl get -f "$ROOT_DIR/gatekeeper/constraints/runasnonroot.yaml" >/dev/null

bash "$ROOT_DIR/verify/verify-admission.sh"

echo "Security validation passed"
