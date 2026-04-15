#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

kubectl apply -f "$ROOT_DIR/01-create-namespace.yaml"

echo "Checking insecure manifests are rejected in audit-zone..."
for manifest in "$ROOT_DIR"/insecure-manifests/*.yaml; do
  if kubectl apply --dry-run=server -f "$manifest" >/tmp/task7-verify.out 2>&1; then
    echo "ERROR: $(basename "$manifest") was accepted but should be rejected"
    cat /tmp/task7-verify.out
    exit 1
  fi
  echo "Rejected as expected: $(basename "$manifest")"
done

echo "Checking secure manifests are accepted..."
for manifest in "$ROOT_DIR"/secure-manifests/*.yaml; do
  if ! kubectl apply --dry-run=server -f "$manifest" >/tmp/task7-verify.out 2>&1; then
    echo "ERROR: $(basename "$manifest") was rejected but should be accepted"
    cat /tmp/task7-verify.out
    exit 1
  fi
  echo "Accepted as expected: $(basename "$manifest")"
done

echo "Admission verification passed"
