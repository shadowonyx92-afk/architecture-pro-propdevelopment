#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

kubectl apply -f "$ROOT_DIR/01-create-namespace.yaml"

echo "Checking insecure pods are rejected..."
if kubectl apply --dry-run=server -f "$ROOT_DIR/02-insecure-pods.yaml" >/tmp/task7-verify.out 2>&1; then
  echo "ERROR: insecure pods were accepted"
  cat /tmp/task7-verify.out
  exit 1
fi
echo "Rejected as expected"

echo "Checking secure pods are accepted..."
if ! kubectl apply --dry-run=server -f "$ROOT_DIR/03-secure-pods.yaml" >/tmp/task7-verify.out 2>&1; then
  echo "ERROR: secure pods were rejected"
  cat /tmp/task7-verify.out
  exit 1
fi
echo "Accepted as expected"

if kubectl get crd constrainttemplates.templates.gatekeeper.sh >/dev/null 2>&1; then
  echo "Gatekeeper detected, applying templates and constraints..."
  kubectl apply -f "$ROOT_DIR/04-gatekeeper-templates.yaml"
  kubectl apply -f "$ROOT_DIR/05-gatekeeper-constraints.yaml"
  echo "Gatekeeper manifests applied"
else
  echo "Gatekeeper is not installed, skipped templates and constraints"
fi

echo "Task7 verification passed"
