#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/certs"
mkdir -p "$CERTS_DIR"

CA_CRT="${MINIKUBE_CA_CRT:-$HOME/.minikube/ca.crt}"
CA_KEY="${MINIKUBE_CA_KEY:-$HOME/.minikube/ca.key}"
CLUSTER_NAME="${KUBE_CLUSTER_NAME:-$(kubectl config view --minify -o jsonpath='{.contexts[0].context.cluster}')}"

if [[ ! -f "$CA_CRT" || ! -f "$CA_KEY" ]]; then
  echo "Minikube CA files were not found."
  echo "Set MINIKUBE_CA_CRT and MINIKUBE_CA_KEY explicitly if needed."
  exit 1
fi

create_user() {
  local username="$1"
  local group="$2"
  local namespace="${3:-}"

  local key_file="$CERTS_DIR/${username}.key"
  local csr_file="$CERTS_DIR/${username}.csr"
  local crt_file="$CERTS_DIR/${username}.crt"

  openssl genrsa -out "$key_file" 2048 >/dev/null 2>&1
  openssl req -new -key "$key_file" -out "$csr_file" -subj "/CN=${username}/O=${group}" >/dev/null 2>&1
  openssl x509 -req -in "$csr_file" -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial -out "$crt_file" -days 365 >/dev/null 2>&1

  kubectl config set-credentials "$username" \
    --client-certificate="$crt_file" \
    --client-key="$key_file" \
    --embed-certs=true >/dev/null

  if [[ -n "$namespace" ]]; then
    kubectl config set-context "${username}@${CLUSTER_NAME}" \
      --cluster="$CLUSTER_NAME" \
      --user="$username" \
      --namespace="$namespace" >/dev/null
  else
    kubectl config set-context "${username}@${CLUSTER_NAME}" \
      --cluster="$CLUSTER_NAME" \
      --user="$username" >/dev/null
  fi

  echo "Created user $username in group $group"
}

create_user "roman-reader" "readers" "propdev"
create_user "olga-crud" "crud-users" "propdev"
create_user "anna-admin" "admins"

echo "Users and kubeconfig contexts were created in $CERTS_DIR"
