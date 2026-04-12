#!/usr/bin/env bash

set -euo pipefail

cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: propdev
EOF

echo "Namespace propdev was created"
