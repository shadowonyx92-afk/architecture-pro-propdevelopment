# Task5. Управление трафиком внутри кластера Kubernetes

- `workloads.yaml` — namespace, 4 deployment и 4 service.
- `non-admin-api-allow.yaml` — сетевые политики для изоляции трафика.

## Как применить

```bash
kubectl apply -f workloads.yaml
kubectl wait --for=jsonpath='{.status.phase}'=Active namespace/task5-network --timeout=60s
kubectl apply -f non-admin-api-allow.yaml
```

## Как проверить

```bash
WGET_CMD='wget -qO- --timeout=2'

kubectl run test-frontend --rm -i -t --restart=Never --image=alpine:3.20 \
  -n task5-network --labels role=front-end,task=task5-network \
  -- sh -lc "$WGET_CMD http://front-end && $WGET_CMD http://back-end-api"
```

```bash
kubectl run test-admin-frontend --rm -i -t --restart=Never --image=alpine:3.20 \
  -n task5-network --labels role=admin-front-end,task=task5-network \
  -- sh -lc "$WGET_CMD http://admin-front-end && $WGET_CMD http://admin-back-end-api"
```

```bash
kubectl run test-cross-blocked --rm -i -t --restart=Never --image=alpine:3.20 \
  -n task5-network --labels role=front-end,task=task5-network \
  -- sh -lc "$WGET_CMD http://admin-back-end-api || echo blocked"
```

```bash
kubectl run test-unlabeled --rm -i -t --restart=Never --image=alpine:3.20 \
  -n task5-network \
  -- sh -lc "$WGET_CMD http://front-end || echo blocked"
```
