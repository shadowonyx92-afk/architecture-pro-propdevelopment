# Task7. PSP / PodSecurity / OPA Gatekeeper

- `01-create-namespace.yaml` — namespace `audit-zone` с `PodSecurity restricted`
- `insecure-manifests/` — небезопасные pod
- `secure-manifests/` — исправленные pod
- `gatekeeper/` — templates и constraints
- `verify/` — скрипты проверки
- `audit-policy.yaml` — пример политики аудита

## Запуск

```bash
kubectl apply -f 01-create-namespace.yaml
bash verify/verify-admission.sh
```

Полная проверка:

```bash
bash verify/validate-security.sh
```
