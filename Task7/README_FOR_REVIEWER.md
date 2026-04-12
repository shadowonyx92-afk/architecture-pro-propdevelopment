# Task7. PSP / PodSecurity / OPA Gatekeeper

- `01-create-namespace.yaml` — namespace `audit-zone` с `PodSecurity restricted`
- `02-insecure-pods.yaml` — три небезопасных pod
- `03-secure-pods.yaml` — три исправленных pod
- `04-gatekeeper-templates.yaml` — три шаблона политик
- `05-gatekeeper-constraints.yaml` — три ограничения для `audit-zone`
- `06-verify.sh` — единый скрипт проверки

## Запуск

```bash
bash 06-verify.sh
```
