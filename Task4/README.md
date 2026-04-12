# Task4. Защита доступа к кластеру Kubernetes

- `rbac-roles-matrix.md` — таблица ролей, полномочий и групп пользователей.
- `01-create-roles.sh` — создание namespace.
- `02-bind-users-to-roles.sh` — привязка групп пользователей к встроенным ролям Kubernetes.
- `03-create-users.sh` — создание тестовых пользователей через client certificates и kubeconfig contexts.

## Порядок запуска

```bash
bash 01-create-roles.sh
bash 02-bind-users-to-roles.sh
bash 03-create-users.sh
```
