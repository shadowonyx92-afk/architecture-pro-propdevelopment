# Task6. Аудит активности пользователей и обнаружение инцидентов

- `audit-policy.yaml` — политика аудита из условия задания.
- `simulate-incident.sh` — симуляция подозрительных действий.
- `filter-audit-log.py` — генерация `audit-extract.json` и `analysis.md`.

## Запуск

```bash
bash simulate-incident.sh
python3 filter-audit-log.py audit.log --json-output audit-extract.json --report-output analysis.md
```
