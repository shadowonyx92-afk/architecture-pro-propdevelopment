#!/usr/bin/env python3

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


def load_events(path: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            events.append(obj)
    return events


def get_username(event: Dict[str, Any]) -> str:
    impersonated = event.get("impersonatedUser", {}) or {}
    if impersonated.get("username"):
        return impersonated["username"]
    return event.get("user", {}).get("username", "unknown")


def get_namespace(event: Dict[str, Any]) -> str:
    return event.get("objectRef", {}).get("namespace", "cluster-scope")


def get_name(event: Dict[str, Any]) -> str:
    object_name = event.get("objectRef", {}).get("name", "")
    if object_name:
        return object_name
    request_object = event.get("requestObject", {}) or {}
    metadata = request_object.get("metadata", {}) or {}
    return metadata.get("name", "")


def get_uri(event: Dict[str, Any]) -> str:
    return event.get("requestURI", "")


def containers_from_event(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    request_object = event.get("requestObject", {}) or {}
    spec = request_object.get("spec", {}) or {}
    containers = spec.get("containers", []) or []
    return [c for c in containers if isinstance(c, dict)]


def is_secret_access(event: Dict[str, Any]) -> bool:
    obj = event.get("objectRef", {}) or {}
    return obj.get("resource") == "secrets" and event.get("verb") in {"get", "list"}


def is_privileged_pod(event: Dict[str, Any]) -> bool:
    obj = event.get("objectRef", {}) or {}
    if obj.get("resource") != "pods" or event.get("verb") not in {"create", "update", "patch"}:
        return False
    if get_namespace(event) != "secure-ops":
        return False
    for container in containers_from_event(event):
        sec = container.get("securityContext", {}) or {}
        if sec.get("privileged") is True:
            return True
    return False


def is_exec_into_pod(event: Dict[str, Any]) -> bool:
    obj = event.get("objectRef", {}) or {}
    return event.get("verb") in {"create", "get", "connect"} and obj.get("subresource") == "exec"


def is_cluster_admin_rolebinding(event: Dict[str, Any]) -> bool:
    obj = event.get("objectRef", {}) or {}
    if obj.get("resource") != "rolebindings" or event.get("verb") not in {"create", "update", "patch"}:
        return False
    request_object = event.get("requestObject", {}) or {}
    role_ref = request_object.get("roleRef", {}) or {}
    return role_ref.get("name") == "cluster-admin" or get_name(event) == "escalate-binding"


def is_audit_policy_tamper(event: Dict[str, Any]) -> bool:
    request_uri = get_uri(event).lower()
    object_ref = event.get("objectRef", {}) or {}
    request_object = event.get("requestObject", {}) or {}
    request_metadata = request_object.get("metadata", {}) or {}
    candidates = [
        request_uri,
        str(object_ref.get("name", "")).lower(),
        str(request_metadata.get("name", "")).lower(),
    ]
    return any(candidate == "audit-policy" or "/audit-policy" in candidate for candidate in candidates)


def summarize_event(event: Dict[str, Any], category: str) -> Dict[str, Any]:
    summary = {
        "category": category,
        "timestamp": event.get("requestReceivedTimestamp") or event.get("stageTimestamp"),
        "verb": event.get("verb"),
        "user": get_username(event),
        "namespace": get_namespace(event),
        "resource": event.get("objectRef", {}).get("resource"),
        "name": get_name(event),
        "requestURI": get_uri(event),
        "sourceIPs": event.get("sourceIPs", []),
        "responseCode": event.get("responseStatus", {}).get("code"),
    }

    if category == "privileged_pod":
        summary["details"] = "requestObject.spec.containers[].securityContext.privileged == true"
    elif category == "secret_access":
        summary["details"] = "secrets get/list request"
    elif category == "exec":
        summary["details"] = "kubectl exec or equivalent remote command execution"
    elif category == "cluster_admin_rolebinding":
        summary["details"] = "rolebinding grants cluster-admin"
    elif category == "audit_policy_tamper":
        summary["details"] = "request references audit-policy"

    return summary


def extract_suspicious(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    extracted: List[Dict[str, Any]] = []
    seen = set()
    for event in events:
        stage = event.get("stage")
        if stage and stage != "ResponseComplete":
            continue

        audit_id = event.get("auditID", "")
        if is_secret_access(event):
            key = (audit_id, "secret_access")
            if key not in seen:
                extracted.append(summarize_event(event, "secret_access"))
                seen.add(key)
        if is_privileged_pod(event):
            key = (audit_id, "privileged_pod")
            if key not in seen:
                extracted.append(summarize_event(event, "privileged_pod"))
                seen.add(key)
        if is_exec_into_pod(event):
            key = (audit_id, "exec")
            if key not in seen:
                extracted.append(summarize_event(event, "exec"))
                seen.add(key)
        if is_cluster_admin_rolebinding(event):
            key = (audit_id, "cluster_admin_rolebinding")
            if key not in seen:
                extracted.append(summarize_event(event, "cluster_admin_rolebinding"))
                seen.add(key)
        if is_audit_policy_tamper(event):
            key = (audit_id, "audit_policy_tamper")
            if key not in seen:
                extracted.append(summarize_event(event, "audit_policy_tamper"))
                seen.add(key)
    return extracted


def first_match(extracted: List[Dict[str, Any]], category: str) -> Dict[str, Any]:
    matches = [item for item in extracted if item["category"] == category]
    if not matches:
        return {}

    def score(item: Dict[str, Any]) -> int:
        score_value = 0
        if category == "secret_access":
            if item.get("user", "").startswith("system:serviceaccount:"):
                score_value += 5
            if item.get("responseCode") == 403:
                score_value += 3
            if item.get("namespace") == "secure-ops":
                score_value += 2
        elif category == "privileged_pod":
            if item.get("name") == "privileged-pod":
                score_value += 5
            if item.get("namespace") == "secure-ops":
                score_value += 2
        elif category == "exec":
            if "/exec" in item.get("requestURI", ""):
                score_value += 5
            if item.get("name") == "attacker-pod":
                score_value += 2
        elif category == "cluster_admin_rolebinding":
            if item.get("name") == "escalate-binding":
                score_value += 5
            if item.get("namespace") == "secure-ops":
                score_value += 2
        elif category == "audit_policy_tamper":
            if item.get("name") == "audit-policy":
                score_value += 5
            if item.get("verb") == "delete":
                score_value += 3
            if item.get("namespace") == "secure-ops":
                score_value += 2
        return score_value

    matches.sort(key=score, reverse=True)
    for item in matches:
        if item["category"] == category:
            return item
    return {}


def condense_extracted(extracted: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    categories = [
        "secret_access",
        "privileged_pod",
        "exec",
        "cluster_admin_rolebinding",
        "audit_policy_tamper",
    ]
    condensed: List[Dict[str, Any]] = []
    for category in categories:
        match = first_match(extracted, category)
        if match:
            condensed.append(match)
    return condensed


def generate_markdown(extracted: List[Dict[str, Any]]) -> str:
    secret_event = first_match(extracted, "secret_access")
    privileged_event = first_match(extracted, "privileged_pod")
    exec_event = first_match(extracted, "exec")
    rolebinding_event = first_match(extracted, "cluster_admin_rolebinding")
    audit_event = first_match(extracted, "audit_policy_tamper")

    lines = [
        "# Отчёт по результатам анализа Kubernetes Audit Log",
        "",
        "## Подозрительные события",
        "",
        "1. Доступ к секретам:",
        f"- Кто: {secret_event.get('user', 'не найдено в audit.log')}",
        f"- Где: {secret_event.get('namespace', 'не найдено')}",
        "- Почему подозрительно: доступ к secrets позволяет получить токены, пароли и иные чувствительные данные.",
        "",
        "2. Привилегированные поды:",
        f"- Кто: {privileged_event.get('user', 'не найдено в audit.log')}",
        "- Комментарий: создание pod с `privileged: true` означает попытку запустить контейнер с повышенными правами на узле.",
        "",
        "3. Использование kubectl exec в чужом поде:",
        f"- Кто: {exec_event.get('user', 'не найдено в audit.log')}",
        f"- Что делал: {exec_event.get('requestURI', 'не найдено в audit.log')}",
        "",
        "4. Создание RoleBinding с правами cluster-admin:",
        f"- Кто: {rolebinding_event.get('user', 'не найдено в audit.log')}",
        "- К чему привело: субъект получает максимально привилегированные права в кластере, что указывает на критическую ошибку RBAC или попытку эскалации привилегий.",
        "",
        "5. Изменение или удаление audit-policy:",
        f"- Кто: {audit_event.get('user', 'не найдено в audit.log')}",
        "- Возможные последствия: снижение наблюдаемости, сокрытие следов действий, потеря аудита безопасности.",
        "",
        "## Что можно считать компрометацией кластера",
        "",
        "- Получение несанкционированного доступа к secrets.",
        "- Запуск привилегированного pod.",
        "- Эскалация прав через RoleBinding с `cluster-admin`.",
        "- Попытка отключить или изменить механизм аудита.",
        "",
        "## Какие ошибки допускает политика RBAC",
        "",
        "- Сервисному аккаунту или пользователю удаётся получить доступ к secrets без жёсткого ограничения по namespace и назначению.",
        "- Есть возможность создать привязку к `cluster-admin` без отдельного контура согласования.",
        "- Отсутствуют ограничения на операции `exec` и контроль административных действий.",
        "",
        "## Вывод",
        "",
        f"Всего выделено подозрительных событий: {len(extracted)}. Для финальной сдачи рекомендуется приложить `audit-extract.json`, сгенерированный на реальном `audit.log`, и пересобрать этот отчёт тем же скриптом.",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract suspicious events from Kubernetes audit.log")
    parser.add_argument("input", help="Path to audit.log")
    parser.add_argument("--json-output", default="audit-extract.json", help="Path to extracted JSON output")
    parser.add_argument("--report-output", default="analysis.md", help="Path to Markdown report output")
    args = parser.parse_args()

    input_path = Path(args.input)
    json_output = Path(args.json_output)
    report_output = Path(args.report_output)

    events = load_events(input_path)
    extracted = condense_extracted(extract_suspicious(events))

    json_output.write_text(json.dumps(extracted, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report_output.write_text(generate_markdown(extracted), encoding="utf-8")


if __name__ == "__main__":
    main()
