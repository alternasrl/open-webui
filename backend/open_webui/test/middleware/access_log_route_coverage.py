from __future__ import annotations

import json
from fastapi.routing import APIRoute
from open_webui.main import app
from open_webui.middleware.access_log import _NIS2_ACTION_RULES

REQUIRED_ACTIONS = {
    ('GET', '/openai/models/{url_idx}/catalog'): 'MODEL_PROVIDER_CATALOG',
    ('POST', '/openai/models/{url_idx}/download'): 'MODEL_PROVIDER_DOWNLOAD',
    ('GET', '/openai/models/{url_idx}/download/status/{job_id}'): 'MODEL_PROVIDER_DOWNLOAD_STATUS',
    ('POST', '/openai/models/{url_idx}/load'): 'MODEL_PROVIDER_LOAD',
    ('POST', '/openai/models/{url_idx}/unload'): 'MODEL_PROVIDER_UNLOAD',
    ('GET', '/openai/models/{url_idx}/sse'): 'MODEL_PROVIDER_SSE',
    ('POST', '/api/v1/retrieval/process/url'): 'RETRIEVAL_PROCESS_URL',
    ('POST', '/api/v1/memories/reindex'): 'MEMORY_REINDEX',
    ('GET', '/ollama/v1/models/{url_idx}'): 'OLLAMA_COMPAT_MODELS_READ',
    ('GET', '/ollama/api/tags/{url_idx}'): 'OLLAMA_COMPAT_TAGS_READ',
    ('GET', '/ollama/api/version/{url_idx}'): 'OLLAMA_COMPAT_VERSION_READ',
}


def classify_route(method: str, path: str) -> str:
    for pattern, rule_method, action in _NIS2_ACTION_RULES:
        if rule_method is not None and method != rule_method:
            continue
        if pattern.search(path):
            return action
    return '-'


def dependency_names(route: APIRoute) -> set[str]:
    names = set()
    for dependency in route.dependant.dependencies:
        call = getattr(dependency, 'call', None)
        name = getattr(call, '__name__', None)
        if name:
            names.add(name)
    return names


def iter_runtime_routes() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        for method in sorted((route.methods or set()) - {'HEAD', 'OPTIONS'}):
            rows.append(
                {
                    'method': method,
                    'path': route.path,
                    'action': classify_route(method, route.path),
                    'dependencies': sorted(dependency_names(route)),
                }
            )
    return sorted(rows, key=lambda row: (row['path'], row['method']))


def main() -> None:
    rows = iter_runtime_routes()
    row_map = {(row['method'], row['path']): row for row in rows}

    mismatches = []
    for key, expected_action in REQUIRED_ACTIONS.items():
        row = row_map.get(key)
        if row is None:
            mismatches.append({'route': key, 'problem': 'missing runtime route'})
            continue
        if row['action'] != expected_action:
            mismatches.append({'route': key, 'expected': expected_action, 'actual': row['action']})

    admin_only_routes = {
        ('GET', '/ollama/v1/models/{url_idx}'),
        ('GET', '/ollama/api/tags/{url_idx}'),
        ('GET', '/ollama/api/version/{url_idx}'),
    }
    admin_dependency_issues = []
    for key in admin_only_routes:
        row = row_map[key]
        if 'get_admin_user' not in row['dependencies']:
            admin_dependency_issues.append({'route': key, 'dependencies': row['dependencies']})

    dead_rules = []
    for pattern, method, action in _NIS2_ACTION_RULES:
        if action in {'READ', 'WRITE_OTHER', 'DELETE_OTHER', '-'}:
            continue
        if not any((method is None or row['method'] == method) and pattern.search(row['path']) for row in rows):
            dead_rules.append({'method': method, 'pattern': pattern.pattern, 'action': action})

    report = {
        'mismatches': mismatches,
        'admin_dependency_issues': admin_dependency_issues,
        'dead_rules': dead_rules,
    }
    print(json.dumps(report, indent=2))
    if mismatches or admin_dependency_issues or dead_rules:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
