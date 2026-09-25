from __future__ import annotations

import asyncio
import inspect
import json
from types import SimpleNamespace
from fastapi.routing import APIRoute
from open_webui.env import ENABLE_SCIM
from open_webui.main import app
from open_webui.middleware.access_log import _NIS2_ACTION_RULES
from starlette.exceptions import HTTPException as StarletteHTTPException

REQUIRED_ACTIONS = {
    ('GET', '/openai/models/{url_idx}/catalog'): 'MODEL_PROVIDER_CATALOG',
    ('GET', '/openai/models/{url_idx}'): 'MODEL_PROVIDER_LIST',
    ('POST', '/openai/models/{url_idx}/download'): 'MODEL_PROVIDER_DOWNLOAD',
    ('GET', '/openai/models/{url_idx}/download/status/{job_id}'): 'MODEL_PROVIDER_DOWNLOAD_STATUS',
    ('POST', '/openai/models/{url_idx}/load'): 'MODEL_PROVIDER_LOAD',
    ('POST', '/openai/models/{url_idx}/unload'): 'MODEL_PROVIDER_UNLOAD',
    ('GET', '/openai/models/{url_idx}/sse'): 'MODEL_PROVIDER_SSE',
    ('POST', '/api/v1/retrieval/process/url'): 'RETRIEVAL_PROCESS_URL',
    ('POST', '/api/v1/images/verify'): 'CONFIG_IMAGES_VERIFY',
    ('POST', '/api/v1/configs/suggestions'): 'CONFIG_SUGGESTIONS',
    ('GET', '/api/v1/models/all'): 'MODEL_LIST_ALL',
    ('GET', '/api/v1/models/export'): 'DATA_EXPORT',
    ('GET', '/api/v1/folders/{id}'): 'FOLDER_ACCESS_READ',
    ('GET', '/api/v1/folders/shared'): 'FOLDER_SHARED_READ',
    ('POST', '/api/v1/memories/reindex'): 'MEMORY_REINDEX',
    ('GET', '/ollama/v1/models/{url_idx}'): 'OLLAMA_COMPAT_MODELS_READ',
    ('GET', '/ollama/api/tags/{url_idx}'): 'OLLAMA_COMPAT_TAGS_READ',
    ('GET', '/ollama/api/version/{url_idx}'): 'OLLAMA_COMPAT_VERSION_READ',
}

REMOVED_ROUTES = {
    ('GET', '/api/v1/images/config/url/verify'),
    ('POST', '/api/v1/utils/pdf'),
}

ABSENT_RULE_PATTERNS = {
    ('GET', r'^/api/v1/images/config/url/verify$'),
    ('POST', r'^/api/v1/utils/pdf$'),
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
                    'endpoint': route.endpoint,
                }
            )
    return sorted(rows, key=lambda row: (row['path'], row['method']))


def _exercise_inline_admin_guard(endpoint):
    async def scenario():
        try:
            await endpoint(
                request=SimpleNamespace(),
                url_idx=0,
                user=SimpleNamespace(role='user'),
            )
        except Exception as exc:
            return exc
        return None

    return asyncio.run(scenario())


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

    removed_routes = []
    for key in REMOVED_ROUTES:
        if key in row_map:
            removed_routes.append({'route': key, 'problem': 'legacy runtime route still registered'})

    mutating_generic_issues = []
    for key in REQUIRED_ACTIONS:
        method, _ = key
        if method not in {'POST', 'PUT', 'PATCH', 'DELETE'}:
            continue
        row = row_map.get(key)
        if row is None:
            continue
        if row['action'] in {'WRITE_OTHER', 'DELETE_OTHER'}:
            mutating_generic_issues.append(
                {
                    'route': key,
                    'problem': 'mutating route fell through to catch-all classification',
                    'actual': row['action'],
                }
            )

    legacy_rule_issues = []
    for method, pattern_text in ABSENT_RULE_PATTERNS:
        if any(rule_method == method and pattern.pattern == pattern_text for pattern, rule_method, _ in _NIS2_ACTION_RULES):
            legacy_rule_issues.append({'method': method, 'pattern': pattern_text})

    admin_only_routes = {
        ('GET', '/openai/models/{url_idx}'),
        ('GET', '/ollama/v1/models/{url_idx}'),
        ('GET', '/ollama/api/tags/{url_idx}'),
        ('GET', '/ollama/api/version/{url_idx}'),
    }
    admin_behavior_issues = []
    for key in admin_only_routes:
        row = row_map[key]
        source = inspect.getsource(row['endpoint'])
        has_inline_admin_guard = 'url_idx is not None' in source and "user.role != 'admin'" in source
        if not has_inline_admin_guard:
            admin_behavior_issues.append({'route': key, 'problem': 'missing inline admin guard in source'})
            continue
        exc = _exercise_inline_admin_guard(row['endpoint'])
        if not isinstance(exc, StarletteHTTPException) or exc.status_code != 401:
            admin_behavior_issues.append(
                {
                    'route': key,
                    'problem': 'inline admin guard did not reject non-admin at runtime',
                    'exception': repr(exc),
                }
            )

    dead_rules = []
    for pattern, method, action in _NIS2_ACTION_RULES:
        if not ENABLE_SCIM and action.startswith('SCIM_'):
            continue
        if action in {'READ', 'WRITE_OTHER', 'DELETE_OTHER', '-'}:
            continue
        if not any((method is None or row['method'] == method) and pattern.search(row['path']) for row in rows):
            dead_rules.append({'method': method, 'pattern': pattern.pattern, 'action': action})

    report = {
        'mismatches': mismatches,
        'removed_routes': removed_routes,
        'mutating_generic_issues': mutating_generic_issues,
        'legacy_rule_issues': legacy_rule_issues,
        'admin_behavior_issues': admin_behavior_issues,
        'dead_rules': dead_rules,
    }
    print(json.dumps(report, indent=2, default=str))
    if mismatches or removed_routes or mutating_generic_issues or legacy_rule_issues or admin_behavior_issues or dead_rules:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
