from __future__ import annotations

import asyncio
import inspect
import json
import re
from types import SimpleNamespace

from fastapi.routing import APIRoute
from open_webui.env import ENABLE_SCIM
from open_webui.main import CORSStaticFiles, SPAStaticFiles, app, socket_app
from open_webui.middleware.access_log import _NIS2_ACTION_RULES, _classify_action
from open_webui.middleware.audit_routes import ROUTE_POLICIES, TECHNICAL_EXCEPTIONS
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

REQUIRED_ACTIONS = {
    ('GET', '/api/v1/apps'): 'APP_LIST_READ',
    ('GET', '/api/v1/apps/{app_id}'): 'APP_READ',
    ('POST', '/api/v1/apps/manifest/preview'): 'APP_MANIFEST_PREVIEW',
    ('POST', '/api/v1/apps'): 'APP_CREATE',
    ('PATCH', '/api/v1/apps/{app_id}'): 'APP_UPDATE',
    ('POST', '/api/v1/apps/{app_id}/connect'): 'APP_CONNECT',
    ('DELETE', '/api/v1/apps/{app_id}'): 'APP_DELETE',
    ('POST', '/api/v1/apps/{app_id}/interactions'): 'APP_INTERACTION',
    ('GET', '/api/v1/channels/{channel_id}/apps'): 'CHANNEL_APPS_READ',
    ('POST', '/api/v1/channels/{channel_id}/apps'): 'CHANNEL_APP_ADD',
    ('DELETE', '/api/v1/channels/{channel_id}/apps/{app_id}'): 'CHANNEL_APP_REMOVE',
    ('POST', '/api/v1/channels/{id}/members/mute'): 'CHANNEL_MEMBER_MUTE',
    ('POST', '/api/v1/channels/{id}/members/active'): 'CHANNEL_MEMBER_ACTIVE',
    ('POST', '/api/v1/channels/{id}/access/update'): 'CHANNEL_ACCESS_UPDATE',
    ('GET', '/api/v1/files/user/search'): 'FILES_SEARCH_READ',
    ('GET', '/api/v1/files/user/count'): 'FILES_COUNT_READ',
    ('GET', '/api/v1/search'): 'WORKSPACE_SEARCH_READ',
    ('PATCH', '/api/v1/chats/{id}/params'): 'CHAT_PARAMS_UPDATE',
    ('POST', '/api/v1/calendars/{calendar_id}/access/update'): 'CALENDAR_ACCESS_UPDATE',
    ('POST', '/api/v1/configs/interface/visibility'): 'INTERFACE_VISIBILITY_UPDATE',
    ('GET', '/oauth/clients/{client_id}/callback'): 'OAUTH_CLIENT_AUTHORIZE',
    ('POST', '/api/v1/auths/mfa/challenge'): 'AUTH_MFA_CHALLENGE',
    ('POST', '/api/v1/auths/mfa/enroll/start'): 'AUTH_MFA_ENROLL_START',
    ('POST', '/api/v1/auths/mfa/enroll/confirm'): 'AUTH_MFA_ENROLL_CONFIRM',
    ('POST', '/api/v1/auths/mfa/verify'): 'AUTH_MFA_VERIFY',
    ('POST', '/api/v1/auths/mfa/replace'): 'AUTH_MFA_REPLACE',
    ('POST', '/api/v1/auths/mfa/recover'): 'AUTH_MFA_RECOVER',
    ('POST', '/api/v1/auths/mfa/recovery/codes'): 'AUTH_MFA_RECOVERY_ROTATE',
    ('GET', '/api/v1/auths/mfa/status'): 'AUTH_MFA_STATUS',
    ('POST', '/api/v1/users/{user_id}/sessions/revoke'): 'AUTH_SESSIONS_REVOKE',
    ('DELETE', '/api/v1/functions/id/{id}/history/{history_id}'): 'FUNCTION_HISTORY_DELETE',
    ('POST', '/api/v1/functions/id/{id}/update/version'): 'FUNCTION_VERSION_RESTORE',
    ('DELETE', '/api/v1/tools/id/{id}/history/{history_id}'): 'TOOL_HISTORY_DELETE',
    ('POST', '/api/v1/tools/id/{id}/update/version'): 'TOOL_VERSION_RESTORE',
    ('DELETE', '/api/v1/models/model/history/{history_id}'): 'MODEL_HISTORY_DELETE',
    ('POST', '/api/v1/models/model/update/version'): 'MODEL_VERSION_RESTORE',
    ('DELETE', '/api/v1/skills/id/{id}/history/{history_id}'): 'SKILL_HISTORY_DELETE',
    ('POST', '/api/v1/skills/id/{id}/update/version'): 'SKILL_VERSION_RESTORE',
    ('POST', '/api/v1/skills/id/{id}/clone'): 'SKILL_CLONE',
    ('POST', '/api/v1/skills/import'): 'SKILL_IMPORT',
    ('POST', '/api/v1/skills/import/preview'): 'SKILL_IMPORT_PREVIEW',
    ('POST', '/api/v1/skills/load/url'): 'SKILL_URL_LOAD',
    ('GET', '/api/v1/skills/id/{id}/files'): 'SKILL_FILE_READ',
    ('GET', '/api/v1/skills/id/{id}/files/content'): 'SKILL_FILE_READ',
    ('GET', '/api/v1/groups/id/{id}/members'): 'GROUP_MEMBERS_READ',
    ('GET', '/api/v1/tools/id/{id}/specs'): 'TOOL_SPECS_READ',
    ('GET', '/api/v1/evaluations/leaderboard/{model_id:path}/history'): 'EVALUATION_LEADERBOARD_HISTORY_READ',
    ('POST', '/api/v1/terminals/{server_id}/chats/{chat_id}/{path:path}'): 'TERMINAL_CHAT_PROXY_WRITE',
    ('PUT', '/api/v1/terminals/{server_id}/chats/{chat_id}/{path:path}'): 'TERMINAL_CHAT_PROXY_WRITE',
    ('PATCH', '/api/v1/terminals/{server_id}/chats/{chat_id}/{path:path}'): 'TERMINAL_CHAT_PROXY_WRITE',
    ('DELETE', '/api/v1/terminals/{server_id}/chats/{chat_id}/{path:path}'): 'TERMINAL_CHAT_PROXY_DELETE',
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

for resource in ('functions', 'tools', 'skills', 'prompts'):
    identifier = '{prompt_id}' if resource == 'prompts' else '{id}'
    for suffix in ('history', 'history/diff', 'history/{history_id}'):
        REQUIRED_ACTIONS[('GET', f'/api/v1/{resource}/id/{identifier}/{suffix}')] = 'WORKSPACE_HISTORY_READ'
for suffix in ('history', 'history/{history_id}'):
    REQUIRED_ACTIONS[('GET', f'/api/v1/models/model/{suffix}')] = 'WORKSPACE_HISTORY_READ'
REQUIRED_ACTIONS[('GET', '/api/v1/skills/id/{id}/history/diff/file')] = 'WORKSPACE_HISTORY_READ'

REMOVED_ROUTES = {
    ('GET', '/api/v1/images/config/url/verify'),
    ('POST', '/api/v1/utils/pdf'),
}

ABSENT_RULE_PATTERNS = {
    ('GET', r'^/api/v1/images/config/url/verify$'),
    ('POST', r'^/api/v1/utils/pdf$'),
}


def classify_route(method: str, path: str) -> str:
    if (method, path) in TECHNICAL_EXCEPTIONS:
        return 'EXEMPT'
    policy = ROUTE_POLICIES.get((method, path))
    return policy.action if policy else 'UNCLASSIFIED'


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
        if not isinstance(route, Route):
            continue
        for method in sorted((route.methods or set()) - {'HEAD', 'OPTIONS'}):
            rows.append(
                {
                    'method': method,
                    'path': route.path,
                    'action': classify_route(method, route.path),
                    'dependencies': sorted(dependency_names(route)) if isinstance(route, APIRoute) else [],
                    'endpoint': route.endpoint,
                }
            )
    return sorted(rows, key=lambda row: (row['path'], row['method']))


def mount_issues() -> list[dict[str, str]]:
    """Opaque transports/assets are not business-route prefix exemptions.

    Only the exact mounted object/type + path below is exempt. Any additional
    application/router mount must be inspected, never silently skipped.
    """
    issues = []
    for route in app.routes:
        if not isinstance(route, Mount):
            continue
        if route.path == '/ws' and route.app is socket_app:
            continue  # Socket.IO's HTTP/WebSocket transport, not a REST router.
        if (route.path, type(route.app)) in {
            ('/static', StaticFiles),
            ('/pyodide', CORSStaticFiles),
            ('', SPAStaticFiles),
        }:
            continue  # Build assets and optional SPA fallback only.
        issues.append({'path': route.path, 'problem': 'unreviewed ASGI mount'})
    return issues


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


def build_report() -> dict[str, list]:
    """Build the route-coverage report without printing or exiting.

    Shared by the standalone script entry point (`main`) and the pytest test
    (`test_access_log_route_coverage.py`) so both execution paths exercise the
    exact same runtime guard.
    """
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

    # Exact template/method membership is mandatory for *all* business routes.
    # Even a new path that happens to match a legacy regex must fail closed.
    mutating_generic_issues = []
    for row in rows:
        if row['action'] not in {'READ', 'WRITE_OTHER', 'DELETE_OTHER', '-', 'UNCLASSIFIED'}:
            continue
        mutating_generic_issues.append(
            {
                'route': (row['method'], row['path']),
                'problem': 'business route has no explicit semantic policy',
                'actual': row['action'],
            }
        )

    legacy_rule_issues = []
    for method, pattern_text in ABSENT_RULE_PATTERNS:
        if any(
            rule_method == method and pattern.pattern == pattern_text for pattern, rule_method, _ in _NIS2_ACTION_RULES
        ):
            legacy_rule_issues.append({'method': method, 'pattern': pattern_text})

    classification_issues = []
    for row in rows:
        key = row['method'], row['path']
        policy = ROUTE_POLICIES.get(key)
        if not policy:
            continue
        concrete = re.sub(r'\{[^}]+\}', 'audit-target', row['path'])
        classified = _classify_action(row['method'], concrete)
        if classified != (policy.action, policy.security):
            classification_issues.append({'route': key, 'actual': classified, 'expected': policy})

    admin_only_routes = {
        ('GET', '/openai/models/{url_idx}'),
        ('GET', '/ollama/v1/models/{url_idx}'),
        ('GET', '/ollama/api/tags/{url_idx}'),
        ('GET', '/ollama/api/version/{url_idx}'),
        ('POST', '/ollama/verify'),
    }
    admin_behavior_issues = []
    for key in admin_only_routes:
        row = row_map[key]
        if key == ('POST', '/ollama/verify'):
            if 'get_admin_user' not in row['dependencies']:
                admin_behavior_issues.append({'route': key, 'problem': 'missing admin dependency'})
            continue
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

    dead_rules = [
        {'route': key, 'action': policy.action}
        for key, policy in ROUTE_POLICIES.items()
        if key not in row_map and not (not ENABLE_SCIM and '/scim/v2/' in key[1])
    ]

    report = {
        'mismatches': mismatches,
        'removed_routes': removed_routes,
        'mutating_generic_issues': mutating_generic_issues,
        'legacy_rule_issues': legacy_rule_issues,
        'classification_issues': classification_issues,
        'admin_behavior_issues': admin_behavior_issues,
        'dead_rules': dead_rules,
        'mount_issues': mount_issues(),
    }
    return report


def coverage_counts() -> dict[str, int]:
    rows = iter_runtime_routes()
    exempt = sum(row['action'] == 'EXEMPT' for row in rows)
    unclassified = sum(row['action'] in {'UNCLASSIFIED', 'READ', 'WRITE_OTHER', 'DELETE_OTHER', '-'} for row in rows)
    return {
        'total': len(rows),
        'classified': len(rows) - exempt - unclassified,
        'exempt': exempt,
        'unclassified': unclassified,
    }


def main() -> None:
    report = build_report()
    print(json.dumps(report, indent=2, default=str))
    print(json.dumps(coverage_counts(), sort_keys=True))
    if any(report.values()):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
