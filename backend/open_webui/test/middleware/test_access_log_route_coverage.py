"""Pytest-collected wrapper around the NIS2 access-log route coverage guard.

`access_log_route_coverage.py` is intentionally not named `test_*` so it can
still be invoked directly as a standalone script (see `patches/README.md` /
the plan's Task 5 runtime-inventory step). This module imports its
`build_report()` and asserts on the same report so the guard also runs under
the normal pytest suite (and CI) instead of only when someone remembers to
run the script manually.
"""

import re

import pytest
from fastapi.routing import APIRoute
from open_webui.middleware.access_log import _classify_action
from open_webui.middleware.audit_routes import ROUTE_POLICIES
from starlette.routing import Mount

from middleware.access_log_route_coverage import REQUIRED_ACTIONS, app, build_report, coverage_counts


def test_route_coverage_report_has_no_issues():
    report = build_report()

    assert report['mismatches'] == [], report['mismatches']
    assert report['removed_routes'] == [], report['removed_routes']
    assert report['mutating_generic_issues'] == [], report['mutating_generic_issues']
    assert report['legacy_rule_issues'] == [], report['legacy_rule_issues']
    assert report['classification_issues'] == [], report['classification_issues']
    assert report['admin_behavior_issues'] == [], report['admin_behavior_issues']
    assert report['dead_rules'] == [], report['dead_rules']
    assert report['mount_issues'] == [], report['mount_issues']
    counts = coverage_counts()
    assert counts['unclassified'] == 0
    assert counts['classified'] + counts['exempt'] == counts['total']


def test_new_opaque_business_mount_is_not_a_technical_exception(monkeypatch):
    async def business_app(scope, receive, send):
        pass

    monkeypatch.setattr(app.router, 'routes', [*app.routes, Mount('/business', business_app)])
    assert build_report()['mount_issues'] == [{'path': '/business', 'problem': 'unreviewed ASGI mount'}]


@pytest.mark.parametrize(
    ('method', 'path'),
    [
        ('GET', '/api/v1/new-business-read'),
        ('POST', '/api/v1/new-business-write'),
        # A legacy broad regex must not authorize a new business template.
        ('GET', '/api/v1/skills/id/{id}/history/new-business'),
        ('GET', '/openai/models/new-business/extra'),
    ],
)
def test_unknown_mounted_business_route_fails_guard(method, path, monkeypatch):
    async def endpoint():
        return {}

    monkeypatch.setattr(app.router, 'routes', [*app.routes, APIRoute(path, endpoint, methods=[method])])
    issues = build_report()['mutating_generic_issues']
    assert any(issue['route'] == (method, path) for issue in issues), issues


def test_catalog_loss_cannot_hide_behind_existing_regex(monkeypatch):
    monkeypatch.delitem(ROUTE_POLICIES, ('GET', '/api/v1/files/{id}/content'))
    assert any(
        issue['route'] == ('GET', '/api/v1/files/{id}/content') for issue in build_report()['mutating_generic_issues']
    )


@pytest.mark.parametrize(
    ('method', 'path', 'action'), [(method, path, action) for (method, path), action in REQUIRED_ACTIONS.items()]
)
@pytest.mark.parametrize('suffix', ['', '/'])
def test_required_action_matches_concrete_route(method, path, action, suffix):
    path = re.sub(r'\{[^}]+\}', 'target', path) + suffix
    classified, security = _classify_action(method, path)
    assert classified == action
    if action in {'WORKSPACE_HISTORY_READ', 'SKILL_FILE_READ', 'GROUP_MEMBERS_READ', 'TOOL_SPECS_READ'}:
        assert not security
    if action.startswith(
        (
            'AUTH_MFA_',
            'AUTH_SESSIONS_',
            'FUNCTION_HISTORY_',
            'FUNCTION_VERSION_',
            'TOOL_HISTORY_',
            'TOOL_VERSION_',
            'MODEL_HISTORY_',
            'MODEL_VERSION_',
            'SKILL_',
            'TERMINAL_CHAT_PROXY_',
        )
    ):
        assert security is (method != 'GET')
