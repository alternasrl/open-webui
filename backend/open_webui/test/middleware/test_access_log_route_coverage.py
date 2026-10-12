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
from middleware.access_log_route_coverage import REQUIRED_ACTIONS, build_report
from open_webui.middleware.access_log import _classify_action


def test_route_coverage_report_has_no_issues():
    report = build_report()

    assert report['mismatches'] == [], report['mismatches']
    assert report['removed_routes'] == [], report['removed_routes']
    assert report['mutating_generic_issues'] == [], report['mutating_generic_issues']
    assert report['legacy_rule_issues'] == [], report['legacy_rule_issues']
    assert report['admin_behavior_issues'] == [], report['admin_behavior_issues']
    assert report['dead_rules'] == [], report['dead_rules']


@pytest.mark.parametrize(
    ('method', 'path', 'action'), [(method, path, action) for (method, path), action in REQUIRED_ACTIONS.items()]
)
def test_required_action_matches_concrete_route(method, path, action):
    path = re.sub(r'\{[^}]+\}', 'target', path)
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
