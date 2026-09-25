"""Pytest-collected wrapper around the NIS2 access-log route coverage guard.

`access_log_route_coverage.py` is intentionally not named `test_*` so it can
still be invoked directly as a standalone script (see `patches/README.md` /
the plan's Task 5 runtime-inventory step). This module imports its
`build_report()` and asserts on the same report so the guard also runs under
the normal pytest suite (and CI) instead of only when someone remembers to
run the script manually.
"""

from middleware.access_log_route_coverage import build_report


def test_route_coverage_report_has_no_issues():
    report = build_report()

    assert report['mismatches'] == [], report['mismatches']
    assert report['removed_routes'] == [], report['removed_routes']
    assert report['mutating_generic_issues'] == [], report['mutating_generic_issues']
    assert report['legacy_rule_issues'] == [], report['legacy_rule_issues']
    assert report['admin_behavior_issues'] == [], report['admin_behavior_issues']
    assert report['dead_rules'] == [], report['dead_rules']
