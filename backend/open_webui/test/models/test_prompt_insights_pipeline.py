import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[3]))

from open_webui.prompt_insights.pipeline import should_run_prompt_insights


def test_run_when_no_history():
    assert should_run_prompt_insights(10_000, None, 24) is True


def test_skip_before_interval():
    h = 60 * 60 * 1_000_000_000
    assert should_run_prompt_insights(10 * h, 9 * h, 24) is False


def test_run_after_interval():
    h = 60 * 60 * 1_000_000_000
    # now=25h, last=0h → elapsed=25h > 24h
    assert should_run_prompt_insights(25 * h, 0, 24) is True


def test_exact_boundary_is_not_due():
    h = 60 * 60 * 1_000_000_000
    # now=24h, last=0h → elapsed == interval → still not due (strict >)
    assert should_run_prompt_insights(24 * h, 0, 24) is False


def test_zero_interval_always_runs():
    """interval_hours=0 means 'always run'."""
    h = 60 * 60 * 1_000_000_000
    assert should_run_prompt_insights(1 * h, 0, 0) is True
