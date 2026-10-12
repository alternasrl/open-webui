import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[3]))

from open_webui.models.prompt_insights import (
    PromptInsightsRun,
    _canonical_label_hash,
    _normalize_cluster_label,
)


def test_label_normalization():
    assert _normalize_cluster_label('  Richieste   Fatture XML  ') == 'richieste fatture xml'


def test_hash_stability():
    assert _canonical_label_hash('Richieste fatture XML') == _canonical_label_hash(' richieste   FATTURE xml ')


def test_active_run_claim_has_named_unique_constraint():
    constraints = {
        constraint.name: tuple(constraint.columns.keys()) for constraint in PromptInsightsRun.__table__.constraints
    }

    assert constraints['uq_prompt_insights_run_active_claim'] == ('active_claim',)
