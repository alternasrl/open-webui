import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[3]))

import pytest

try:
    import hdbscan  # noqa: F401
    import sklearn  # noqa: F401

    _ml_available = True
except ImportError:
    _ml_available = False

requires_ml = pytest.mark.skipif(not _ml_available, reason='hdbscan and scikit-learn required')


@requires_ml
def test_noise_detection():
    from open_webui.prompt_insights.clusterer import cluster_embeddings

    labels, noise = cluster_embeddings([[0, 0], [0.1, 0], [0, 0.1], [9, 9]], min_cluster_size=2)
    assert 3 in noise


@requires_ml
def test_all_noise_returns_empty_cluster_set():
    from open_webui.prompt_insights.clusterer import cluster_embeddings

    labels, noise = cluster_embeddings([[0, 0], [9, 9]], min_cluster_size=5)
    assert set(labels) == {-1}
    assert noise == {0, 1}


@requires_ml
def test_cluster_embeddings_returns_label_per_point():
    from open_webui.prompt_insights.clusterer import cluster_embeddings

    embeddings = [[float(i), 0.0] for i in range(10)]
    labels, noise = cluster_embeddings(embeddings, min_cluster_size=2)
    assert len(labels) == 10


@requires_ml
def test_keywords_per_cluster():
    from open_webui.prompt_insights.tfidf import extract_cluster_keywords

    kws = extract_cluster_keywords(
        ['fattura xml pa', 'fattura xml schema', 'marketing social ads', 'marketing copy social'],
        [0, 0, 1, 1],
        top_n=2,
    )
    assert 'fattura' in kws[0]
    assert 'marketing' in kws[1]


@requires_ml
def test_keywords_ignores_noise_label():
    from open_webui.prompt_insights.tfidf import extract_cluster_keywords

    kws = extract_cluster_keywords(
        ['noise text random', 'fattura xml pa', 'fattura xml schema'],
        [-1, 0, 0],
        top_n=2,
    )
    assert -1 not in kws
    assert 'fattura' in kws[0]


def test_labeler_prompt_contains_keywords():
    from open_webui.prompt_insights.labeler import build_cluster_label_prompt

    prompt = build_cluster_label_prompt(['fattura', 'xml', 'pa'])
    assert 'fattura' in prompt
    assert 'xml' in prompt
    assert 'Italian' in prompt or 'italiano' in prompt.lower()


def test_labeler_prompt_privacy_instruction():
    from open_webui.prompt_insights.labeler import build_cluster_label_prompt

    prompt = build_cluster_label_prompt(['keyword'])
    assert 'personal' in prompt.lower() or 'dati' in prompt.lower()


def test_labeler_limits_keywords_to_ten():
    from open_webui.prompt_insights.labeler import build_cluster_label_prompt

    many = [f'kw{i}' for i in range(20)]
    prompt = build_cluster_label_prompt(many)
    # only first 10 should appear
    assert 'kw10' not in prompt
    assert 'kw9' in prompt
