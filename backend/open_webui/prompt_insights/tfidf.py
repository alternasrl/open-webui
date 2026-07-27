"""TF-IDF keyword extractor for prompt-insights analytics.

Extracts the top-N keywords per cluster from the cluster's texts.
Noise points (label == -1) are excluded.
"""

from __future__ import annotations

from collections import defaultdict

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer


def extract_cluster_keywords(
    texts: list[str],
    labels: list[int],
    top_n: int = 10,
) -> dict[int, list[str]]:
    """Return top-N TF-IDF keywords for each non-noise cluster.

    Args:
        texts: One text per data point (parallel to *labels*).
        labels: Cluster label per point; -1 means noise.
        top_n: Number of keywords to return per cluster.

    Returns:
        Mapping {cluster_id: [keyword, ...]} for every cluster_id != -1.
    """
    cluster_texts: dict[int, list[str]] = defaultdict(list)
    for text, label in zip(texts, labels):
        if label != -1:
            cluster_texts[label].append(text)

    if not cluster_texts:
        return {}

    cluster_ids = sorted(cluster_texts)
    corpus = [" ".join(cluster_texts[cid]) for cid in cluster_ids]

    vectorizer = TfidfVectorizer(
        analyzer="word",
        token_pattern=r"(?u)\b\w+\b",
        sublinear_tf=True,
    )
    tfidf_matrix = vectorizer.fit_transform(corpus)
    feature_names: list[str] = vectorizer.get_feature_names_out().tolist()

    result: dict[int, list[str]] = {}
    for row_idx, cid in enumerate(cluster_ids):
        row = np.asarray(tfidf_matrix[row_idx].todense()).flatten()
        top_indices = row.argsort()[-top_n:][::-1]
        result[cid] = [feature_names[i] for i in top_indices if row[i] > 0]

    return result
