"""Clusterer for prompt-insights analytics.

Wraps HDBSCAN to cluster pre-computed embeddings and report noise indices.
"""

from __future__ import annotations

import numpy as np


def cluster_embeddings(
    embeddings: list[list[float]],
    min_cluster_size: int = 5,
) -> tuple[list[int], set[int]]:
    """Cluster embeddings with HDBSCAN.

    Args:
        embeddings: List of embedding vectors.
        min_cluster_size: Minimum cluster size (default 5).

    Returns:
        Tuple of (labels, noise_indices) where labels is a list of integer
        cluster assignments (-1 = noise) and noise_indices is the set of
        positional indices assigned to noise.
    """
    import hdbscan  # noqa: PLC0415

    X = np.array(embeddings, dtype=np.float32)
    clusterer = hdbscan.HDBSCAN(min_cluster_size=min_cluster_size)
    labels: list[int] = clusterer.fit_predict(X).tolist()
    noise_indices: set[int] = {i for i, lbl in enumerate(labels) if lbl == -1}
    return labels, noise_indices
