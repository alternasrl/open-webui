"""LLM prompt builder for cluster label generation.

Generates a prompt asking an LLM to produce an Italian label of max 5 words
from cluster keywords only — never from raw prompt text.
"""

from __future__ import annotations


def build_cluster_label_prompt(keywords: list[str]) -> str:
    """Build an LLM prompt for generating an Italian cluster label.

    The LLM receives only keywords — never original user prompt text —
    to prevent personal data leakage.

    Args:
        keywords: Cluster keywords (only the first 10 are used).

    Returns:
        A prompt string for the LLM.
    """
    top_keywords = keywords[:10]
    return (
        "Generate an Italian label of max 5 words that describes the following keywords. "
        "Do not include personal data or sensitive information. "
        "Reply with the label only, no explanation. "
        f"Keywords: {', '.join(top_keywords)}"
    )
