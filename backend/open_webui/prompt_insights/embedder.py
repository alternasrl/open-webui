"""Azure OpenAI text embedder with DB-backed cache for prompt-insights analytics.

Checks `prompt_embedding_cache` before calling the Azure API; stores results
with a 7-day TTL.  Uses the same RAG Azure OpenAI credentials configured in
`open_webui.config`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger(__name__)

_EMBEDDING_MODEL = "text-embedding-3-small"
_CACHE_TTL_SECONDS = 7 * 24 * 60 * 60  # 7 days


def _text_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class PromptInsightsEmbedder:
    """Produces embeddings for prompt-insights analytics.

    Uses Azure OpenAI ``text-embedding-3-small`` with a DB-backed cache
    (``prompt_embedding_cache`` table, 7-day TTL).

    Credentials are read from environment variables via ``open_webui.config``:
    - ``RAG_AZURE_OPENAI_BASE_URL``
    - ``RAG_AZURE_OPENAI_API_KEY``
    - ``RAG_AZURE_OPENAI_API_VERSION``
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        api_version: Optional[str] = None,
        model: str = _EMBEDDING_MODEL,
    ) -> None:
        if base_url is None or api_key is None or api_version is None:
            try:
                from open_webui import config as _cfg  # noqa: PLC0415

                base_url = base_url or _cfg.RAG_AZURE_OPENAI_BASE_URL
                api_key = api_key or _cfg.RAG_AZURE_OPENAI_API_KEY
                api_version = api_version or _cfg.RAG_AZURE_OPENAI_API_VERSION
            except Exception:
                pass

        self._base_url: str = (base_url or "").rstrip("/")
        self._api_key: str = api_key or ""
        self._api_version: str = api_version or ""
        self._model: str = model

    async def embed_texts(
        self,
        texts: list[str],
        db: AsyncSession,
    ) -> list[list[float]]:
        """Return embeddings for *texts*, using the cache where possible.

        Args:
            texts: Texts to embed (should already be PII-scrubbed).
            db: Active SQLAlchemy async session for cache read/write.

        Returns:
            Embedding vector per input text, in the same order.
        """
        from open_webui.models.prompt_insights import PromptEmbeddingCache  # noqa: PLC0415

        hashes = [_text_hash(t) for t in texts]
        now = int(time.time())

        # -- Load cached embeddings --
        cached_rows = (
            await db.execute(
                select(PromptEmbeddingCache).where(
                    PromptEmbeddingCache.text_hash.in_(hashes),
                    PromptEmbeddingCache.expires_at > now,
                )
            )
        ).scalars().all()

        cache: dict[str, list[float]] = {}
        for row in cached_rows:
            if row.embedding:
                cache[row.text_hash] = json.loads(row.embedding)

        # -- Identify texts that need API calls --
        missing_indices = [i for i, h in enumerate(hashes) if h not in cache]
        missing_texts = [texts[i] for i in missing_indices]

        if missing_texts:
            new_embeddings = await self._call_azure_api(missing_texts)
            expires_at = now + _CACHE_TTL_SECONDS
            for i, (text, embedding) in enumerate(zip(missing_texts, new_embeddings)):
                h = hashes[missing_indices[i]]
                cache[h] = embedding
                row = PromptEmbeddingCache(
                    text_hash=h,
                    embedding=json.dumps(embedding),
                    expires_at=expires_at,
                )
                await db.merge(row)
            await db.flush()

        return [cache[h] for h in hashes]

    async def _call_azure_api(self, texts: list[str]) -> list[list[float]]:
        """Call Azure OpenAI embeddings endpoint and return vectors."""
        import aiohttp  # noqa: PLC0415

        url = (
            f"{self._base_url}/openai/deployments/{self._model}"
            f"/embeddings?api-version={self._api_version}"
        )
        headers = {
            "Content-Type": "application/json",
            "api-key": self._api_key,
        }
        payload = {"input": texts}

        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=payload) as resp:
                resp.raise_for_status()
                data = await resp.json()

        if "data" not in data:
            raise ValueError(f"Unexpected Azure OpenAI embeddings response: {list(data.keys())}")

        # Azure returns items in the same order as input
        items = sorted(data["data"], key=lambda x: x.get("index", 0))
        return [item["embedding"] for item in items]
