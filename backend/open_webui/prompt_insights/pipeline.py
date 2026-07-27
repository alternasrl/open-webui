"""Prompt Insights pipeline orchestrator.

Ties together PII scrubbing, embedding, clustering, keyword extraction,
and persistence.  Entry points for the scheduler:

    should_run_prompt_insights(now_ns, last_completed_ns, interval_hours) -> bool
    run_prompt_insights_if_due(app) -> None
    PromptInsightsPipeline(app).run(window_start, window_end) -> dict
"""

from __future__ import annotations

import logging
import os
import time
from typing import Optional

log = logging.getLogger(__name__)

_NS_PER_HOUR = 60 * 60 * 1_000_000_000


# ---------------------------------------------------------------------------
# Scheduler helpers
# ---------------------------------------------------------------------------


def should_run_prompt_insights(
    now_ns: int,
    last_completed_ns: Optional[int],
    interval_hours: int,
) -> bool:
    """Return True when the pipeline is due to run.

    Args:
        now_ns:           Current time in nanoseconds.
        last_completed_ns: Nanosecond timestamp of last successful run, or None.
        interval_hours:   Minimum hours between runs; 0 means "always run".
    """
    if last_completed_ns is None:
        return True
    if interval_hours == 0:
        return True
    elapsed_ns = now_ns - last_completed_ns
    return elapsed_ns > interval_hours * _NS_PER_HOUR


async def run_prompt_insights_if_due(app) -> None:
    """Check whether the pipeline is due and, if so, kick it off.

    Reads PROMPT_INSIGHTS_INTERVAL_HOURS (default 24).  Stores the
    last-completed timestamp on app.state to survive the process lifetime
    without a dedicated config table row.
    """
    try:
        interval_hours = int(os.getenv("PROMPT_INSIGHTS_INTERVAL_HOURS", "24"))
        now_ns = time.time_ns()
        last_ns: Optional[int] = getattr(app.state, "_prompt_insights_last_run_ns", None)

        if not should_run_prompt_insights(now_ns, last_ns, interval_hours):
            return

        # Cross-instance lock: the prompt_insights_run table is shared, so a
        # DB-level active-run check prevents multiple instances (whose in-memory
        # last-run timestamps are independent) from running concurrently and
        # producing duplicate clusters / double-counted trends.
        from open_webui.internal.db import get_async_db  # noqa: PLC0415
        from open_webui.models.prompt_insights import PromptInsightsRuns  # noqa: PLC0415

        async with get_async_db() as db:
            active = await PromptInsightsRuns.get_active_run(db=db)
            if active is not None:
                return

        # Compute window: previous run end (or 24h ago) → now (seconds)
        window_end = int(time.time())
        if last_ns is not None:
            window_start = last_ns // 1_000_000_000
        else:
            window_start = window_end - interval_hours * 3600

        pipeline = PromptInsightsPipeline(app)
        await pipeline.run(window_start, window_end)

        app.state._prompt_insights_last_run_ns = now_ns
    except Exception:
        log.exception("run_prompt_insights_if_due: unhandled error")


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------


class PromptInsightsPipeline:
    def __init__(self, app) -> None:
        self._app = app

    async def run(self, window_start: int, window_end: int) -> dict:
        """Execute the full prompt-insights pipeline for a time window.

        Args:
            window_start: Unix epoch seconds (inclusive).
            window_end:   Unix epoch seconds (inclusive).

        Returns:
            Summary dict with run_id, total_prompts, clusters_found, noise_count.
        """
        from open_webui.internal.db import get_async_db  # noqa: PLC0415
        from open_webui.models.prompt_insights import (  # noqa: PLC0415
            PromptInsightsRuns,
            PromptInsightsTable,
            _canonical_label_hash,
        )
        from open_webui.prompt_insights.clusterer import cluster_embeddings  # noqa: PLC0415
        from open_webui.prompt_insights.embedder import PromptInsightsEmbedder  # noqa: PLC0415
        from open_webui.prompt_insights.labeler import build_cluster_label_prompt  # noqa: PLC0415
        from open_webui.prompt_insights.pii_scrubber import scrub_pii  # noqa: PLC0415
        from open_webui.prompt_insights.tfidf import extract_cluster_keywords  # noqa: PLC0415

        # Defense-in-depth: the prompt_insights_run table is the cross-instance
        # lock. If any run is already in progress, bail out so concurrent
        # instances don't produce duplicate clusters / double-counted trends.
        async with get_async_db() as db:
            active = await PromptInsightsRuns.get_active_run(db=db)
            if active is not None:
                log.info("PromptInsights: run already active (%s); skipping", active.id)
                return {
                    "run_id": active.id,
                    "total_prompts": 0,
                    "clusters_found": 0,
                    "noise_count": 0,
                    "skipped": True,
                }

        async with get_async_db() as db:
            run = await PromptInsightsRuns.create_run(window_start, window_end, db=db)
            run_id = run.id

        try:
            # -- 1. Fetch user messages within the time window --
            records = await self._fetch_prompts(window_start, window_end)
            if not records:
                async with get_async_db() as db:
                    await PromptInsightsRuns.complete_run(run_id, 0, 0, 0, db=db)
                return {"run_id": run_id, "total_prompts": 0, "clusters_found": 0, "noise_count": 0}

            # -- 2. PII scrub --
            scrubbed_texts: list[str] = []
            for user_id, content in records:
                text = _extract_text(content)
                cleaned, _ = scrub_pii(text)
                scrubbed_texts.append(cleaned)

            # -- 3. Embed (with cache) --
            async with get_async_db() as db:
                embedder = PromptInsightsEmbedder()
                embeddings = await embedder.embed_texts(scrubbed_texts, db)

            # -- 4. Cluster --
            labels, noise_indices = cluster_embeddings(embeddings)

            # -- 5. Keywords → labels → persist clusters --
            keywords_by_cluster = extract_cluster_keywords(scrubbed_texts, labels)

            bucket = _time_bucket(window_start)
            cluster_ids = sorted(set(labels) - {-1})

            async with get_async_db() as db:
                for cid in cluster_ids:
                    keywords = keywords_by_cluster.get(cid, [])
                    label_prompt = build_cluster_label_prompt(keywords)
                    canonical_label = await self._generate_label(label_prompt, keywords)
                    label_hash = _canonical_label_hash(canonical_label)

                    cluster_size = sum(1 for lbl in labels if lbl == cid)

                    from open_webui.models.prompt_insights import PromptCluster  # noqa: PLC0415
                    cluster_row = PromptCluster(
                        run_id=run_id,
                        canonical_label=canonical_label,
                        canonical_label_hash=label_hash,
                        cluster_size=cluster_size,
                    )
                    db.add(cluster_row)
                    await db.flush()

                    await PromptInsightsTable.upsert_trend(
                        canonical_label_hash=label_hash,
                        bucket=bucket,
                        count=cluster_size,
                        run_id=run_id,
                        db=db,
                    )

                await db.commit()

            total_prompts = len(records)
            clusters_found = len(cluster_ids)
            noise_count = len(noise_indices)

            async with get_async_db() as db:
                await PromptInsightsRuns.complete_run(
                    run_id, total_prompts, clusters_found, noise_count, db=db
                )

            log.info(
                "PromptInsights run=%s window=[%s,%s] prompts=%d clusters=%d noise=%d",
                run_id, window_start, window_end, total_prompts, clusters_found, noise_count,
            )
            return {
                "run_id": run_id,
                "total_prompts": total_prompts,
                "clusters_found": clusters_found,
                "noise_count": noise_count,
            }

        except Exception as exc:
            log.exception("PromptInsights pipeline failed (run=%s)", run_id)
            try:
                async with get_async_db() as db:
                    await PromptInsightsRuns.fail_run(run_id, str(exc), db=db)
            except Exception:
                log.exception("PromptInsights: could not mark run as failed")
            raise

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _fetch_prompts(self, window_start: int, window_end: int) -> list[tuple[str, object]]:
        """Return (user_id, content) pairs for user messages in the window."""
        from open_webui.internal.db import get_async_db  # noqa: PLC0415
        from open_webui.models.chat_messages import ChatMessage  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        async with get_async_db() as db:
            result = await db.execute(
                select(ChatMessage.user_id, ChatMessage.content)
                .where(
                    ChatMessage.role == "user",
                    ChatMessage.created_at >= window_start,
                    ChatMessage.created_at <= window_end,
                )
                .order_by(ChatMessage.created_at.asc())
            )
            return list(result.all())

    async def _generate_label(self, prompt: str, keywords: list[str]) -> str:
        """Best-effort LLM label generation; falls back to top keywords."""
        try:
            from open_webui.utils.task import prompt_template  # noqa: PLC0415 - unused but keep import pattern

            models = getattr(getattr(self._app, "state", None), "MODELS", {})
            if not models:
                raise RuntimeError("no models available")

            # Pick first available model
            model_id = next(iter(models))
            from open_webui.routers.openai import generate_completion  # noqa: PLC0415

            # Lightweight single-turn completion
            response = await generate_completion(
                self._app,
                model_id=model_id,
                messages=[{"role": "user", "content": prompt}],
            )
            label = (response or "").strip()
            if label:
                return label
        except Exception:
            pass

        # Fallback: join first 3 keywords
        return " ".join(keywords[:3]) if keywords else "cluster"


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def _extract_text(content: object) -> str:
    """Extract plain text from a chat message content field.

    Content can be a bare string or a list of content blocks
    (OpenAI-style: [{"type": "text", "text": "..."}]).
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(str(block.get("text", "")))
            elif isinstance(block, str):
                parts.append(block)
        return " ".join(parts)
    return str(content) if content is not None else ""


def _time_bucket(window_start: int) -> str:
    """Return a YYYY-MM-DD bucket string for trend aggregation."""
    import datetime  # noqa: PLC0415

    return datetime.datetime.utcfromtimestamp(window_start).strftime("%Y-%m-%d")
