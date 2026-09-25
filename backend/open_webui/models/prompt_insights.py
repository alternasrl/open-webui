import hashlib
import time
import uuid
from contextlib import asynccontextmanager
from typing import Optional

from pydantic import BaseModel, ConfigDict
from sqlalchemy import BigInteger, Column, ForeignKey, Index, String, Text, UniqueConstraint, insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import declarative_base

try:
    from open_webui.internal.db import Base, get_async_db_context
except Exception:  # pragma: no cover - fallback for isolated tests
    Base = declarative_base()

    @asynccontextmanager
    async def get_async_db_context(db: Optional[AsyncSession] = None):
        if db is not None:
            yield db
            return
        raise RuntimeError('An AsyncSession is required for prompt insights operations')


def _normalize_cluster_label(label: str) -> str:
    return ' '.join((label or '').strip().lower().split())


def _canonical_label_hash(label: str) -> str:
    return hashlib.sha256(_normalize_cluster_label(label).encode()).hexdigest()


@asynccontextmanager
async def _prompt_insights_db_context(db: Optional[AsyncSession] = None):
    if db is not None:
        yield db, False
        return
    async with get_async_db_context() as session:
        yield session, True


class PromptInsightsRun(Base):
    __tablename__ = 'prompt_insights_run'

    id = Column(Text, primary_key=True, default=lambda: str(uuid.uuid4()))
    window_start = Column(BigInteger, nullable=False, index=True)
    window_end = Column(BigInteger, nullable=False, index=True)
    status = Column(Text, nullable=False, default='running')
    active_claim = Column(String(16), nullable=True)
    total_prompts = Column(BigInteger, nullable=True)
    clusters_found = Column(BigInteger, nullable=True)
    noise_count = Column(BigInteger, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(BigInteger, nullable=False, default=lambda: int(time.time()))
    completed_at = Column(BigInteger, nullable=True)

    __table_args__ = (UniqueConstraint('active_claim', name='uq_prompt_insights_run_active_claim'),)


class PromptCluster(Base):
    __tablename__ = 'prompt_cluster'

    id = Column(Text, primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id = Column(Text, ForeignKey('prompt_insights_run.id'), nullable=False, index=True)
    canonical_label = Column(Text, nullable=False)
    canonical_label_hash = Column(Text, nullable=False, index=True)
    cluster_size = Column(BigInteger, nullable=False, default=0)
    created_at = Column(BigInteger, nullable=False, default=lambda: int(time.time()))

    __table_args__ = (UniqueConstraint('run_id', 'canonical_label_hash', name='uq_prompt_cluster_run_hash'),)


class PromptClusterTrend(Base):
    __tablename__ = 'prompt_cluster_trend'

    id = Column(Text, primary_key=True, default=lambda: str(uuid.uuid4()))
    canonical_label_hash = Column(Text, nullable=False, index=True)
    bucket = Column(Text, nullable=False, index=True)
    count = Column(BigInteger, nullable=False, default=0)
    run_id = Column(Text, ForeignKey('prompt_insights_run.id'), nullable=False, index=True)
    created_at = Column(BigInteger, nullable=False, default=lambda: int(time.time()))

    __table_args__ = (UniqueConstraint('canonical_label_hash', 'bucket', name='uq_prompt_cluster_trend_label_bucket'),)


# Reserved for a future iteration: per-model breakdown of clusters.
# No writer exists yet; the table is created by the migration so the schema is
# stable when the per-model breakdown feature lands.
class PromptClusterModel(Base):
    __tablename__ = 'prompt_cluster_model'

    id = Column(Text, primary_key=True, default=lambda: str(uuid.uuid4()))
    cluster_id = Column(Text, ForeignKey('prompt_cluster.id'), nullable=False, index=True)
    model_id = Column(Text, nullable=False, index=True)
    requested_model_key = Column(Text, nullable=False, index=True)
    created_at = Column(BigInteger, nullable=False, default=lambda: int(time.time()))

    __table_args__ = (
        UniqueConstraint(
            'cluster_id', 'model_id', 'requested_model_key', name='uq_prompt_cluster_model_cluster_model_key'
        ),
    )


class PromptEmbeddingCache(Base):
    __tablename__ = 'prompt_embedding_cache'

    # NOTE: only the text hash is persisted (not the scrubbed prompt text) so
    # that no raw prompt content is stored. A periodic cleanup job should purge
    # rows where expires_at < now(); that cleanup is not implemented here.
    text_hash = Column(Text, primary_key=True)
    embedding = Column(Text, nullable=True)
    expires_at = Column(BigInteger, nullable=False, index=True)
    created_at = Column(BigInteger, nullable=False, default=lambda: int(time.time()))

    __table_args__ = (Index('idx_prompt_embedding_cache_expires_at', 'expires_at'),)


class PromptInsightsRunModel(BaseModel):
    id: str
    window_start: int
    window_end: int
    status: str
    total_prompts: Optional[int] = None
    clusters_found: Optional[int] = None
    noise_count: Optional[int] = None
    error_message: Optional[str] = None
    created_at: int
    completed_at: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)


class PromptClusterModelRow(BaseModel):
    id: str
    run_id: str
    canonical_label: str
    canonical_label_hash: str
    cluster_size: int
    created_at: int

    model_config = ConfigDict(from_attributes=True)


class PromptClusterTrendModel(BaseModel):
    id: str
    canonical_label_hash: str
    bucket: str
    count: int
    run_id: str
    created_at: int

    model_config = ConfigDict(from_attributes=True)


class PromptEmbeddedCacheModel(BaseModel):
    text_hash: str
    embedding: Optional[str] = None
    expires_at: int
    created_at: int

    model_config = ConfigDict(from_attributes=True)


class PromptInsightsRunsTable:
    async def claim_run(
        self,
        window_start: int,
        window_end: int,
        db: Optional[AsyncSession] = None,
    ) -> Optional[PromptInsightsRunModel]:
        """Atomically claim the single active pipeline slot.

        The nullable unique ``active_claim`` column makes the insert itself the
        cross-dialect lock. The claim is committed immediately so other
        instances observe it before any expensive pipeline work begins.
        """
        async with _prompt_insights_db_context(db) as (session, _):
            run = PromptInsightsRun(window_start=window_start, window_end=window_end, active_claim='active')
            session.add(run)
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                result = await session.execute(
                    select(PromptInsightsRun).where(PromptInsightsRun.active_claim == 'active').limit(1)
                )
                if result.scalar_one_or_none() is not None:
                    return None
                raise
            return PromptInsightsRunModel.model_validate(run)

    async def complete_run(
        self,
        run_id: str,
        total_prompts: int,
        clusters_found: int,
        noise_count: int,
        db: Optional[AsyncSession] = None,
    ) -> None:
        async with _prompt_insights_db_context(db) as (session, owns_session):
            result = await session.execute(select(PromptInsightsRun).filter(PromptInsightsRun.id == run_id))
            run = result.scalar_one_or_none()
            if not run:
                return
            run.status = 'completed'
            run.active_claim = None
            run.total_prompts = total_prompts
            run.clusters_found = clusters_found
            run.noise_count = noise_count
            run.completed_at = int(time.time())
            if owns_session:
                await session.commit()

    async def fail_run(
        self,
        run_id: str,
        error_message: str,
        db: Optional[AsyncSession] = None,
    ) -> None:
        async with _prompt_insights_db_context(db) as (session, owns_session):
            result = await session.execute(select(PromptInsightsRun).filter(PromptInsightsRun.id == run_id))
            run = result.scalar_one_or_none()
            if not run:
                return
            run.status = 'failed'
            run.active_claim = None
            run.error_message = error_message
            run.completed_at = int(time.time())
            if owns_session:
                await session.commit()

    async def get_active_run(self, db: Optional[AsyncSession] = None) -> Optional[PromptInsightsRunModel]:
        async with _prompt_insights_db_context(db) as (session, _):
            result = await session.execute(
                select(PromptInsightsRun)
                .filter(PromptInsightsRun.active_claim == 'active')
                .order_by(PromptInsightsRun.created_at.desc())
                .limit(1)
            )
            run = result.scalar_one_or_none()
            return PromptInsightsRunModel.model_validate(run) if run else None

    async def get_latest_completed_run(self, db: Optional[AsyncSession] = None) -> Optional[PromptInsightsRunModel]:
        async with _prompt_insights_db_context(db) as (session, _):
            result = await session.execute(
                select(PromptInsightsRun)
                .filter(PromptInsightsRun.status == 'completed')
                .order_by(PromptInsightsRun.completed_at.desc())
                .limit(1)
            )
            run = result.scalar_one_or_none()
            return PromptInsightsRunModel.model_validate(run) if run else None

    async def list_runs(self, limit: int = 20, db: Optional[AsyncSession] = None) -> list[PromptInsightsRunModel]:
        async with _prompt_insights_db_context(db) as (session, _):
            result = await session.execute(
                select(PromptInsightsRun).order_by(PromptInsightsRun.created_at.desc()).limit(limit)
            )
            runs = result.scalars().all()
            return [PromptInsightsRunModel.model_validate(r) for r in runs]

    async def count_runs(self, db: Optional[AsyncSession] = None) -> int:
        from sqlalchemy import func  # noqa: PLC0415

        async with _prompt_insights_db_context(db) as (session, _):
            result = await session.execute(select(func.count()).select_from(PromptInsightsRun))
            return result.scalar_one() or 0


def _trend_increment_statement(canonical_label_hash: str, bucket: str, count: int):
    return (
        update(PromptClusterTrend)
        .where(
            PromptClusterTrend.canonical_label_hash == canonical_label_hash,
            PromptClusterTrend.bucket == bucket,
        )
        .values(count=PromptClusterTrend.count + count)
    )


def _trend_insert_statement(canonical_label_hash: str, bucket: str, count: int, run_id: str):
    return insert(PromptClusterTrend).values(
        id=str(uuid.uuid4()),
        run_id=run_id,
        canonical_label_hash=canonical_label_hash,
        bucket=bucket,
        count=count,
        created_at=int(time.time()),
    )


class PromptInsightsTableStore:
    async def upsert_trend(
        self,
        canonical_label_hash: str,
        bucket: str,
        count: int,
        run_id: str,
        db: Optional[AsyncSession] = None,
    ) -> None:
        async with _prompt_insights_db_context(db) as (session, owns_session):
            increment = _trend_increment_statement(canonical_label_hash, bucket, count)
            result = await session.execute(increment)
            if result.rowcount == 0:
                try:
                    async with session.begin_nested():
                        await session.execute(_trend_insert_statement(canonical_label_hash, bucket, count, run_id))
                except IntegrityError:
                    await session.execute(increment)
            if owns_session:
                await session.commit()

    async def get_summary(self, run_id: str, db: Optional[AsyncSession] = None) -> dict:
        async with _prompt_insights_db_context(db) as (session, _):
            result = await session.execute(
                select(PromptClusterTrend)
                .filter(PromptClusterTrend.run_id == run_id)
                .order_by(PromptClusterTrend.bucket.asc())
            )
            trends = result.scalars().all()
            return {
                'run_id': run_id,
                'total_clusters': len(trends),
                'trends': [PromptClusterTrendModel.model_validate(trend).model_dump() for trend in trends],
            }

    async def get_clusters_by_run_id(
        self, run_id: str, db: Optional[AsyncSession] = None
    ) -> list[PromptClusterModelRow]:
        async with _prompt_insights_db_context(db) as (session, _):
            result = await session.execute(
                select(PromptCluster).filter(PromptCluster.run_id == run_id).order_by(PromptCluster.cluster_size.desc())
            )
            clusters = result.scalars().all()
            return [PromptClusterModelRow.model_validate(c) for c in clusters]

    async def get_trend_for_cluster(
        self, cluster_id: str, db: Optional[AsyncSession] = None
    ) -> tuple[Optional[PromptClusterModelRow], list[PromptClusterTrendModel]]:
        async with _prompt_insights_db_context(db) as (session, _):
            cluster_result = await session.execute(select(PromptCluster).filter(PromptCluster.id == cluster_id))
            cluster = cluster_result.scalar_one_or_none()
            if not cluster:
                return None, []
            trend_result = await session.execute(
                select(PromptClusterTrend)
                .filter(PromptClusterTrend.canonical_label_hash == cluster.canonical_label_hash)
                .order_by(PromptClusterTrend.bucket.asc())
            )
            trends = trend_result.scalars().all()
            return (
                PromptClusterModelRow.model_validate(cluster),
                [PromptClusterTrendModel.model_validate(t) for t in trends],
            )

    async def get_emerging_topics(
        self,
        min_volume: int = 5,
        min_growth_ratio: float = 1.5,
        limit: int = 20,
        db: Optional[AsyncSession] = None,
    ) -> list[dict]:
        """Return topics with high recent growth relative to prior activity."""
        from collections import defaultdict  # noqa: PLC0415

        async with _prompt_insights_db_context(db) as (session, _):
            trend_result = await session.execute(select(PromptClusterTrend).order_by(PromptClusterTrend.bucket.desc()))
            all_trends = trend_result.scalars().all()

            # Group by canonical_label_hash
            groups: dict[str, list] = defaultdict(list)
            for t in all_trends:
                groups[t.canonical_label_hash].append(t)

            # Compute growth ratios
            candidates = []
            for label_hash, rows in groups.items():
                rows_sorted = sorted(rows, key=lambda r: r.bucket, reverse=True)
                recent_count = rows_sorted[0].count
                total_count = sum(r.count for r in rows_sorted)
                prior_count = total_count - recent_count
                growth_ratio = recent_count / prior_count if prior_count > 0 else float('inf')

                if recent_count >= min_volume and growth_ratio >= min_growth_ratio:
                    candidates.append(
                        {
                            'canonical_label_hash': label_hash,
                            'recent_count': recent_count,
                            'total_count': total_count,
                            'growth_ratio': growth_ratio,
                        }
                    )

            # Sort by growth ratio desc, then look up labels
            candidates.sort(key=lambda x: -x['growth_ratio'])
            candidates = candidates[:limit]

            # Enrich with canonical labels from most recent cluster row
            results = []
            for item in candidates:
                label_result = await session.execute(
                    select(PromptCluster)
                    .filter(PromptCluster.canonical_label_hash == item['canonical_label_hash'])
                    .order_by(PromptCluster.created_at.desc())
                    .limit(1)
                )
                cluster = label_result.scalar_one_or_none()
                results.append(
                    {
                        **item,
                        'canonical_label': cluster.canonical_label if cluster else item['canonical_label_hash'],
                    }
                )
            return results


PromptInsightsRuns = PromptInsightsRunsTable()
PromptInsightsTable = PromptInsightsTableStore()
