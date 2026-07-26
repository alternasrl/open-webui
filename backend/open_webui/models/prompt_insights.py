import hashlib
import time
import uuid
from contextlib import asynccontextmanager
from typing import Optional

from pydantic import BaseModel, ConfigDict
from sqlalchemy import BigInteger, Column, ForeignKey, Index, Text, UniqueConstraint, select, text
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
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


class PromptInsightsRun(Base):
    __tablename__ = 'prompt_insights_run'

    id = Column(Text, primary_key=True, default=lambda: str(uuid.uuid4()))
    window_start = Column(BigInteger, nullable=False, index=True)
    window_end = Column(BigInteger, nullable=False, index=True)
    status = Column(Text, nullable=False, default='running')
    total_prompts = Column(BigInteger, nullable=True)
    clusters_found = Column(BigInteger, nullable=True)
    noise_count = Column(BigInteger, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(BigInteger, nullable=False, default=lambda: int(time.time()))
    completed_at = Column(BigInteger, nullable=True)


class PromptCluster(Base):
    __tablename__ = 'prompt_cluster'

    id = Column(Text, primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id = Column(Text, ForeignKey('prompt_insights_run.id'), nullable=False, index=True)
    canonical_label = Column(Text, nullable=False)
    canonical_label_hash = Column(Text, nullable=False, index=True)
    cluster_size = Column(BigInteger, nullable=False, default=0)
    created_at = Column(BigInteger, nullable=False, default=lambda: int(time.time()))

    __table_args__ = (
        UniqueConstraint('run_id', 'canonical_label_hash', name='uq_prompt_cluster_run_hash'),
    )


class PromptClusterTrend(Base):
    __tablename__ = 'prompt_cluster_trend'

    id = Column(Text, primary_key=True, default=lambda: str(uuid.uuid4()))
    canonical_label_hash = Column(Text, nullable=False, index=True)
    bucket = Column(Text, nullable=False, index=True)
    count = Column(BigInteger, nullable=False, default=0)
    run_id = Column(Text, ForeignKey('prompt_insights_run.id'), nullable=False, index=True)
    created_at = Column(BigInteger, nullable=False, default=lambda: int(time.time()))

    __table_args__ = (
        Index(
            'uq_prompt_cluster_trend_label_bucket',
            text("COALESCE(canonical_label_hash, '')"),
            text("COALESCE(bucket, '')"),
            unique=True,
        ),
    )


class PromptClusterModel(Base):
    __tablename__ = 'prompt_cluster_model'

    id = Column(Text, primary_key=True, default=lambda: str(uuid.uuid4()))
    cluster_id = Column(Text, ForeignKey('prompt_cluster.id'), nullable=False, index=True)
    model_id = Column(Text, nullable=False, index=True)
    requested_model_key = Column(Text, nullable=False, index=True)
    created_at = Column(BigInteger, nullable=False, default=lambda: int(time.time()))

    __table_args__ = (
        UniqueConstraint('cluster_id', 'model_id', 'requested_model_key', name='uq_prompt_cluster_model_cluster_model_key'),
    )


class PromptEmbeddingCache(Base):
    __tablename__ = 'prompt_embedding_cache'

    text_hash = Column(Text, primary_key=True)
    text = Column(Text, nullable=False)
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
    text: str
    embedding: Optional[str] = None
    expires_at: int
    created_at: int

    model_config = ConfigDict(from_attributes=True)


class PromptInsightsRunsTable:
    async def create_run(
        self,
        window_start: int,
        window_end: int,
        db: Optional[AsyncSession] = None,
    ) -> PromptInsightsRunModel:
        async with get_async_db_context(db) as session:
            run = PromptInsightsRun(window_start=window_start, window_end=window_end)
            session.add(run)
            await session.commit()
            await session.refresh(run)
            return PromptInsightsRunModel.model_validate(run)

    async def complete_run(
        self,
        run_id: str,
        total_prompts: int,
        clusters_found: int,
        noise_count: int,
        db: Optional[AsyncSession] = None,
    ) -> None:
        async with get_async_db_context(db) as session:
            result = await session.execute(select(PromptInsightsRun).filter(PromptInsightsRun.id == run_id))
            run = result.scalar_one_or_none()
            if not run:
                return
            run.status = 'completed'
            run.total_prompts = total_prompts
            run.clusters_found = clusters_found
            run.noise_count = noise_count
            run.completed_at = int(time.time())
            await session.commit()

    async def fail_run(
        self,
        run_id: str,
        error_message: str,
        db: Optional[AsyncSession] = None,
    ) -> None:
        async with get_async_db_context(db) as session:
            result = await session.execute(select(PromptInsightsRun).filter(PromptInsightsRun.id == run_id))
            run = result.scalar_one_or_none()
            if not run:
                return
            run.status = 'failed'
            run.error_message = error_message
            run.completed_at = int(time.time())
            await session.commit()


class PromptInsightsTableStore:
    async def upsert_trend(
        self,
        canonical_label_hash: str,
        bucket: str,
        count: int,
        run_id: str,
        db: Optional[AsyncSession] = None,
    ) -> None:
        async with get_async_db_context(db) as session:
            stmt = sqlite_insert(PromptClusterTrend).values(
                run_id=run_id,
                canonical_label_hash=canonical_label_hash,
                bucket=bucket,
                count=count,
                created_at=int(time.time()),
            ).on_conflict_do_update(
                index_elements=['canonical_label_hash', 'bucket'],
                set_=dict(count=PromptClusterTrend.count + count),
            )
            await session.execute(stmt)
            await session.commit()

    async def get_summary(self, run_id: str, db: Optional[AsyncSession] = None) -> dict:
        async with get_async_db_context(db) as session:
            result = await session.execute(
                select(PromptClusterTrend).filter(PromptClusterTrend.run_id == run_id).order_by(PromptClusterTrend.bucket.asc())
            )
            trends = result.scalars().all()
            return {
                'run_id': run_id,
                'total_clusters': len(trends),
                'trends': [PromptClusterTrendModel.model_validate(trend).model_dump() for trend in trends],
            }


PromptInsightsRuns = PromptInsightsRunsTable()
PromptInsightsTable = PromptInsightsTableStore()
