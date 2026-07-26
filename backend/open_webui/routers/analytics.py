import logging
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request
from open_webui.internal.db import get_async_session
from open_webui.models.chat_messages import ChatMessageModel, ChatMessages
from open_webui.models.chats import Chats
from open_webui.models.feedbacks import Feedbacks
from open_webui.models.groups import Groups
from open_webui.models.prompt_insights import (
    PromptInsightsRuns,
    PromptInsightsTable,
    PromptInsightsRunModel,
)
from open_webui.models.users import Users
from open_webui.utils.auth import get_admin_user
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger(__name__)


router = APIRouter()


####################
# Response Models
####################


class ModelAnalyticsEntry(BaseModel):
    model_id: str
    count: int
    unique_users: int = 0
    unique_chats: int = 0
    avg_ttft_ms: Optional[float] = None
    avg_tokens_per_second: Optional[float] = None
    error_requests: int = 0
    total_requests: int = 0
    error_rate: float = 0.0


class ModelAnalyticsResponse(BaseModel):
    models: list[ModelAnalyticsEntry]


class UserAnalyticsEntry(BaseModel):
    user_id: str
    name: Optional[str] = None
    email: Optional[str] = None
    count: int
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0


class UserAnalyticsResponse(BaseModel):
    users: list[UserAnalyticsEntry]


####################
# Endpoints
####################


@router.get('/models', response_model=ModelAnalyticsResponse)
async def get_model_analytics(
    start_date: Optional[int] = Query(None, description='Start timestamp (epoch)'),
    end_date: Optional[int] = Query(None, description='End timestamp (epoch)'),
    group_id: Optional[str] = Query(None, description='Filter by user group ID'),
    user_id: Optional[str] = Query(None, description='Filter by user ID'),
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    """Get message counts per model."""
    counts = await ChatMessages.get_message_count_by_model(
        start_date=start_date, end_date=end_date, group_id=group_id, user_id=user_id, db=db
    )
    perf = await ChatMessages.get_performance_metrics_by_model(
        start_date=start_date, end_date=end_date, group_id=group_id, user_id=user_id, db=db
    )
    unique_counts = await ChatMessages.get_unique_counts_by_model(
        start_date=start_date, end_date=end_date, group_id=group_id, db=db
    )
    models = [
        ModelAnalyticsEntry(
            model_id=model_id,
            count=count,
            unique_users=unique_counts.get(model_id, {}).get('unique_users', 0),
            unique_chats=unique_counts.get(model_id, {}).get('unique_chats', 0),
            **perf.get(model_id, {}),
        )
        for model_id, count in sorted(counts.items(), key=lambda x: -x[1])
    ]
    return ModelAnalyticsResponse(models=models)


@router.get('/users', response_model=UserAnalyticsResponse)
async def get_user_analytics(
    start_date: Optional[int] = Query(None, description='Start timestamp (epoch)'),
    end_date: Optional[int] = Query(None, description='End timestamp (epoch)'),
    group_id: Optional[str] = Query(None, description='Filter by user group ID'),
    model_id: Optional[str] = Query(None, description='Filter by model ID'),
    limit: int = Query(50, description='Max users to return'),
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    """Get message counts and token usage per user with user info."""
    counts = await ChatMessages.get_message_count_by_user(
        start_date=start_date, end_date=end_date, group_id=group_id, model_id=model_id, db=db
    )
    token_usage = await ChatMessages.get_token_usage_by_user(
        start_date=start_date, end_date=end_date, group_id=group_id, model_id=model_id, db=db
    )

    # Get user info for top users
    top_user_ids = [uid for uid, _ in sorted(counts.items(), key=lambda x: -x[1])[:limit]]
    user_info = {u.id: u for u in await Users.get_users_by_user_ids(top_user_ids, db=db)}

    users = []
    for user_id in top_user_ids:
        u = user_info.get(user_id)
        tokens = token_usage.get(user_id, {})
        users.append(
            UserAnalyticsEntry(
                user_id=user_id,
                name=u.name if u else None,
                email=u.email if u else None,
                count=counts[user_id],
                input_tokens=tokens.get('input_tokens', 0),
                output_tokens=tokens.get('output_tokens', 0),
                total_tokens=tokens.get('total_tokens', 0),
            )
        )

    return UserAnalyticsResponse(users=users)


@router.get('/messages', response_model=list[ChatMessageModel])
async def get_messages(
    model_id: Optional[str] = Query(None, description='Filter by model ID'),
    user_id: Optional[str] = Query(None, description='Filter by user ID'),
    chat_id: Optional[str] = Query(None, description='Filter by chat ID'),
    start_date: Optional[int] = Query(None, description='Start timestamp (epoch)'),
    end_date: Optional[int] = Query(None, description='End timestamp (epoch)'),
    skip: int = Query(0),
    limit: int = Query(50, le=100),
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    """Query messages with filters."""
    if chat_id:
        return await ChatMessages.get_messages_by_chat_id(chat_id=chat_id, db=db)
    elif model_id:
        return await ChatMessages.get_messages_by_model_id(
            model_id=model_id,
            start_date=start_date,
            end_date=end_date,
            skip=skip,
            limit=limit,
            db=db,
        )
    elif user_id:
        return await ChatMessages.get_messages_by_user_id(user_id=user_id, skip=skip, limit=limit, db=db)
    else:
        # Return empty if no filter specified
        return []


class SummaryResponse(BaseModel):
    total_messages: int
    total_chats: int
    total_models: int
    total_users: int
    avg_ttft_ms: Optional[float] = None
    avg_tokens_per_second: Optional[float] = None
    error_requests: int = 0
    total_requests: int = 0
    error_rate: float = 0.0


@router.get('/summary', response_model=SummaryResponse)
async def get_summary(
    start_date: Optional[int] = Query(None, description='Start timestamp (epoch)'),
    end_date: Optional[int] = Query(None, description='End timestamp (epoch)'),
    group_id: Optional[str] = Query(None, description='Filter by user group ID'),
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    """Get summary statistics for the dashboard."""
    model_counts = await ChatMessages.get_message_count_by_model(
        start_date=start_date, end_date=end_date, group_id=group_id, db=db
    )
    user_counts = await ChatMessages.get_message_count_by_user(
        start_date=start_date, end_date=end_date, group_id=group_id, db=db
    )
    chat_counts = await ChatMessages.get_message_count_by_chat(
        start_date=start_date, end_date=end_date, group_id=group_id, db=db
    )
    performance = await ChatMessages.get_performance_metrics(
        start_date=start_date, end_date=end_date, group_id=group_id, db=db
    )

    return SummaryResponse(
        total_messages=sum(model_counts.values()),
        total_chats=len(chat_counts),
        total_models=len(model_counts),
        total_users=len(user_counts),
        **performance,
    )


class DailyStatsEntry(BaseModel):
    date: str
    models: dict[str, int]


class DailyStatsResponse(BaseModel):
    data: list[DailyStatsEntry]


@router.get('/daily', response_model=DailyStatsResponse)
async def get_daily_stats(
    start_date: Optional[int] = Query(None, description='Start timestamp (epoch)'),
    end_date: Optional[int] = Query(None, description='End timestamp (epoch)'),
    group_id: Optional[str] = Query(None, description='Filter by user group ID'),
    granularity: str = Query('daily', description="Granularity: 'hourly' or 'daily'"),
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    """Get message counts grouped by model for time-series chart."""
    if granularity == 'hourly':
        counts = await ChatMessages.get_hourly_message_counts_by_model(start_date=start_date, end_date=end_date, db=db)
    else:
        counts = await ChatMessages.get_daily_message_counts_by_model(
            start_date=start_date, end_date=end_date, group_id=group_id, db=db
        )
    return DailyStatsResponse(
        data=[DailyStatsEntry(date=date, models=models) for date, models in sorted(counts.items())]
    )


class TokenUsageEntry(BaseModel):
    model_id: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    message_count: int


class RoutingSummaryEntry(BaseModel):
    requested_model_id: str
    selected_model_id: str
    count: int
    percentage: float


class RoutingEventEntry(BaseModel):
    message_id: str
    chat_id: str
    user_id: Optional[str] = None
    created_at: int
    requested_model_id: str
    selected_model_id: str


@router.get('/routing/summary', response_model=list[RoutingSummaryEntry])
async def get_routing_summary(
    start_date: Optional[int] = Query(None, description='Start timestamp (epoch)'),
    end_date: Optional[int] = Query(None, description='End timestamp (epoch)'),
    group_id: Optional[str] = Query(None, description='Filter by user group ID'),
    user_id: Optional[str] = Query(None, description='Filter by user ID'),
    model_selected: Optional[str] = Query(None, description='Filter by selected model ID'),
    model_requested: Optional[str] = Query(None, description='Filter by requested model ID'),
    model_mode: str = Query(
        'or',
        description="Model filter mode: 'or', 'and', 'selected', or 'requested'",
    ),
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    """Get routing pair summary (requested -> selected) with count and percentage."""
    return await ChatMessages.get_routing_summary(
        start_date=start_date,
        end_date=end_date,
        group_id=group_id,
        user_id=user_id,
        model_selected=model_selected,
        model_requested=model_requested,
        model_mode=model_mode,
        db=db,
    )


@router.get('/routing/events', response_model=list[RoutingEventEntry])
async def get_routing_events(
    start_date: Optional[int] = Query(None, description='Start timestamp (epoch)'),
    end_date: Optional[int] = Query(None, description='End timestamp (epoch)'),
    group_id: Optional[str] = Query(None, description='Filter by user group ID'),
    user_id: Optional[str] = Query(None, description='Filter by user ID'),
    model_selected: Optional[str] = Query(None, description='Filter by selected model ID'),
    model_requested: Optional[str] = Query(None, description='Filter by requested model ID'),
    model_mode: str = Query(
        'or',
        description="Model filter mode: 'or', 'and', 'selected', or 'requested'",
    ),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    """Get routing events sourced from assistant message usage metadata."""
    return await ChatMessages.get_routing_events(
        start_date=start_date,
        end_date=end_date,
        group_id=group_id,
        user_id=user_id,
        model_selected=model_selected,
        model_requested=model_requested,
        model_mode=model_mode,
        skip=skip,
        limit=limit,
        db=db,
    )


class TokenUsageResponse(BaseModel):
    models: list[TokenUsageEntry]
    total_input_tokens: int
    total_output_tokens: int
    total_tokens: int


@router.get('/tokens', response_model=TokenUsageResponse)
async def get_token_usage(
    start_date: Optional[int] = Query(None),
    end_date: Optional[int] = Query(None),
    group_id: Optional[str] = Query(None, description='Filter by user group ID'),
    user_id: Optional[str] = Query(None, description='Filter by user ID'),
    model_id: Optional[str] = Query(None, description='Filter by model ID'),
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    """Get token usage aggregated by model."""
    usage = await ChatMessages.get_token_usage_by_model(
        start_date=start_date, end_date=end_date, group_id=group_id, user_id=user_id, model_id=model_id, db=db
    )

    models = [
        TokenUsageEntry(model_id=model_id, **data)
        for model_id, data in sorted(usage.items(), key=lambda x: -x[1]['total_tokens'])
    ]

    total_input = sum(m.input_tokens for m in models)
    total_output = sum(m.output_tokens for m in models)

    return TokenUsageResponse(
        models=models,
        total_input_tokens=total_input,
        total_output_tokens=total_output,
        total_tokens=total_input + total_output,
    )


####################
# Model Chats Browser
####################


class ModelChatEntry(BaseModel):
    chat_id: str
    user_id: Optional[str] = None
    user_name: Optional[str] = None
    first_message: Optional[str] = None
    updated_at: int


class ModelChatsResponse(BaseModel):
    chats: list[ModelChatEntry]
    total: int


MODEL_CHAT_ORDER_FIELDS = {'title', 'updated_at', 'user_name'}


@router.get('/models/{model_id:path}/chats', response_model=ModelChatsResponse)
async def get_model_chats(
    model_id: str,
    start_date: Optional[int] = Query(None),
    end_date: Optional[int] = Query(None),
    skip: int = Query(0),
    limit: int = Query(50, le=100),
    order_by: str = Query('updated_at'),
    direction: str = Query('desc'),
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    """Get chats that used a specific model, with preview and feedback info."""
    filter = {}
    if start_date:
        filter['start_date'] = start_date
    if end_date:
        filter['end_date'] = end_date
    if order_by in MODEL_CHAT_ORDER_FIELDS:
        filter['order_by'] = order_by
    if direction in {'asc', 'desc'}:
        filter['direction'] = direction

    result = await Chats.get_chats_by_model_id(
        model_id=model_id,
        filter=filter,
        skip=skip,
        limit=limit,
        db=db,
    )

    return ModelChatsResponse(
        chats=[ModelChatEntry.model_validate(chat) for chat in result['items']],
        total=result['total'] or 0,
    )


####################
# Model Overview
####################


class HistoryEntry(BaseModel):
    date: str
    won: int = 0
    lost: int = 0


class TagEntry(BaseModel):
    tag: str
    count: int


class ModelOverviewResponse(BaseModel):
    history: list[HistoryEntry]
    tags: list[TagEntry]


@router.get('/models/{model_id:path}/overview', response_model=ModelOverviewResponse)
async def get_model_overview(
    model_id: str,
    days: int = Query(30, description='Number of days of history (0 for all)'),
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    """Get model overview with feedback history and chat tags."""

    # Calculate start date for history
    now = datetime.now()
    start_dt = None
    if days > 0:
        start_dt = now - timedelta(days=days)

    # Get chat IDs that used this model
    chat_ids = await ChatMessages.get_chat_ids_by_model_id(
        model_id=model_id,
        start_date=None,
        end_date=None,
        skip=0,
        limit=10000,  # Get all chats
        db=db,
    )

    history_rows = await Feedbacks.get_model_feedback_counts_by_day(
        model_id=model_id,
        start_date=int(start_dt.timestamp()) if start_dt else None,
        db=db,
    )
    history_counts = {
        entry.date: {
            'won': entry.won,
            'lost': entry.lost,
        }
        for entry in history_rows
    }

    # Fill in missing days
    history = []
    if history_counts or days > 0:
        end_dt = now
        if days > 0:
            current = start_dt
        elif history_counts:
            # Find earliest date
            min_date = min(history_counts.keys())
            current = datetime.strptime(min_date, '%Y-%m-%d')
        else:
            current = now

        while current <= end_dt:
            date_str = current.strftime('%Y-%m-%d')
            counts = history_counts.get(date_str, {'won': 0, 'lost': 0})
            history.append(
                HistoryEntry(
                    date=date_str,
                    won=counts['won'],
                    lost=counts['lost'],
                )
            )
            current += timedelta(days=1)

    # Get chat tags
    tag_counts: dict[str, int] = defaultdict(int)
    if chat_ids:
        chat_metas = await Chats.get_chat_metas_by_chat_ids(
            chat_ids,
            include_archived=True,
            db=db,
        )
        for meta in chat_metas:
            for tag in meta.get('tags', []):
                tag_counts[tag] += 1

    # Sort by count and take top 10
    tags = [TagEntry(tag=tag, count=count) for tag, count in sorted(tag_counts.items(), key=lambda x: -x[1])[:10]]

    return ModelOverviewResponse(history=history, tags=tags)


####################
# Prompt Insights
####################


class PromptInsightsSummaryResponse(BaseModel):
    latest_run: Optional[PromptInsightsRunModel] = None
    active_run: Optional[PromptInsightsRunModel] = None
    total_runs: int = 0


class PromptClusterEntry(BaseModel):
    id: str
    run_id: str
    canonical_label: str
    canonical_label_hash: str
    cluster_size: int
    created_at: int


class PromptInsightsClustersResponse(BaseModel):
    run_id: str
    clusters: list[PromptClusterEntry]


class TrendPoint(BaseModel):
    bucket: str
    count: int


class PromptClusterTrendResponse(BaseModel):
    cluster_id: str
    canonical_label: str
    canonical_label_hash: str
    trend: list[TrendPoint]


class EmergingTopicEntry(BaseModel):
    canonical_label: str
    canonical_label_hash: str
    recent_count: int
    total_count: int
    growth_ratio: float


class EmergingTopicsResponse(BaseModel):
    topics: list[EmergingTopicEntry]


class PromptInsightsRunTriggerResponse(BaseModel):
    status: str
    reason: Optional[str] = None
    run_id: Optional[str] = None


class PromptInsightsRunsResponse(BaseModel):
    runs: list[PromptInsightsRunModel]


@router.get('/prompt-insights/summary', response_model=PromptInsightsSummaryResponse)
async def get_prompt_insights_summary(
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    """Get summary of the latest prompt insights run and any active run."""
    latest, active, total = await _gather_summary(db)
    return PromptInsightsSummaryResponse(latest_run=latest, active_run=active, total_runs=total)


async def _gather_summary(db: AsyncSession):
    latest = await PromptInsightsRuns.get_latest_completed_run(db=db)
    active = await PromptInsightsRuns.get_active_run(db=db)
    total = await PromptInsightsRuns.count_runs(db=db)
    return latest, active, total


@router.get('/prompt-insights/clusters', response_model=PromptInsightsClustersResponse)
async def get_prompt_insights_clusters(
    run_id: Optional[str] = Query(None, description='Run ID; defaults to latest completed run'),
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    """Get clusters for a given run (defaults to the latest completed run)."""
    if run_id is None:
        latest = await PromptInsightsRuns.get_latest_completed_run(db=db)
        if latest is None:
            return PromptInsightsClustersResponse(run_id='', clusters=[])
        run_id = latest.id

    clusters = await PromptInsightsTable.get_clusters_by_run_id(run_id=run_id, db=db)
    return PromptInsightsClustersResponse(
        run_id=run_id,
        clusters=[PromptClusterEntry(**c.model_dump()) for c in clusters],
    )


@router.get('/prompt-insights/clusters/{cluster_id}/trend', response_model=PromptClusterTrendResponse)
async def get_prompt_insights_cluster_trend(
    cluster_id: str,
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    """Get historical trend data for a single cluster."""
    from fastapi import HTTPException  # noqa: PLC0415

    cluster, trends = await PromptInsightsTable.get_trend_for_cluster(cluster_id=cluster_id, db=db)
    if cluster is None:
        raise HTTPException(status_code=404, detail='Cluster not found')

    return PromptClusterTrendResponse(
        cluster_id=cluster_id,
        canonical_label=cluster.canonical_label,
        canonical_label_hash=cluster.canonical_label_hash,
        trend=[TrendPoint(bucket=t.bucket, count=t.count) for t in trends],
    )


@router.get('/prompt-insights/emerging', response_model=EmergingTopicsResponse)
async def get_prompt_insights_emerging(
    min_volume: int = Query(5, ge=1, description='Minimum recent count to qualify'),
    min_growth_ratio: float = Query(1.5, ge=1.0, description='Minimum growth ratio to qualify'),
    limit: int = Query(20, ge=1, le=100),
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    """Get topics with the highest recent growth relative to prior activity."""
    topics = await PromptInsightsTable.get_emerging_topics(
        min_volume=min_volume,
        min_growth_ratio=min_growth_ratio,
        limit=limit,
        db=db,
    )
    return EmergingTopicsResponse(
        topics=[
            EmergingTopicEntry(
                canonical_label=t['canonical_label'],
                canonical_label_hash=t['canonical_label_hash'],
                recent_count=t['recent_count'],
                total_count=t['total_count'],
                growth_ratio=t['growth_ratio'] if t['growth_ratio'] != float('inf') else 999999.0,
            )
            for t in topics
        ]
    )


@router.post('/prompt-insights/run', response_model=PromptInsightsRunTriggerResponse)
async def trigger_prompt_insights_run(
    background_tasks: BackgroundTasks,
    request: Request,
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    """Manually trigger a prompt insights run. No-op if a run is already in progress."""
    active = await PromptInsightsRuns.get_active_run(db=db)
    if active is not None:
        return PromptInsightsRunTriggerResponse(
            status='skipped', reason='run_in_progress', run_id=active.id
        )

    window_end = int(time.time())
    window_start = window_end - 86400  # default: last 24 h

    async def _run_pipeline():
        from open_webui.prompt_insights.pipeline import PromptInsightsPipeline  # noqa: PLC0415
        try:
            await PromptInsightsPipeline(request.app).run(window_start, window_end)
        except Exception:
            log.exception('Manual prompt insights run failed')

    background_tasks.add_task(_run_pipeline)
    return PromptInsightsRunTriggerResponse(status='started')


@router.get('/prompt-insights/runs', response_model=PromptInsightsRunsResponse)
async def get_prompt_insights_runs(
    limit: int = Query(20, ge=1, le=100, description='Max runs to return'),
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    """List past prompt insights runs, newest first."""
    runs = await PromptInsightsRuns.list_runs(limit=limit, db=db)
    return PromptInsightsRunsResponse(runs=runs)
