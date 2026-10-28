"""Mounted v0.12.4 Analytics contract; no provider calls or app lifespan jobs."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.testclient import TestClient
from open_webui.internal.db import get_async_session
from open_webui.models.config import Config
from open_webui.routers import analytics
from open_webui.utils.auth import get_current_user

PREFIX = '/api/v1/analytics'
UPSTREAM_ROUTES = {
    ('GET', f'{PREFIX}/models'),
    ('GET', f'{PREFIX}/users'),
    ('GET', f'{PREFIX}/messages'),
    ('GET', f'{PREFIX}/summary'),
    ('GET', f'{PREFIX}/daily'),
    ('GET', f'{PREFIX}/tokens'),
    ('GET', f'{PREFIX}/models/{{model_id:path}}/chats'),
    ('GET', f'{PREFIX}/models/{{model_id:path}}/overview'),
}
RETIRED_ROUTES = [
    ('GET', '/routing/summary'),
    ('GET', '/routing/events'),
    ('GET', '/prompt-insights/summary'),
    ('GET', '/prompt-insights/clusters'),
    ('GET', '/prompt-insights/clusters/cluster-1/trend'),
    ('GET', '/prompt-insights/emerging'),
    ('POST', '/prompt-insights/run'),
    ('GET', '/prompt-insights/runs'),
]
STANDARD_PATHS = [
    '/models',
    '/users',
    '/messages',
    '/summary',
    '/daily',
    '/tokens',
    '/models/provider/model/chats',
    '/models/provider/model/overview',
]


@pytest.fixture
def api(monkeypatch):
    # Keep the real mounted app and auth gate, but never start its background jobs.
    monkeypatch.setattr(Config, 'PERSISTENT_ENABLED', False)
    from open_webui.main import app

    actor = SimpleNamespace(id='admin', role='admin')
    db = object()

    async def session():
        yield db

    overrides = dict(app.dependency_overrides)
    app.dependency_overrides[get_async_session] = session
    app.dependency_overrides[get_current_user] = lambda: actor
    client = TestClient(app)
    try:
        yield SimpleNamespace(app=app, client=client, db=db, actor=actor)
    finally:
        client.close()
        app.dependency_overrides.clear()
        app.dependency_overrides.update(overrides)


def test_mounted_analytics_is_exact_upstream_surface(api):
    mounted = {
        (method, route.path)
        for route in api.app.routes
        if getattr(route, 'path', '').startswith(PREFIX)
        for method in getattr(route, 'methods', ())
    }
    assert mounted == UPSTREAM_ROUTES
    assert not any(
        'prompt-insights' in getattr(route, 'path', '')
        or 'prompt_insights' in getattr(route, 'path', '')
        or '/analytics/routing' in getattr(route, 'path', '')
        for route in api.app.routes
    )


@pytest.mark.parametrize(('method', 'path'), RETIRED_ROUTES)
def test_custom_analytics_endpoints_are_not_served(api, method, path):
    response = api.client.request(method, PREFIX + path)
    assert response.status_code == 404
    assert response.json() == {'detail': 'Not Found'}


@pytest.mark.parametrize('path', STANDARD_PATHS)
def test_standard_analytics_requires_admin(api, path):
    api.actor.role = 'user'
    assert api.client.get(PREFIX + path).status_code == 401


def test_models_counts_and_filters(api, monkeypatch):
    counts = AsyncMock(
        return_value={
            'small': {'count': 1, 'unique_users': 1, 'unique_chats': 1},
            'large': {'count': 4, 'unique_users': 2, 'unique_chats': 3},
        }
    )
    monkeypatch.setattr(analytics.ChatMessages, 'get_model_analytics', counts)
    response = api.client.get(PREFIX + '/models?start_date=10&end_date=20&group_id=group')
    assert response.status_code == 200
    assert response.json() == {
        'models': [
            {'model_id': 'large', 'count': 4, 'unique_users': 2, 'unique_chats': 3},
            {'model_id': 'small', 'count': 1, 'unique_users': 1, 'unique_chats': 1},
        ]
    }
    counts.assert_awaited_once_with(start_date=10, end_date=20, group_id='group', db=api.db)


def test_users_rank_by_tokens_before_limit(api, monkeypatch):
    usage = AsyncMock(
        return_value={
            'frequent': {'message_count': 10, 'total_tokens': 10},
            'heavy': {'message_count': 2, 'input_tokens': 80, 'output_tokens': 20, 'total_tokens': 100},
        }
    )
    users = AsyncMock(return_value=[SimpleNamespace(id='heavy', name='Heavy', email='heavy@example.com')])
    monkeypatch.setattr(analytics.ChatMessages, 'get_user_analytics', usage)
    monkeypatch.setattr(analytics.Users, 'get_users_by_user_ids', users)
    response = api.client.get(PREFIX + '/users?metric=tokens&limit=1&group_id=group')
    assert response.status_code == 200
    assert response.json() == {
        'users': [
            {
                'user_id': 'heavy',
                'name': 'Heavy',
                'email': 'heavy@example.com',
                'count': 2,
                'input_tokens': 80,
                'output_tokens': 20,
                'total_tokens': 100,
            }
        ]
    }
    usage.assert_awaited_once_with(start_date=None, end_date=None, group_id='group', db=api.db)
    users.assert_awaited_once_with(['heavy'], db=api.db)


def test_summary_retains_standard_counters(api, monkeypatch):
    expected = {'total_messages': 8, 'total_chats': 3, 'total_models': 2, 'total_users': 2}
    summary = AsyncMock(return_value=expected)
    monkeypatch.setattr(analytics.ChatMessages, 'get_analytics_summary', summary)
    response = api.client.get(PREFIX + '/summary?start_date=10&end_date=20')
    assert response.status_code == 200
    assert response.json() == expected
    summary.assert_awaited_once_with(start_date=10, end_date=20, group_id=None, db=api.db)


def test_daily_retains_standard_time_series(api, monkeypatch):
    usage = AsyncMock(return_value={'2026-10-27': {'model': 17}})
    monkeypatch.setattr(analytics.ChatMessages, 'get_usage_over_time_by_model', usage)
    response = api.client.get(PREFIX + '/daily?metric=tokens&granularity=hourly&start_date=10&end_date=20')
    assert response.status_code == 200
    assert response.json() == {
        'data': [{'date': '2026-10-27', 'models': {'model': 17}, 'start': None, 'end': None, 'previous': None}]
    }
    usage.assert_awaited_once_with(
        start_date=10, end_date=20, group_id=None, db=api.db, granularity='hourly', metric='tokens'
    )
    assert api.client.get(PREFIX + '/daily?compare=true').status_code == 400
    assert usage.await_count == 1


def test_tokens_aggregate_and_sort_standard_usage(api, monkeypatch):
    usage = AsyncMock(
        return_value={
            'small': {'input_tokens': 2, 'output_tokens': 1, 'total_tokens': 3, 'message_count': 1},
            'large': {'input_tokens': 10, 'output_tokens': 5, 'total_tokens': 15, 'message_count': 2},
        }
    )
    monkeypatch.setattr(analytics.ChatMessages, 'get_token_usage_by_model', usage)
    response = api.client.get(PREFIX + '/tokens?group_id=group')
    assert response.status_code == 200
    assert response.json() == {
        'models': [
            {'model_id': 'large', 'input_tokens': 10, 'output_tokens': 5, 'total_tokens': 15, 'message_count': 2},
            {'model_id': 'small', 'input_tokens': 2, 'output_tokens': 1, 'total_tokens': 3, 'message_count': 1},
        ],
        'total_input_tokens': 12,
        'total_output_tokens': 6,
        'total_tokens': 18,
    }
    usage.assert_awaited_once_with(start_date=None, end_date=None, group_id='group', db=api.db)


@pytest.mark.parametrize(
    ('query', 'method', 'kwargs'),
    [
        ('chat_id=chat&model_id=model', 'get_messages_by_chat_id', {'chat_id': 'chat'}),
        (
            'model_id=model&start_date=10&end_date=20&skip=2&limit=3',
            'get_messages_by_model_id',
            {'model_id': 'model', 'start_date': 10, 'end_date': 20, 'skip': 2, 'limit': 3},
        ),
        ('user_id=user&skip=2&limit=3', 'get_messages_by_user_id', {'user_id': 'user', 'skip': 2, 'limit': 3}),
    ],
)
def test_messages_dispatch_standard_filters(api, monkeypatch, query, method, kwargs):
    message = {
        'id': 'chat-message',
        'chat_id': 'chat',
        'user_id': 'user',
        'role': 'assistant',
        'content': 'answer',
        'model_id': 'model',
        'usage': {'input_tokens': 10, 'output_tokens': 3, 'total_tokens': 13},
        'created_at': 10,
        'updated_at': 20,
    }
    lookup = AsyncMock(return_value=[message])
    monkeypatch.setattr(analytics.ChatMessages, method, lookup)
    response = api.client.get(PREFIX + '/messages?' + query)
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert {key: response.json()[0][key] for key in message} == message
    lookup.assert_awaited_once_with(**kwargs, db=api.db)
    assert api.client.get(PREFIX + '/messages').json() == []
    assert lookup.await_count == 1


def test_model_chats_accepts_namespaced_model_and_standard_order(api, monkeypatch):
    chats = AsyncMock(
        return_value={
            'items': [
                {'chat_id': 'chat', 'user_id': 'user', 'user_name': 'User', 'first_message': 'Hello', 'updated_at': 20}
            ],
            'total': 1,
        }
    )
    monkeypatch.setattr(analytics.Chats, 'get_chats_by_model_id', chats)
    response = api.client.get(PREFIX + '/models/provider/model/chats?order_by=title&direction=asc&skip=2&limit=3')
    assert response.status_code == 200
    assert response.json() == {
        'chats': [
            {'chat_id': 'chat', 'user_id': 'user', 'user_name': 'User', 'first_message': 'Hello', 'updated_at': 20}
        ],
        'total': 1,
    }
    chats.assert_awaited_once_with(
        model_id='provider/model', filter={'order_by': 'title', 'direction': 'asc'}, skip=2, limit=3, db=api.db
    )


def test_model_overview_retains_feedback_and_tags(api, monkeypatch):
    clock = Mock(wraps=analytics.datetime)
    clock.now.return_value = analytics.datetime(2026, 10, 28, 12)
    monkeypatch.setattr(analytics, 'datetime', clock)
    ids = AsyncMock(return_value=['chat'])
    feedback = AsyncMock(return_value=[SimpleNamespace(date='2026-10-28', won=3, lost=1)])
    metas = AsyncMock(return_value=[{'tags': ['common', 'other']}, {'tags': ['common']}])
    monkeypatch.setattr(analytics.ChatMessages, 'get_chat_ids_by_model_id', ids)
    monkeypatch.setattr(analytics.Feedbacks, 'get_model_feedback_counts_by_day', feedback)
    monkeypatch.setattr(analytics.Chats, 'get_chat_metas_by_chat_ids', metas)
    response = api.client.get(PREFIX + '/models/provider/model/overview?days=0')
    assert response.status_code == 200
    assert response.json() == {
        'history': [{'date': '2026-10-28', 'won': 3, 'lost': 1}],
        'tags': [{'tag': 'common', 'count': 2}, {'tag': 'other', 'count': 1}],
    }
    ids.assert_awaited_once_with(
        model_id='provider/model', start_date=None, end_date=None, skip=0, limit=10000, db=api.db
    )
    feedback.assert_awaited_once_with(model_id='provider/model', start_date=None, db=api.db)
    metas.assert_awaited_once_with(['chat'], include_archived=True, db=api.db)
