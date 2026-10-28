"""Shared-chat authorship, owner settings and dual-audit compatibility."""

import asyncio
import copy
import logging
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from starlette.requests import Request
from starlette.responses import JSONResponse

from open_webui import events
from open_webui.middleware import access_log
from open_webui.models import chats
from open_webui.models.chat_messages import ChatMessage, ChatMessages
from open_webui.models.users import UserModel
from open_webui.routers import chats as chat_router
from open_webui.utils import middleware


def _actor():
    return UserModel(
        id='actor',
        name='Collaborator',
        email='collaborator@example.com',
        role='user',
        created_at=0,
        updated_at=0,
        last_active_at=0,
    )


def _request(user):
    req = Request(
        {
            'type': 'http',
            'method': 'POST',
            'path': '/api/chat/completions',
            'query_string': b'',
            'headers': [],
            'scheme': 'http',
            'client': ('127.0.0.1', 1234),
            'server': ('testserver', 80),
            'app': SimpleNamespace(state=SimpleNamespace(redis=None)),
        }
    )
    req.state.user = user
    return req


def _in_memory(monkeypatch, callback):
    from open_webui.internal import db as internal_db

    monkeypatch.setattr(internal_db, 'DATABASE_ENABLE_SESSION_SHARING', True)

    async def scenario():
        engine = create_async_engine('sqlite+aiosqlite:///:memory:')
        try:
            async with engine.begin() as connection:
                await connection.run_sync(
                    lambda db: chats.Chat.metadata.create_all(db, tables=[chats.Chat.__table__, ChatMessage.__table__])
                )
            sessions = async_sessionmaker(engine, expire_on_commit=False)

            @asynccontextmanager
            async def get_db():
                async with sessions() as db:
                    yield db

            monkeypatch.setattr(chats, 'get_async_db', get_db)
            async with sessions() as db:
                chat = chats.Chat(
                    id='shared-chat',
                    user_id='owner',
                    title='Owner title',
                    chat={
                        'title': 'Owner title',
                        'models': ['owner-model'],
                        'params': {'temperature': 0.25},
                        'history': {'messages': {}, 'currentId': None},
                    },
                    variables={'private': 'owner-value'},
                    meta={'tags': ['owner-tag']},
                    folder_id='owner-folder',
                    created_at=1_780_000_000,
                    updated_at=1_780_000_000,
                )
                db.add(chat)
                await db.commit()
            # Permission resolution is the Task 4 gate; exercise the real transactional turn path.
            monkeypatch.setattr(chats.Chats, 'get_accessible_chat_by_id', AsyncMock(return_value=chat))
            await callback(sessions, chat)
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_shared_reply_preserves_owner_settings_and_actor(monkeypatch, caplog):
    actor = _actor()
    published = []

    async def sink(app, event, request=None):
        published.append(event)

    async def config(key, default=None):
        return default

    monkeypatch.setattr(events, 'EVENT_SINKS', [SimpleNamespace(handle_event=sink)])
    monkeypatch.setattr(middleware.Config, 'get', config)
    monkeypatch.setattr(middleware, 'get_event_emitter', AsyncMock(return_value=None))
    monkeypatch.setattr(
        access_log,
        '_resolve_user_context',
        AsyncMock(
            return_value=SimpleNamespace(
                email=actor.email,
                role='user',
                oidc_sub=None,
                mfa_status=None,
            )
        ),
    )

    async def scenario(sessions, chat):
        before = copy.deepcopy(chat.chat)
        before_vars, before_meta = copy.deepcopy(chat.variables), copy.deepcopy(chat.meta)
        req = _request(actor)

        async def endpoint(request):
            turn = await chats.Chats.insert_chat_turn(
                chat.id,
                actor,
                {
                    'id': 'prompt',
                    'content': 'hello',
                    'models': ['collaborator-model'],
                    'user_id': 'owner',
                    'meta': {'untrusted': True},
                },
                [{'message_id': 'reply', 'model_id': 'collaborator-model'}],
            )
            assert turn['messages']['reply']['user_id'] == actor.id
            await chats.Chats.upsert_message_to_chat_by_id_and_message_id(
                chat.id,
                'reply',
                {
                    'done': True,
                    'content': 'answer',
                    'usage': {
                        'input_tokens': 10,
                        'output_tokens': 3,
                    },
                },
            )
            await middleware.publish_chat_finished_event(
                request,
                actor,
                {'chat_id': chat.id, 'message_id': 'reply', 'user_id': actor.id},
                chat.title,
                'answer',
            )
            return JSONResponse({'status': True})

        await access_log.AccessLogMiddleware(None).dispatch(req, endpoint)
        async with sessions() as db:
            stored = await db.get(chats.Chat, chat.id)
            assert stored.user_id == 'owner'
            assert stored.title == 'Owner title'
            assert stored.chat['models'] == before['models']
            assert stored.chat['params'] == before['params']
            assert stored.variables == before_vars
            assert stored.meta == before_meta
            assert stored.folder_id == 'owner-folder'
            rows = (await db.execute(select(ChatMessage))).scalars().all()
            assert {row.user_id for row in rows} == {'actor'}
            usage = await ChatMessages.get_user_analytics(db=db)
            assert 'owner' not in usage
            assert usage['actor']['total_tokens'] == 13

    with caplog.at_level(logging.INFO, logger='open_webui.access'):
        _in_memory(monkeypatch, scenario)
    assert len(published) == 1
    assert published[0].actor['id'] == 'actor'
    assert published[0].data['user_id'] == 'actor'
    assert f'email={actor.email}' in caplog.text
    assert 'outcome=success' in caplog.text
    assert 'email=owner' not in caplog.text


def test_collaborator_cannot_edit_others_message(monkeypatch):
    async def scenario(sessions, chat):
        owner_turn = await chats.Chats.insert_chat_turn(
            chat.id,
            SimpleNamespace(id='owner', name='Owner'),
            {'id': 'owner-prompt', 'content': 'owner content'},
            [{'message_id': 'owner-reply', 'model_id': 'owner-model'}],
        )
        assert owner_turn['messages']['owner-prompt']['user_id'] == 'owner'
        with pytest.raises(HTTPException) as regenerate:
            await chats.Chats.insert_chat_turn(
                chat.id,
                _actor(),
                {'id': 'owner-prompt', 'content': 'modified'},
                [{'message_id': 'new-reply', 'model_id': 'model'}],
            )
        assert regenerate.value.status_code == 403
        monkeypatch.setattr(chat_router.Chats, 'get_chat_by_id', AsyncMock(return_value=chat))
        with pytest.raises(HTTPException) as edit:
            await chat_router.update_chat_message_by_id(
                _request(_actor()),
                chat.id,
                'owner-prompt',
                chat_router.MessageForm(content='modified'),
                user=_actor(),
                db=None,
            )
        assert edit.value.status_code == 401
        async with sessions() as db:
            original = await db.get(ChatMessage, f'{chat.id}-owner-prompt')
            assert original.content == 'owner content'
            assert await db.get(ChatMessage, f'{chat.id}-new-reply') is None

    _in_memory(monkeypatch, scenario)
