import asyncio
import ast
import importlib.util
import sys
from contextlib import asynccontextmanager
from numbers import Number
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from sqlalchemy import Column, Table, Text, select
from sqlalchemy.dialects import sqlite
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base


def _load_chat_messages_module(monkeypatch):
    base = declarative_base()
    Table('chat', base.metadata, Column('id', Text, primary_key=True))

    @asynccontextmanager
    async def get_async_db_context(db):
        yield db

    open_webui_pkg = ModuleType('open_webui')
    open_webui_pkg.__path__ = []
    internal_pkg = ModuleType('open_webui.internal')
    internal_pkg.__path__ = []
    models_pkg = ModuleType('open_webui.models')
    models_pkg.__path__ = []
    utils_pkg = ModuleType('open_webui.utils')
    utils_pkg.__path__ = []

    internal_db = ModuleType('open_webui.internal.db')
    internal_db.Base = base
    internal_db.get_async_db_context = get_async_db_context

    response_utils = ModuleType('open_webui.utils.response')
    response_path = Path(__file__).resolve().parents[2] / 'utils' / 'response.py'
    response_ast = ast.parse(response_path.read_text())
    response_nodes = [node for node in response_ast.body if isinstance(node, (ast.FunctionDef, ast.Assign))]
    # Function globals must share the namespace with the usage constants/helpers.
    response_utils.Number = Number
    exec(compile(ast.Module(body=response_nodes, type_ignores=[]), str(response_path), 'exec'), response_utils.__dict__)

    groups_module = ModuleType('open_webui.models.groups')

    class GroupMember(base):
        __tablename__ = 'group_member'
        user_id = Column(Text, primary_key=True)
        group_id = Column(Text, primary_key=True)

    groups_module.GroupMember = GroupMember
    groups_module.membership_calls = []

    def group_user_memberships(group_ids, include_inherited=False):
        groups_module.membership_calls.append((group_ids, include_inherited))
        # This fixture represents a root and its inherited child membership.
        ids = [*group_ids, 'child'] if include_inherited else group_ids
        return select(GroupMember.user_id).where(GroupMember.group_id.in_(ids)).subquery()

    groups_module.group_user_memberships = group_user_memberships

    pydantic_module = ModuleType('pydantic')

    class BaseModel:
        @classmethod
        def model_validate(cls, value):
            return value

    class ConfigDict(dict):
        pass

    pydantic_module.BaseModel = BaseModel
    pydantic_module.ConfigDict = ConfigDict

    monkeypatch.setitem(sys.modules, 'open_webui', open_webui_pkg)
    monkeypatch.setitem(sys.modules, 'open_webui.internal', internal_pkg)
    monkeypatch.setitem(sys.modules, 'open_webui.internal.db', internal_db)
    monkeypatch.setitem(sys.modules, 'open_webui.models', models_pkg)
    monkeypatch.setitem(sys.modules, 'open_webui.models.groups', groups_module)
    monkeypatch.setitem(sys.modules, 'open_webui.utils', utils_pkg)
    monkeypatch.setitem(sys.modules, 'open_webui.utils.response', response_utils)
    monkeypatch.setitem(sys.modules, 'pydantic', pydantic_module)

    path = Path(__file__).resolve().parents[2] / 'models' / 'chat_messages.py'
    spec = importlib.util.spec_from_file_location('test_chat_messages_module', path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class _FakeAsyncDB:
    def __init__(self, rows):
        self.rows = rows
        self.statements = []

    async def connection(self):
        return SimpleNamespace(dialect=SimpleNamespace(name='sqlite'))

    async def execute(self, stmt):
        self.statements.append(stmt)
        return SimpleNamespace(all=lambda: self.rows)


def test_get_token_usage_by_model_accepts_model_id_and_filters(monkeypatch):
    module = _load_chat_messages_module(monkeypatch)
    fake_db = _FakeAsyncDB(
        [
            SimpleNamespace(
                model_id='gpt-4o-mini',
                input_tokens=11,
                output_tokens=7,
                message_count=2,
            )
        ]
    )

    usage = asyncio.run(
        module.ChatMessages.get_token_usage_by_model(
            start_date=1,
            end_date=2,
            user_id='user-1',
            model_id='gpt-4o-mini',
            db=fake_db,
        )
    )

    compiled = str(fake_db.statements[0].compile(dialect=sqlite.dialect(), compile_kwargs={'literal_binds': True}))

    assert usage == {
        'gpt-4o-mini': {
            'input_tokens': 11,
            'output_tokens': 7,
            'total_tokens': 18,
            'message_count': 2,
        }
    }
    assert "chat_message.model_id = 'gpt-4o-mini'" in compiled
    assert "chat_message.user_id = 'user-1'" in compiled


def test_usage_snapshots_do_not_double_count_and_preserve_routing(monkeypatch):
    module = _load_chat_messages_module(monkeypatch)
    message = module.ChatMessage(
        usage={'input_tokens': 10, 'output_tokens': 2, 'routing': {'requested_model_id': 'router'}}
    )
    module.ChatMessages._apply_message_data(message, {'usage': {'input_tokens': 20, 'output_tokens': 5}}, 1)
    module.ChatMessages._apply_message_data(message, {'usage': {'input_tokens': 20, 'output_tokens': 5}}, 2)
    assert message.usage['input_tokens'] == 20
    assert message.usage['output_tokens'] == 5
    assert message.usage['routing']['requested_model_id'] == 'router'


def test_metadata_only_usage_update_does_not_erase_tokens(monkeypatch):
    module = _load_chat_messages_module(monkeypatch)
    message = module.ChatMessage(usage={'input_tokens': 10, 'output_tokens': 3, 'total_tokens': 13})
    module.ChatMessages._apply_message_data(message, {'usage': {'routing': {'requested_model_id': 'router'}}}, 1)
    assert message.usage['input_tokens'] == 10
    assert message.usage['output_tokens'] == 3
    assert message.usage['total_tokens'] == 13


def _run_rows(monkeypatch, callback):
    module = _load_chat_messages_module(monkeypatch)

    async def scenario():
        engine = create_async_engine('sqlite+aiosqlite:///:memory:')
        try:
            async with engine.begin() as connection:
                await connection.run_sync(module.ChatMessage.metadata.create_all)
            async with async_sessionmaker(engine)() as db:
                await callback(module, db)
        finally:
            await engine.dispose()

    asyncio.run(scenario())


@pytest.mark.parametrize('timestamp', [1_780_000_000, 1_780_000_000_000])
def test_timestamp_actor_tokens_and_inherited_groups(monkeypatch, timestamp):
    async def scenario(module, db):
        groups = sys.modules['open_webui.models.groups']
        db.add(groups.GroupMember(user_id='actor', group_id='child'))
        for actor, tokens in [('actor', 11), ('owner', 99)]:
            await module.ChatMessages.upsert_message(
                actor,
                'shared-chat',
                actor,
                {
                    'role': 'assistant',
                    'model': 'model',
                    'timestamp': timestamp,
                    'usage': {'prompt_tokens': tokens, 'completion_tokens': 7},
                },
                db=db,
            )
        usage = await module.ChatMessages.get_token_usage_by_model(
            start_date=1_779_999_999,
            end_date=1_780_000_001,
            user_id='actor',
            model_id='model',
            group_id='root',
            db=db,
        )
        assert usage == {
            'model': {
                'input_tokens': 11,
                'output_tokens': 7,
                'total_tokens': 18,
                'message_count': 1,
            }
        }
        assert groups.membership_calls == [(['root'], True)]
        assert module._date_key(timestamp, module._timezone('UTC')) == '2026-05-28'

    _run_rows(monkeypatch, scenario)


def test_performance_error_scales_and_missing_timing(monkeypatch):
    async def scenario(module, db):
        groups = sys.modules['open_webui.models.groups']
        db.add(groups.GroupMember(user_id='actor', group_id='child'))
        for mid, error in [('ok', None), ('failed', {'content': 'interrupted'})]:
            await module.ChatMessages.upsert_message(
                mid,
                'shared-chat',
                'actor',
                {
                    'role': 'assistant',
                    'model': 'model',
                    'error': error,
                    'usage': {'input_tokens': 11, 'output_tokens': 7},
                },
                db=db,
            )
        model = (await module.ChatMessages.get_performance_metrics_by_model(user_id='actor', group_id='root', db=db))[
            'model'
        ]
        summary = await module.ChatMessages.get_performance_metrics(group_id='root', db=db)
        assert model['avg_ttft_ms'] is None
        assert model['avg_tokens_per_second'] is None
        assert model['error_rate'] == 0.5  # Model Err% multiplies by 100.
        assert summary['error_rate'] == 50.0  # Summary already displays percent.
        assert groups.membership_calls == [(['root'], True), (['root'], True)]

    _run_rows(monkeypatch, scenario)


@pytest.mark.parametrize('mode', ['selected', 'requested', 'or', 'and'])
def test_routing_filters_true_target_before_pagination(monkeypatch, mode):
    async def scenario(module, db):
        groups = sys.modules['open_webui.models.groups']
        db.add(groups.GroupMember(user_id='actor', group_id='child'))
        for index, (actor, selected, requested) in enumerate(
            [
                ('actor', 'target', 'router'),
                ('owner', 'target', 'router'),
                ('actor', 'other', 'other-router'),
            ]
        ):
            await module.ChatMessages.upsert_message(
                str(index),
                'shared-chat',
                actor,
                {
                    'role': 'assistant',
                    'model': 'display-alias',
                    'timestamp': 1_780_000_000 + index,
                    'usage': {'routing': {'selected_model_id': selected, 'requested_model_id': requested}},
                },
                db=db,
            )
        events = await module.ChatMessages.get_routing_events(
            user_id='actor',
            group_id='root',
            model_selected='target',
            model_requested='router',
            model_mode=mode,
            limit=1,
            db=db,
        )
        assert len(events) == 1
        assert events[0]['message_id'] == 'shared-chat-0'
        assert events[0]['user_id'] == 'actor'
        assert events[0]['selected_model_id'] == 'target'
        assert (
            await module.ChatMessages.get_routing_events(
                user_id='actor',
                model_selected='target',
                model_requested='router',
                model_mode=mode,
                skip=1,
                limit=1,
                db=db,
            )
            == []
        )
        assert groups.membership_calls == [(['root'], True)]

    _run_rows(monkeypatch, scenario)


def test_routing_orders_mixed_timestamp_units_chronologically(monkeypatch):
    async def scenario(module, db):
        for mid, timestamp in [('older', 1_780_000_000_000), ('newer', 1_780_000_001)]:
            await module.ChatMessages.upsert_message(
                mid,
                'chat',
                'actor',
                {
                    'role': 'assistant',
                    'model': 'model',
                    'timestamp': timestamp,
                    'usage': {'routing': {'requested_model_id': 'router', 'selected_model_id': 'model'}},
                },
                db=db,
            )
        events = await module.ChatMessages.get_routing_events(start_date=1_779_999_999, end_date=1_780_000_002, db=db)
        assert [event['message_id'] for event in events] == ['chat-newer', 'chat-older']
        assert [event['created_at'] for event in events] == [1_780_000_001, 1_780_000_000]

    _run_rows(monkeypatch, scenario)
