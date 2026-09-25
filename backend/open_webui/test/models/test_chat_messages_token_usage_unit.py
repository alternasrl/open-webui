import asyncio
import importlib.util
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace

from sqlalchemy.dialects import sqlite
from sqlalchemy.orm import declarative_base


def _load_chat_messages_module(monkeypatch):
    base = declarative_base()

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
    response_utils.merge_usage = lambda existing, usage: usage
    response_utils.normalize_usage = lambda usage: usage

    groups_module = ModuleType('open_webui.models.groups')

    class GroupMember:
        user_id = None
        group_id = None

    groups_module.GroupMember = GroupMember

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
