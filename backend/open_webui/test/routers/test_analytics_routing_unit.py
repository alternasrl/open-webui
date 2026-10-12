import ast
import asyncio
from pathlib import Path
from typing import Optional

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


def _load_routing_helpers():
    chat_messages_path = Path(__file__).resolve().parents[2] / 'models' / 'chat_messages.py'
    source = chat_messages_path.read_text(encoding='utf-8')
    module_ast = ast.parse(source)

    helper_nodes = [
        node
        for node in module_ast.body
        if isinstance(node, ast.FunctionDef) and node.name in {'_routing_match', '_summarize_routing_pairs'}
    ]
    helper_source = '\n\n'.join(ast.get_source_segment(source, node) for node in helper_nodes)
    namespace = {'Optional': Optional}
    exec(helper_source, namespace)
    return namespace['_routing_match'], namespace['_summarize_routing_pairs']


_routing_match, _summarize_routing_pairs = _load_routing_helpers()


def test_summarize_pairs_counts_requested_selected():
    events = [
        {'requested_model_id': 'GPT-5-nano', 'selected_model_id': 'DeepSeek-V4-flash'},
        {'requested_model_id': 'GPT-5-nano', 'selected_model_id': 'DeepSeek-V4-flash'},
        {'requested_model_id': 'GPT-5-nano', 'selected_model_id': 'Mistral-large-3'},
    ]

    pairs = _summarize_routing_pairs(events)

    assert pairs[0]['requested_model_id'] == 'GPT-5-nano'
    assert pairs[0]['selected_model_id'] == 'DeepSeek-V4-flash'
    assert pairs[0]['count'] == 2
    assert pairs[0]['percentage'] == 66.67

    assert pairs[1]['requested_model_id'] == 'GPT-5-nano'
    assert pairs[1]['selected_model_id'] == 'Mistral-large-3'
    assert pairs[1]['count'] == 1
    assert pairs[1]['percentage'] == 33.33


def test_summarize_pairs_ignores_missing_requested_or_selected():
    events = [
        {'requested_model_id': None, 'selected_model_id': 'A'},
        {'requested_model_id': 'A', 'selected_model_id': None},
        {'requested_model_id': 'A', 'selected_model_id': 'B'},
    ]

    pairs = _summarize_routing_pairs(events)

    assert len(pairs) == 1
    assert pairs[0]['requested_model_id'] == 'A'
    assert pairs[0]['selected_model_id'] == 'B'
    assert pairs[0]['count'] == 1
    assert pairs[0]['percentage'] == 100.0


def test_routing_match_selected_mode():
    assert _routing_match('A', 'B', model_selected='A', model_requested=None, model_mode='selected') is True
    assert _routing_match('B', 'A', model_selected='A', model_requested=None, model_mode='selected') is False


def test_routing_match_requested_mode():
    assert _routing_match('A', 'B', model_selected=None, model_requested='B', model_mode='requested') is True
    assert _routing_match('A', 'C', model_selected=None, model_requested='B', model_mode='requested') is False


def test_routing_match_or_mode_with_dual_axis_filters():
    assert _routing_match('SEL', 'REQ', model_selected='SEL', model_requested='X', model_mode='or') is True
    assert _routing_match('SEL', 'REQ', model_selected='X', model_requested='REQ', model_mode='or') is True
    assert _routing_match('SEL', 'REQ', model_selected='X', model_requested='Y', model_mode='or') is False


def test_routing_match_and_mode_with_dual_axis_filters():
    assert _routing_match('SEL', 'REQ', model_selected='SEL', model_requested='REQ', model_mode='and') is True
    assert _routing_match('SEL', 'REQ', model_selected='SEL', model_requested='X', model_mode='and') is False
    assert _routing_match('SEL', 'REQ', model_selected='X', model_requested='REQ', model_mode='and') is False


def test_model_cross_filter_and_tokens_use_same_actor_scope(monkeypatch):
    from open_webui.internal import db as internal_db
    from open_webui.models.chats import Chat
    from open_webui.models.chat_messages import ChatMessage, ChatMessages
    from open_webui.routers import analytics

    monkeypatch.setattr(internal_db, 'DATABASE_ENABLE_SESSION_SHARING', True)

    async def scenario():
        engine = create_async_engine('sqlite+aiosqlite:///:memory:')
        try:
            async with engine.begin() as connection:
                await connection.run_sync(
                    lambda db: Chat.metadata.create_all(db, tables=[Chat.__table__, ChatMessage.__table__])
                )
            async with async_sessionmaker(engine)() as db:
                for actor in ['actor', 'owner']:
                    await ChatMessages.upsert_message(
                        actor,
                        f'chat-{actor}',
                        actor,
                        {
                            'role': 'assistant',
                            'model': 'model',
                            'timestamp': 1_780_000_000,
                            'usage': {'input_tokens': 10, 'output_tokens': 3},
                        },
                        db=db,
                    )
                response = await analytics.get_model_analytics(
                    start_date=None,
                    end_date=None,
                    group_id=None,
                    user_id='actor',
                    user=None,
                    db=db,
                )
                assert len(response.models) == 1
                assert response.models[0].count == 1
                assert response.models[0].unique_users == 1
                assert response.models[0].unique_chats == 1
                tokens = await analytics.get_token_usage(
                    start_date=None,
                    end_date=None,
                    group_id=None,
                    user_id='actor',
                    model_id='model',
                    user=None,
                    db=db,
                )
                assert tokens.total_input_tokens == 10
                assert tokens.total_output_tokens == 3
                assert tokens.total_tokens == 13
        finally:
            await engine.dispose()

    asyncio.run(scenario())
