import ast
import asyncio
import copy
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route


def _load_merge_routing_usage():
    middleware_path = Path(__file__).resolve().parents[2] / 'utils' / 'middleware.py'
    source = middleware_path.read_text(encoding='utf-8')
    module_ast = ast.parse(source)

    fn_node = next(
        node for node in module_ast.body if isinstance(node, ast.FunctionDef) and node.name == 'merge_routing_usage'
    )
    fn_source = ast.get_source_segment(source, fn_node)
    namespace = {}
    exec(fn_source, namespace)
    return namespace['merge_routing_usage']


merge_routing_usage = _load_merge_routing_usage()


def test_merge_routing_usage_adds_requested_model_id():
    usage = {'input_tokens': 10, 'output_tokens': 5}
    metadata = {
        'routing': {'requested_model_id': 'GPT-5-nano', 'selected_model_id': 'DeepSeek-V4-flash', 'routed': True}
    }

    result = merge_routing_usage(usage, metadata)

    assert result['input_tokens'] == 10
    assert result['output_tokens'] == 5
    assert result['routing']['requested_model_id'] == 'GPT-5-nano'
    assert result['routing']['selected_model_id'] == 'DeepSeek-V4-flash'
    assert result['routing']['routed'] is True


def test_merge_routing_usage_passthrough_same_model():
    """When routed=False (same model), flag is preserved from metadata."""
    usage = {'input_tokens': 5}
    metadata = {'routing': {'requested_model_id': 'council', 'selected_model_id': 'council', 'routed': False}}

    result = merge_routing_usage(usage, metadata)

    assert result['routing']['requested_model_id'] == 'council'
    assert result['routing']['selected_model_id'] == 'council'
    assert result['routing']['routed'] is False


def test_merge_routing_usage_noop_without_routing_metadata():
    usage = {'input_tokens': 7, 'output_tokens': 3}

    result = merge_routing_usage(usage, {'model': {'id': 'some-model'}})

    assert result == usage
    assert 'routing' not in result


@pytest.fixture
def pipeline(monkeypatch):
    from open_webui.utils import middleware

    saved, emitted = [], []

    async def save(chat_id, message_id, data, **kwargs):
        saved.append(copy.deepcopy(data))

    async def emit(event):
        emitted.append(copy.deepcopy(event))

    async def config(key, default=None):
        return default

    monkeypatch.setattr(middleware, 'ENABLE_FUNCTIONS', False)
    monkeypatch.setattr(middleware.Config, 'get', config)
    monkeypatch.setattr(middleware, 'get_system_oauth_token', AsyncMock(return_value=None))
    monkeypatch.setattr(middleware.Chats, 'upsert_message_to_chat_by_id_and_message_id', save)
    monkeypatch.setattr(middleware.Chats, 'get_message_by_id_and_message_id', AsyncMock(return_value={}))
    monkeypatch.setattr(middleware.Chats, 'get_chat_title_by_id', AsyncMock(return_value='Owner title'))
    monkeypatch.setattr(middleware.Chats, 'get_chat_folder_id', AsyncMock(return_value=None))
    monkeypatch.setattr(middleware, 'get_event_emitter', AsyncMock(return_value=None))
    monkeypatch.setattr(middleware, 'publish_event', AsyncMock())
    monkeypatch.setattr(middleware, 'save_response_stream', AsyncMock())
    monkeypatch.setattr(middleware, 'clear_response_stream', AsyncMock())
    monkeypatch.setattr(middleware, 'outlet_filter_handler', AsyncMock())
    monkeypatch.setattr(middleware, 'background_tasks_handler', AsyncMock())
    ctx = {
        'request': SimpleNamespace(
            state=SimpleNamespace(), app=SimpleNamespace(state=SimpleNamespace(redis=None, MODELS={}))
        ),
        'user': SimpleNamespace(id='actor', name='Collaborator', role='user'),
        'model': {'id': 'selected'},
        'form_data': {'model': 'selected', 'messages': [{'role': 'user', 'content': 'hello'}]},
        'metadata': {
            'chat_id': 'shared-chat',
            'message_id': 'reply',
            'user_id': 'actor',
            'params': {'reasoning_tags': False},
            'routing': {'requested_model_id': 'router', 'selected_model_id': 'selected', 'routed': True},
        },
        'events': [],
        'event_emitter': emit,
        'event_caller': None,
        'tasks': None,
    }
    return middleware, ctx, saved, emitted


def _stream(payloads, *, cancelled=False):
    async def chunks():
        for payload in payloads:
            yield f'data: {json.dumps(payload)}\n\n'
        if cancelled:
            raise asyncio.CancelledError()
        yield 'data: [DONE]\n\n'

    return StreamingResponse(chunks(), media_type='text/event-stream')


def _usage_payload(input_tokens=10, output_tokens=3):
    return {'usage': {'prompt_tokens': input_tokens, 'completion_tokens': output_tokens}, 'choices': []}


def test_nonstreaming_routes_usage_in_response_events_and_persistence(pipeline):
    middleware, ctx, saved, emitted = pipeline
    response = {
        'choices': [{'message': {'content': 'answer'}, 'finish_reason': 'stop'}],
        'usage': {'prompt_tokens': 10, 'completion_tokens': 3},
    }
    result = asyncio.run(middleware.non_streaming_chat_response_handler(response, ctx))
    assert result['usage']['routing'] == ctx['metadata']['routing']
    assert saved[-1]['usage']['input_tokens'] == 10
    assert saved[-1]['usage']['output_tokens'] == 3
    assert [event['data']['usage'] for event in emitted if event['data'].get('usage')]
    assert all(
        event['data']['usage']['routing'] == ctx['metadata']['routing']
        for event in emitted
        if event['data'].get('usage')
    )


@pytest.mark.parametrize('cancelled', [False, True])
@pytest.mark.parametrize('with_usage', [False, True])
@pytest.mark.parametrize('responses_api', [False, True])
def test_streaming_interruption_preserves_routing_and_known_usage(pipeline, cancelled, with_usage, responses_api):
    middleware, ctx, saved, emitted = pipeline
    payloads = [{'choices': [{'delta': {'content': 'partial'}}]}]
    if with_usage:
        payloads.append(
            {
                'type': 'response.completed',
                'response': {
                    'id': 'response-id',
                    'usage': {'input_tokens': 10, 'output_tokens': 3},
                },
            }
            if responses_api
            else _usage_payload()
        )

    async def scenario():
        if cancelled:
            with pytest.raises(asyncio.CancelledError):
                await middleware.streaming_chat_response_handler(_stream(payloads, cancelled=True), ctx)
        else:
            await middleware.streaming_chat_response_handler(_stream(payloads), ctx)

    asyncio.run(scenario())
    assert saved[-1]['usage']['routing'] == ctx['metadata']['routing']
    assert saved[-1]['usage'].get('input_tokens', 0) == (10 if with_usage else 0)
    assert saved[-1]['usage'].get('output_tokens', 0) == (3 if with_usage else 0)
    assert 'ttft_ms' not in saved[-1]['usage']
    assert 'tokens_per_second' not in saved[-1]['usage']


def test_nonstreaming_provider_error_records_routing(pipeline):
    middleware, ctx, saved, _ = pipeline
    result = asyncio.run(middleware.non_streaming_chat_response_handler({'error': {'detail': 'provider error'}}, ctx))
    assert result['usage']['routing'] == ctx['metadata']['routing']
    assert saved[-1]['error'] == {'content': 'provider error'}
    assert saved[-1]['usage']['routing'] == ctx['metadata']['routing']


def test_nonstreaming_api_json_response_records_routing(pipeline):
    middleware, ctx, _, _ = pipeline
    ctx['event_emitter'] = None
    response = JSONResponse(
        {
            'choices': [{'message': {'content': 'answer'}}],
            'usage': {'prompt_tokens': 10, 'completion_tokens': 3},
        }
    )
    result = asyncio.run(middleware.non_streaming_chat_response_handler(response, ctx))
    assert json.loads(result.body)['usage']['routing'] == ctx['metadata']['routing']


@pytest.mark.parametrize('provider_error', [False, True])
@pytest.mark.parametrize('api_path', [False, True])
@pytest.mark.parametrize('content_encoding', [None, 'gzip'])
def test_rewritten_json_response_transmits_correct_headers(pipeline, provider_error, api_path, content_encoding):
    middleware, ctx, _, _ = pipeline
    if api_path:
        ctx['event_emitter'] = None
    payload = (
        {'error': {'detail': 'provider error'}}
        if provider_error
        else {
            'choices': [{'message': {'content': 'answer'}}],
            'usage': {'prompt_tokens': 10, 'completion_tokens': 3},
        }
    )
    headers = {'X-Provider-Request-Id': 'provider-request', 'Retry-After': '3'}
    if content_encoding:
        headers['Content-Encoding'] = content_encoding
    upstream = JSONResponse(payload, status_code=429 if provider_error else 200, headers=headers)
    upstream.set_cookie('provider-session', 'session')
    upstream.set_cookie('provider-affinity', 'affinity')

    async def endpoint(request):
        return await middleware.non_streaming_chat_response_handler(upstream, ctx)

    async def scenario():
        app = Starlette(routes=[Route('/', endpoint)])
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as client:
            response = await client.get('/')
        assert response.status_code == upstream.status_code
        assert response.headers['x-provider-request-id'] == 'provider-request'
        assert response.headers['retry-after'] == '3'
        assert response.headers.get_list('set-cookie') == upstream.headers.getlist('set-cookie')
        assert 'content-encoding' not in response.headers
        assert int(response.headers['content-length']) == len(response.content)
        assert response.json()['usage']['routing'] == ctx['metadata']['routing']
        if provider_error:
            assert response.json()['error'] == payload['error']
        else:
            assert response.json()['usage']['input_tokens'] == 10
            assert response.json()['usage']['output_tokens'] == 3

    asyncio.run(scenario())


@pytest.mark.parametrize('wrapper', ['middleware', 'ollama'])
def test_rewritten_stream_drops_upstream_body_headers(pipeline, monkeypatch, wrapper):
    middleware, ctx, _, _ = pipeline
    ctx['event_emitter'] = None
    ctx['events'] = [{'notice': 'extra event'}]
    upstream = _stream([_usage_payload()])
    if wrapper == 'ollama':
        from open_webui.utils import chat

        async def chunks():
            yield json.dumps({'model': 'selected', 'message': {'content': 'converted'}, 'done': True})

        upstream = StreamingResponse(chunks(), media_type='application/x-ndjson')
        ctx['request'].app.state.MODELS = {'selected': {'id': 'selected', 'owned_by': 'ollama'}}
        monkeypatch.setattr(chat, 'generate_ollama_chat_completion', AsyncMock(return_value=upstream))
        monkeypatch.setattr(chat.Models, 'get_model_by_id', AsyncMock(return_value=None))

    upstream.headers['Content-Length'] = '1'
    upstream.headers['Content-Encoding'] = 'gzip'
    upstream.headers['X-Provider-Request-Id'] = 'provider-request'

    async def endpoint(request):
        if wrapper == 'ollama':
            return await chat.generate_chat_completion(
                ctx['request'], {**ctx['form_data'], 'stream': True}, ctx['user'], bypass_filter=True
            )
        return await middleware.streaming_chat_response_handler(upstream, ctx)

    async def scenario():
        app = Starlette(routes=[Route('/', endpoint)])
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as client:
            response = await client.get('/')
        assert response.status_code == 200
        assert 'content-length' not in response.headers
        assert 'content-encoding' not in response.headers
        assert response.headers['x-provider-request-id'] == 'provider-request'
        assert 'data: [DONE]' in response.text
        assert ('converted' if wrapper == 'ollama' else 'extra event') in response.text

    asyncio.run(scenario())


def test_nonstreaming_continuation_adds_only_new_provider_call(pipeline):
    middleware, ctx, saved, _ = pipeline
    ctx['metadata']['assistant_message_id'] = 'reply'
    ctx['assistant_message'] = {'content': 'before', 'usage': {'input_tokens': 5, 'output_tokens': 2}}
    response = {
        'choices': [{'message': {'content': 'after'}}],
        'usage': {'prompt_tokens': 10, 'completion_tokens': 3},
    }
    asyncio.run(middleware.non_streaming_chat_response_handler(response, ctx))
    assert saved[-1]['usage']['input_tokens'] == 15
    assert saved[-1]['usage']['output_tokens'] == 5


def test_streaming_continuation_keeps_previous_usage(pipeline):
    middleware, ctx, saved, _ = pipeline
    ctx['metadata']['assistant_message_id'] = 'reply'
    ctx['assistant_message'] = {'content': 'before', 'usage': {'input_tokens': 5, 'output_tokens': 2}}
    asyncio.run(middleware.streaming_chat_response_handler(_stream([_usage_payload()]), ctx))
    assert saved[-1]['usage']['input_tokens'] == 15
    assert saved[-1]['usage']['output_tokens'] == 5


def test_api_outlet_stream_retains_routing(pipeline, monkeypatch):
    middleware, ctx, _, _ = pipeline
    monkeypatch.setattr(middleware, 'ENABLE_API_OUTLET_FILTERS', True)
    ctx['model']['pipeline'] = True
    ctx['event_emitter'] = None

    async def scenario():
        response = await middleware.streaming_chat_response_handler(_stream([_usage_payload()]), ctx)
        async for _ in response.body_iterator:
            pass

    asyncio.run(scenario())
    assert ctx['assistant_message']['usage']['routing'] == ctx['metadata']['routing']


def test_multiple_native_tool_rounds_count_each_provider_call_once(pipeline, monkeypatch):
    middleware, ctx, saved, _ = pipeline
    ctx['metadata']['tools'] = {'lookup': {'spec': {'name': 'lookup'}}}
    ctx['metadata']['tool_approval_mode'] = 'full'

    def tool_round(index):
        return _stream(
            [
                {
                    'choices': [
                        {
                            'delta': {
                                'tool_calls': [
                                    {
                                        'index': 0,
                                        'id': f'call-{index}',
                                        'type': 'function',
                                        'function': {'name': 'lookup', 'arguments': '{}'},
                                    }
                                ]
                            },
                            'finish_reason': 'tool_calls',
                        }
                    ]
                },
                _usage_payload(10, 3),
            ]
        )

    replies = [
        tool_round(2),
        _stream(
            [
                {'choices': [{'delta': {'content': 'answer'}, 'finish_reason': 'stop'}]},
                _usage_payload(10, 3),
            ]
        ),
    ]
    monkeypatch.setattr(middleware, 'generate_chat_completion', AsyncMock(side_effect=replies))
    monkeypatch.setattr(
        middleware,
        'execute_tool_call',
        AsyncMock(
            return_value=(
                {},
                'tool answer',
                {},
                'function',
                False,
            )
        ),
    )

    async def compact(request, user, messages, *args):
        return messages, None, False

    monkeypatch.setattr(middleware, 'compact_messages_for_request', compact)
    asyncio.run(middleware.streaming_chat_response_handler(tool_round(1), ctx))
    assert saved[-1]['usage']['input_tokens'] == 30
    assert saved[-1]['usage']['output_tokens'] == 9
    assert saved[-1]['usage']['routing'] == ctx['metadata']['routing']
    assert middleware.generate_chat_completion.await_count == 2


def test_approval_pause_and_resume_preserve_cumulative_usage(pipeline):
    middleware, ctx, saved, _ = pipeline
    ctx['metadata']['params']['tool_approval_mode'] = 'ask'
    response = _stream(
        [
            {
                'choices': [
                    {
                        'delta': {
                            'tool_calls': [
                                {
                                    'index': 0,
                                    'id': 'approval-call',
                                    'type': 'function',
                                    'function': {'name': 'dynamic_tool', 'arguments': '{}'},
                                }
                            ]
                        },
                        'finish_reason': 'tool_calls',
                    }
                ]
            },
            _usage_payload(),
        ]
    )
    asyncio.run(middleware.streaming_chat_response_handler(response, ctx))
    paused = saved[-1]
    assert paused['done'] is False
    assert paused['output'][-1]['status'] == 'pending'
    assert paused['usage']['input_tokens'] == 10
    assert paused['usage']['output_tokens'] == 3
    assert paused['usage']['routing'] == ctx['metadata']['routing']
    ctx['metadata']['assistant_message_id'] = 'reply'
    ctx['metadata']['params']['tool_approval_mode'] = 'full'
    ctx['assistant_message'] = paused
    asyncio.run(middleware.streaming_chat_response_handler(_stream([_usage_payload()]), ctx))
    assert saved[-1]['usage']['input_tokens'] == 20
    assert saved[-1]['usage']['output_tokens'] == 6


@pytest.mark.parametrize('api_outlet', [False, True])
def test_usage_updates_within_one_provider_call_are_snapshots(pipeline, monkeypatch, api_outlet):
    middleware, ctx, saved, _ = pipeline
    if api_outlet:
        ctx['event_emitter'] = None
        ctx['model']['pipeline'] = True
        monkeypatch.setattr(middleware, 'ENABLE_API_OUTLET_FILTERS', True)

    async def scenario():
        response = await middleware.streaming_chat_response_handler(
            _stream([_usage_payload(10, 3), _usage_payload(10, 5), {'timings': {'ttft_ms': 42}, 'choices': []}]), ctx
        )
        if api_outlet:
            async for _ in response.body_iterator:
                pass

    asyncio.run(scenario())
    usage = ctx['assistant_message']['usage'] if api_outlet else saved[-1]['usage']
    assert usage['input_tokens'] == 10
    assert usage['output_tokens'] == 5
    assert usage['total_tokens'] == 15
    assert usage['ttft_ms'] == 42
    assert usage['routing'] == ctx['metadata']['routing']
