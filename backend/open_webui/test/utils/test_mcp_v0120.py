"""MCP contracts against the pinned SDK, with in-memory HTTP only."""

import asyncio
import json
import math
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx2
import pytest
from mcp.types import CallToolResult, ElicitRequestFormParams, ElicitRequestURLParams
from open_webui.utils.mcp import client as mcp_client


@pytest.fixture(autouse=True)
def isolated_proxy_environment(monkeypatch):
    for name in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY'):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)


@pytest.mark.parametrize(
    ('rotated', 'status', 'tokens'),
    [
        (False, 401, ['Bearer old']),
        (True, 200, ['Bearer old', 'Bearer new']),
    ],
)
def test_oauth_retries_401_only_after_token_rotation(rotated, status, tokens):
    async def run():
        current = 'Bearer old'
        seen = []

        async def headers():
            return {'Authorization': current}

        async def handle(request):
            nonlocal current
            seen.append(request.headers['Authorization'])
            if len(seen) == 1:
                if rotated:
                    current = 'Bearer new'
                return httpx2.Response(401)
            return httpx2.Response(200)

        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handle),
            auth=mcp_client.OAuthTokenAuth(headers),
        ) as client:
            response = await client.post('https://mcp.example.com', content=b'replayable')
        assert response.status_code == status
        assert seen == tokens

    asyncio.run(run())


def test_oauth_missing_token_never_sends_request():
    async def run():
        def no_request(request):
            pytest.fail('Missing token must fail before transport')

        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(no_request),
            auth=mcp_client.OAuthTokenAuth(AsyncMock(return_value={})),
        ) as client:
            with pytest.raises(httpx2.RequestError):
                await client.get('https://mcp.example.com')

    asyncio.run(run())


def test_connect_real_sdk_transport_signature_and_auth(monkeypatch):
    async def run():
        seen = []
        clients = []
        auth = httpx2.BasicAuth('user', 'password')

        async def handle(request):
            assert request.headers['Authorization'].startswith('Basic ')
            assert request.headers['X-Test'] == 'configured'
            if request.method != 'POST':
                return httpx2.Response(405)
            body = json.loads(request.content)
            seen.append(body['method'])
            if body['method'] == 'server/discover':
                # A legacy server: the SDK falls back to the initialize handshake.
                return httpx2.Response(
                    200,
                    json={'jsonrpc': '2.0', 'id': body['id'], 'error': {'code': -32601, 'message': 'Method not found'}},
                )
            if body['method'] == 'initialize':
                return httpx2.Response(
                    200,
                    json={
                        'jsonrpc': '2.0',
                        'id': body['id'],
                        'result': {
                            'protocolVersion': '2025-11-25',
                            'capabilities': {},
                            'serverInfo': {'name': 'mock', 'version': '1'},
                            'instructions': 'real SDK handshake',
                        },
                    },
                )
            return httpx2.Response(202)

        def factory(headers=None, auth=None):
            client = httpx2.AsyncClient(transport=httpx2.MockTransport(handle), headers=headers, auth=auth)
            clients.append(client)
            return client

        monkeypatch.setattr(mcp_client, 'create_httpx_client', factory)
        client = mcp_client.MCPClient()
        await client.connect('https://mcp.example.com', headers={'X-Test': 'configured'}, auth=auth)
        assert client.instructions == 'real SDK handshake'
        assert 'initialize' in seen
        await client.disconnect()
        await client.disconnect()
        assert client.client is None
        assert all(client.is_closed for client in clients)

    asyncio.run(run())


@pytest.mark.parametrize('failure', [TimeoutError, asyncio.CancelledError])
def test_initialize_failure_cleans_failed_session(monkeypatch, failure):
    clients = []

    def factory(headers=None, auth=None):
        client = httpx2.AsyncClient(transport=httpx2.MockTransport(lambda request: httpx2.Response(500)))
        clients.append(client)
        return client

    class FailingClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            raise failure()

        async def __aexit__(self, *args):
            pass

    monkeypatch.setattr(mcp_client, 'create_httpx_client', factory)
    monkeypatch.setattr(mcp_client, 'Client', FailingClient)

    async def run():
        client = mcp_client.MCPClient()
        with pytest.raises(failure):
            await client.connect('https://mcp.example.com')
        assert client.client is None
        assert client.exit_stack is None
        assert client.instructions is None
        assert [c.is_closed for c in clients] == [True]

    asyncio.run(run())


@pytest.mark.parametrize(
    ('response', 'action', 'content'),
    [
        ({'action': 'accept', 'content': {'age': 21}}, 'accept', {'age': 21}),
        ({'action': 'accept', 'content': {'age': '21'}}, 'cancel', None),
        ({'action': 'accept', 'content': {'age': -1}}, 'cancel', None),
        ({'action': 'decline', 'content': {'age': 21}}, 'decline', None),
        ({'action': 'cancel'}, 'cancel', None),
        ({'action': 'unexpected'}, 'cancel', None),
        (None, 'cancel', None),
    ],
)
def test_elicitation_validates_without_coercing(response, action, content):
    params = ElicitRequestFormParams(
        message='Age?',
        requestedSchema={
            'type': 'object',
            'properties': {'age': {'type': 'integer', 'minimum': 0}},
            'required': ['age'],
            'additionalProperties': False,
        },
    )
    result = asyncio.run(
        mcp_client.MCPClient(
            event_caller=AsyncMock(return_value=response),
            server_name='mock',
        ).elicit(None, params)
    )
    assert result.action == action
    assert result.content == content


@pytest.mark.parametrize(
    'schema',
    [
        {'type': 'not-a-json-type'},
        {'$ref': 'https://schema.example.com/private.json'},
    ],
)
def test_invalid_or_remote_elicitation_schema_is_cancelled(schema):
    params = ElicitRequestFormParams(message='Question', requestedSchema=schema)
    result = asyncio.run(
        mcp_client.MCPClient(
            event_caller=AsyncMock(return_value={'action': 'accept', 'content': {}}),
        ).elicit(None, params)
    )
    assert result.action == 'cancel'


@pytest.mark.parametrize(
    'url',
    [
        'file:///etc/passwd',
        'https://user:secret@example.com/',
        'https://example.com:invalid/',
        'https://example.com:65536/',
        'https://example.com\\@other.example.com/',
        'https://example.com/\r\nlogin',
        'https://example.com/\tlogin',
    ],
)
def test_unsafe_url_elicitation_is_cancelled_before_prompt(url):
    prompted = []

    async def no_prompt(event):
        prompted.append(event)
        return {'action': 'accept'}

    params = ElicitRequestURLParams(message='Login', url=url, elicitationId='login')
    assert asyncio.run(mcp_client.MCPClient(event_caller=no_prompt).elicit(None, params)).action == 'cancel'
    assert prompted == []


def test_valid_url_elicitation_has_no_form_content():
    params = ElicitRequestURLParams(
        message='Login',
        url='https://example.com/login',
        elicitationId='login',
    )
    result = asyncio.run(
        mcp_client.MCPClient(
            event_caller=AsyncMock(return_value={'action': 'accept', 'content': {'ignored': True}}),
        ).elicit(None, params)
    )
    assert result.action == 'accept'
    assert result.content is None


def test_event_failure_cancels_elicitation():
    params = ElicitRequestFormParams(message='Question', requestedSchema={'type': 'object'})
    result = asyncio.run(
        mcp_client.MCPClient(
            event_caller=AsyncMock(side_effect=TimeoutError('UI timed out')),
        ).elicit(None, params)
    )
    assert result.action == 'cancel'


@pytest.mark.parametrize(
    ('texts', 'structured', 'expected_texts'),
    [
        (['{"a":1}'], {'a': 1}, ['{"a":1}']),
        (['true'], {'result': True}, ['true']),
        (['1', '2'], {'result': [1, 2]}, ['1', '2']),
        (['hello'], {'result': 'hello'}, ['hello']),
        (['true'], {'result': 1}, ['true', '{"result": 1}']),
        (['unrelated'], {'a': 1}, ['unrelated', '{"a": 1}']),
    ],
)
def test_structured_content_is_appended_only_when_not_already_present(texts, structured, expected_texts):
    result = CallToolResult(
        content=[{'type': 'text', 'text': text} for text in texts],
        structuredContent=structured,
    )
    client = mcp_client.MCPClient()
    client.client = SimpleNamespace(call_tool=AsyncMock(return_value=result))
    output = asyncio.run(client.call_tool('tool', {}))
    assert [item['text'] for item in output] == expected_texts


def test_tool_call_receives_configured_read_timeout(monkeypatch):
    monkeypatch.setattr(mcp_client, 'AIOHTTP_CLIENT_TIMEOUT_TOOL_SERVER', 4)

    async def call(name, args, *, read_timeout_seconds):
        assert read_timeout_seconds == 4
        raise TimeoutError('tool timed out')

    client = mcp_client.MCPClient()
    client.client = SimpleNamespace(call_tool=call)
    with pytest.raises(TimeoutError, match='tool timed out'):
        asyncio.run(client.call_tool('slow', {}))


def test_tool_call_without_configured_timeout_is_unbounded(monkeypatch):
    monkeypatch.setattr(mcp_client, 'AIOHTTP_CLIENT_TIMEOUT_TOOL_SERVER', None)

    async def call(name, args, *, read_timeout_seconds):
        assert read_timeout_seconds == math.inf
        raise TimeoutError('tool timed out')

    client = mcp_client.MCPClient()
    client.client = SimpleNamespace(call_tool=call)
    with pytest.raises(TimeoutError):
        asyncio.run(client.call_tool('slow', {}))


def test_http_client_keeps_sdk_timeouts_and_configured_tls(monkeypatch):
    monkeypatch.setattr(mcp_client, 'AIOHTTP_CLIENT_SESSION_TOOL_SERVER_SSL', False)

    async def run():
        async with mcp_client.create_httpx_client(headers={'X-Test': '1'}) as client:
            assert client.timeout.connect == 30
            assert client.timeout.read == 300
            assert client.headers['X-Test'] == '1'

    asyncio.run(run())
