"""MCP contracts against the pinned SDK, with in-memory HTTP only."""

import asyncio
import builtins
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
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
                return httpx.Response(401)
            return httpx.Response(200)

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handle),
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

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(no_request),
            auth=mcp_client.OAuthTokenAuth(AsyncMock(return_value={})),
        ) as client:
            with pytest.raises(httpx.RequestError):
                await client.get('https://mcp.example.com')

    asyncio.run(run())


@pytest.mark.parametrize('modern_only', [False, True])
def test_connect_real_sdk_transport_signature_and_auth(monkeypatch, modern_only):
    module = mcp_client
    if modern_only:
        original_import = builtins.__import__

        def import_without_deprecated(name, globals=None, locals=None, fromlist=(), level=0):
            if name == 'mcp.client.streamable_http' and 'streamablehttp_client' in fromlist:
                raise ImportError('Deprecated transport removed')
            return original_import(name, globals, locals, fromlist, level)

        monkeypatch.setattr(builtins, '__import__', import_without_deprecated)
        spec = importlib.util.spec_from_file_location('mcp_modern_only', Path(mcp_client.__file__))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

    async def run():
        seen = []
        clients = []
        initialized = asyncio.Event()
        auth = httpx.BasicAuth('user', 'password')

        async def handle(request):
            assert request.headers['Authorization'].startswith('Basic ')
            assert request.headers['X-Test'] == 'configured'
            body = json.loads(request.content)
            seen.append(body['method'])
            if body['method'] == 'initialize':
                return httpx.Response(
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
            initialized.set()
            return httpx.Response(202)

        def factory(headers=None, timeout=None, auth=None):
            client = httpx.AsyncClient(
                transport=httpx.MockTransport(handle),
                headers=headers,
                auth=auth,
                timeout=timeout if timeout is not None else 30,
            )
            clients.append(client)
            return client

        monkeypatch.setattr(module, 'create_httpx_client', factory)
        monkeypatch.setattr(module, 'AIOHTTP_CLIENT_SESSION_TOOL_SERVER_SSL', True)
        client = module.MCPClient()
        await client.connect('https://mcp.example.com', headers={'X-Test': 'configured'}, auth=auth)
        assert client.instructions == 'real SDK handshake'
        await asyncio.wait_for(initialized.wait(), timeout=1)
        assert seen == ['initialize', 'notifications/initialized']
        await client.disconnect()
        await client.disconnect()
        assert client.session is None
        assert all(client.is_closed for client in clients)

    asyncio.run(run())


@pytest.mark.parametrize('failure', [TimeoutError, asyncio.CancelledError])
def test_initialize_failure_cleans_failed_session(monkeypatch, failure):
    from contextlib import asynccontextmanager

    closed = []

    @asynccontextmanager
    async def transport(*args, **kwargs):
        try:
            yield (None, None, None)
        finally:
            closed.append('transport')

    class Session:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            closed.append('session')

        async def initialize(self):
            if failure is asyncio.CancelledError:
                raise asyncio.CancelledError()
            await asyncio.sleep(60)

    monkeypatch.setattr(mcp_client, 'streamablehttp_client', transport)
    monkeypatch.setattr(mcp_client, 'ClientSession', Session)
    monkeypatch.setattr(mcp_client, 'MCP_INITIALIZE_TIMEOUT', 0.01)

    async def run():
        client = mcp_client.MCPClient()
        with pytest.raises(failure):
            await client.connect('https://mcp.example.com')
        assert client.session is None
        assert client.exit_stack is None
        assert closed == ['session', 'transport']

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
    client.session = SimpleNamespace(call_tool=AsyncMock(return_value=result))
    output = asyncio.run(client.call_tool('tool', {}))
    assert [item['text'] for item in output] == expected_texts


def test_tool_call_receives_configured_read_timeout(monkeypatch):
    monkeypatch.setattr(mcp_client, 'AIOHTTP_CLIENT_TIMEOUT_TOOL_SERVER', 4)

    async def call(name, args, *, read_timeout_seconds):
        assert read_timeout_seconds.total_seconds() == 4
        raise TimeoutError('tool timed out')

    client = mcp_client.MCPClient()
    client.session = SimpleNamespace(call_tool=call)
    with pytest.raises(TimeoutError, match='tool timed out'):
        asyncio.run(client.call_tool('slow', {}))


@pytest.mark.parametrize(('explicit', 'expected'), [(None, 8), (2, 2)])
def test_http_client_timeout_uses_explicit_or_configured_value(monkeypatch, explicit, expected):
    monkeypatch.setattr(mcp_client, 'AIOHTTP_CLIENT_TIMEOUT_TOOL_SERVER', 8)

    async def run():
        async with mcp_client.create_httpx_client(timeout=explicit) as client:
            assert client.timeout.read == expected
            assert client.timeout.connect == expected
            assert client.follow_redirects is True

    asyncio.run(run())
