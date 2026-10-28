"""Mounted NIS2 wiring and dual-audit privacy, without startup or external I/O."""

import asyncio
import json
import logging
import re
import time
from dataclasses import asdict
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi import HTTPException, Request
from open_webui.main import app
from open_webui.middleware import access_log
from open_webui.models.channels import ChannelModel
from open_webui.models.users import UserModel
from open_webui.routers import apps, channels
from open_webui.utils import audit, auth
from open_webui.utils.asgi_middleware import AppHTTPMiddleware

from middleware.access_log_route_coverage import REQUIRED_ACTIONS


@pytest.fixture
def mounted(monkeypatch, caplog):
    user = UserModel(
        id='actor',
        email='actor@example.com',
        name='Actor',
        role='admin',
        last_active_at=0,
        updated_at=0,
        created_at=0,
    )
    db = MagicMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    db.execute = AsyncMock()
    db.scalar = AsyncMock(return_value=None)
    entries = []

    async def identity(request: Request):
        request.state.user = user
        request.state.oidc_audit_claims = {'sub': 'subject', 'mfa': 'pwd,otp'}
        return user

    async def database():
        yield db

    async def config(key, default=None):
        return True if key in {'apps.enable', 'channels.enable'} else default

    monkeypatch.setattr(
        app,
        'dependency_overrides',
        {
            **app.dependency_overrides,
            auth.get_admin_user: identity,
            auth.get_verified_user: identity,
            apps.get_async_session: database,
        },
    )
    monkeypatch.setattr(apps.Config, 'get', config)
    monkeypatch.setattr(
        access_log,
        '_resolve_user_context',
        AsyncMock(return_value=access_log._UserContext(user.email, 'subject', 'pwd,otp', user.role)),
    )
    monkeypatch.setattr(audit.AuditLogger, 'write', lambda self, entry, **kwargs: entries.append(asdict(entry)))
    # Install neither replacement routers nor replacement middleware: exercise
    # the same app/routes/ordering that main.py actually registered.
    logger = logging.getLogger('open_webui.access')
    logger.addHandler(caplog.handler)
    caplog.set_level(logging.INFO, logger='open_webui.access')

    async def request(method, path, **kwargs):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url='http://testserver',
            headers={'Authorization': 'Bearer test-only', 'X-Request-ID': 'request-4'},
        ) as client:
            return await client.request(method, path, **kwargs)

    try:
        yield SimpleNamespace(user=user, db=db, entries=entries, request=request, logs=caplog)
    finally:
        logger.removeHandler(caplog.handler)


def assert_event(mounted, action, status, object_ref):
    messages = [record.getMessage() for record in mounted.logs.records if record.name == 'open_webui.access']
    event = next(message for message in reversed(messages) if f'action={action} |' in message)
    outcome = 'error' if status >= 500 else 'failure' if status >= 400 else 'success'
    assert f'outcome={outcome}' in event
    assert 'email=actor@example.com' in event
    assert 'correlation_id=request-4' in event
    assert f'object={object_ref} |' in event
    assert ('EXCEPTION' if status == 500 else f'" {status} |') in event
    return event


def app_payload():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    public_key = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return {
        'slug': 'test-app',
        'url': 'https://app.invalid',
        'api_key': 'api-key-secret',
        'manifest': {
            'id': 'manifest-id',
            'name': 'Application',
            'public_key': public_key,
            'description': 'manifest-content-secret',
            'requested_scopes': [],
        },
        'granted_scopes': [],
    }


@pytest.mark.parametrize('failure', [None, 409, 500])
def test_real_mounted_app_creation_records_returned_id_and_failure(mounted, monkeypatch, failure):
    from sqlalchemy.exc import IntegrityError

    monkeypatch.setattr(apps, 'validate_app_url', MagicMock())
    cipher = MagicMock()
    cipher.encrypt.return_value = b'ciphertext-secret'
    monkeypatch.setattr(apps, 'get_app_encryption_cipher', lambda: cipher)
    monkeypatch.setattr(apps.AccessGrants, 'replace_access_grants', AsyncMock())
    if failure == 409:
        mounted.db.commit.side_effect = IntegrityError('private-query-secret', {}, Exception('private-error-secret'))
    elif failure == 500:
        mounted.db.commit.side_effect = RuntimeError('private-error-secret')

    response = asyncio.run(mounted.request('POST', '/api/v1/apps?key=query-secret', json=app_payload()))
    assert response.status_code == (failure or 200)
    object_ref = 'app:' + response.json()['id'] if not failure else '-:-'
    assert_event(mounted, 'APP_CREATE', response.status_code, object_ref)
    assert response.headers.get('X-Session-ID') or failure == 500
    classes = [item.cls for item in app.user_middleware]
    assert classes.count(access_log.AccessLogMiddleware) == 1
    assert classes.index(AppHTTPMiddleware) < classes.index(access_log.AccessLogMiddleware)
    if audit.AuditLoggingMiddleware in classes:
        assert classes.index(AppHTTPMiddleware) < classes.index(audit.AuditLoggingMiddleware)
        assert classes.index(audit.AuditLoggingMiddleware) < classes.index(access_log.AccessLogMiddleware)
        assert len(mounted.entries) == 1
        entry = mounted.entries[0]
        assert entry['user']['id'] == 'actor'
        assert entry['request_object'] == entry['response_object'] == ''
        assert entry['response_status_code'] == response.status_code
    assert '-secret' not in mounted.logs.text + json.dumps(mounted.entries)


@pytest.mark.parametrize('denied', [False, True])
@pytest.mark.parametrize('method', ['POST', 'DELETE'])
def test_channel_app_logs_both_identifiers_without_context(mounted, monkeypatch, method, denied):
    app_model = SimpleNamespace(
        id='app-target',
        slug='test-app',
        name='Application',
        is_active=True,
        data={'context': 'interaction-context-secret'},
        api_key='api-key-secret',
        created_at=0,
        updated_at=0,
    )
    check = AsyncMock(side_effect=HTTPException(403, 'Denied') if denied else None)
    monkeypatch.setattr(channels, 'check_app_channel_access', check)
    monkeypatch.setattr(channels, 'get_app_by_id', AsyncMock(return_value=app_model))
    monkeypatch.setattr(channels, 'has_app_access', AsyncMock(return_value=True))
    path = '/api/v1/channels/channel-target/apps'
    kwargs = {'json': {'app_id': 'app-target'}} if method == 'POST' else {}
    if method == 'DELETE':
        path += '/app-target'
    response = asyncio.run(mounted.request(method, path, **kwargs))
    assert response.status_code == (403 if denied else 200)
    event = assert_event(
        mounted,
        'CHANNEL_APP_ADD' if method == 'POST' else 'CHANNEL_APP_REMOVE',
        response.status_code,
        'channel:channel-target',
    )
    assert 'app_id=app-target' in event
    assert '-secret' not in mounted.logs.text + json.dumps(mounted.entries)


@pytest.mark.parametrize('suffix', ['search', 'count'])
@pytest.mark.parametrize('status', [200, 403])
def test_file_user_collections_never_log_user_as_file_id(mounted, monkeypatch, suffix, status):
    from open_webui.routers import files

    # Exercise the actual mounted handler, including its non-2xx outcome.
    # Fail at the data boundary, not by replacing the endpoint/router.
    boundary = AsyncMock(
        return_value=[] if suffix == 'search' else 4,
        side_effect=HTTPException(403, 'Denied') if status == 403 else None,
    )
    if suffix == 'search':
        monkeypatch.setattr(files, '_search_files', boundary)
    else:
        monkeypatch.setattr(files.Files, 'count_files_by_user_id', boundary)
    response = asyncio.run(mounted.request('GET', f'/api/v1/files/user/{suffix}?query=query-secret'))
    assert response.status_code == status
    assert_event(
        mounted, 'FILES_SEARCH_READ' if suffix == 'search' else 'FILES_COUNT_READ', response.status_code, '-:-'
    )
    assert 'file:user' not in mounted.logs.text
    assert 'query-secret' not in mounted.logs.text + json.dumps(mounted.entries)


@pytest.mark.parametrize(
    ('method', 'suffix', 'body', 'action'),
    [
        ('POST', 'update', {'name': 'Work', 'data': {'ciphertext': 'ciphertext-secret'}}, 'CHANNEL_UPDATE'),
        ('POST', 'access/update', {'access_grants': []}, 'CHANNEL_ACCESS_UPDATE'),
        ('DELETE', 'delete', None, 'CHANNEL_DELETE'),
        ('POST', 'update/members/remove', {'user_ids': ['former-member']}, 'CHANNEL_MEMBER_REMOVE'),
        ('POST', 'members/active', {'is_active': False}, 'CHANNEL_MEMBER_ACTIVE'),
    ],
)
@pytest.mark.parametrize('denied', [False, True])
def test_channel_mutation_keeps_invalidation_events_and_private_audits(
    mounted, monkeypatch, method, suffix, body, action, denied
):
    channel = ChannelModel(
        id='channel-target',
        user_id='owner' if denied else 'actor',
        type='standard' if suffix == 'access/update' else 'group',
        is_private=True,
        name='Work',
        description='channel-content-secret',
        data={'ciphertext': 'ciphertext-secret'},
        created_at=0,
        updated_at=0,
    )
    if denied:
        mounted.user.role = 'user'
    monkeypatch.setattr(channels, 'has_permission', AsyncMock(return_value=True))
    monkeypatch.setattr(channels.Channels, 'get_channel_by_id', AsyncMock(return_value=channel))
    monkeypatch.setattr(channels.Channels, 'is_user_channel_member', AsyncMock(return_value=not denied))
    monkeypatch.setattr(channels.Channels, 'update_channel_by_id', AsyncMock(return_value=channel))
    monkeypatch.setattr(channels.Channels, 'delete_channel_by_id', AsyncMock(return_value=True))
    monkeypatch.setattr(channels.Channels, 'remove_members_from_channel', AsyncMock(return_value=True))
    monkeypatch.setattr(channels.Channels, 'update_member_active_status', AsyncMock(return_value=True))
    monkeypatch.setattr(channels, 'validate_access_grants', AsyncMock(return_value=[]))
    monkeypatch.setattr(channels.AccessGrants, 'set_access_grants', AsyncMock(return_value=[]))
    monkeypatch.setattr(
        channels.AccessGrants, 'get_revoked_user_ids_by_resource', AsyncMock(return_value={'actor', 'former-member'})
    )
    from open_webui.socket.encryption import Relay

    transport = MagicMock()
    transport.emit = AsyncMock()
    relay = Relay(transport, AsyncMock())
    relay.local['socket-id'] = 'channel-target'
    registry_key = relay.registry.key('channel-target')
    relay.registry.values[registry_key] = json.dumps(
        {
            'channel': 'channel-target',
            'session': 'private-session',
            'expires': time.time() + 90,
            'members': {'participation': {'sid': 'socket-id'}},
        }
    )
    invalidate = AsyncMock(wraps=relay.invalidate)
    monkeypatch.setattr(relay, 'invalidate', invalidate)
    monkeypatch.setattr(channels, 'encryption', relay)
    publish = AsyncMock()
    monkeypatch.setattr(channels, 'publish_event', publish)
    monkeypatch.setattr(channels, 'leave_room_for_users', AsyncMock())
    monkeypatch.setattr(channels.sio, 'close_room', AsyncMock())

    response = asyncio.run(mounted.request(method, f'/api/v1/channels/channel-target/{suffix}', json=body))
    assert response.status_code == (404 if denied and suffix == 'members/active' else 403 if denied else 200)
    assert_event(mounted, action, response.status_code, 'channel:channel-target')
    if denied:
        invalidate.assert_not_awaited()
        publish.assert_not_awaited()
        assert registry_key in relay.registry.values
        assert relay.local == {'socket-id': 'channel-target'}
    else:
        invalidate.assert_awaited_once_with('channel-target')
        publish.assert_awaited_once()
        assert publish.call_args.kwargs['subject_id'] == 'channel-target'
        assert publish.call_args.kwargs['actor'].id == 'actor'
        assert '-secret' not in json.dumps(publish.call_args.kwargs['data'])
        assert registry_key not in relay.registry.values
        assert relay.local == {}
        assert transport.emit.await_count == 2
        for call in transport.emit.await_args_list:
            assert set(call.args[1]) <= {'kind', 'channel', 'session'}
            assert '-secret' not in json.dumps(call.args[1])
    assert '-secret' not in mounted.logs.text + json.dumps(mounted.entries)


@pytest.mark.parametrize(
    ('method', 'template', 'action'),
    [
        (method, path, action)
        for (method, path), action in REQUIRED_ACTIONS.items()
        if action
        in {
            'APP_LIST_READ',
            'APP_READ',
            'APP_MANIFEST_PREVIEW',
            'APP_CREATE',
            'APP_UPDATE',
            'APP_CONNECT',
            'APP_DELETE',
            'APP_INTERACTION',
            'CHANNEL_APPS_READ',
            'CHANNEL_APP_ADD',
            'CHANNEL_APP_REMOVE',
            'CHANNEL_MEMBER_MUTE',
            'CHANNEL_ACCESS_UPDATE',
            'FILES_SEARCH_READ',
            'FILES_COUNT_READ',
            'WORKSPACE_SEARCH_READ',
            'CHAT_PARAMS_UPDATE',
            'CALENDAR_ACCESS_UPDATE',
            'INTERFACE_VISIBILITY_UPDATE',
        }
    ],
)
def test_all_appendix_a_mounted_routes_audit_auth_failure(mounted, monkeypatch, method, template, action):
    async def denied():
        raise HTTPException(403, 'Denied')

    monkeypatch.setitem(app.dependency_overrides, auth.get_admin_user, denied)
    monkeypatch.setitem(app.dependency_overrides, auth.get_verified_user, denied)
    path = re.sub(r'\{[^}]+\}', 'target-id', template)
    response = asyncio.run(
        mounted.request(
            method, path + '?key=query-secret', json={'api_key': 'api-key-secret', 'context': 'context-secret'}
        )
    )
    assert response.status_code == 403
    records = [
        record.getMessage()
        for record in mounted.logs.records
        if record.name == 'open_webui.access' and f'action={action} |' in record.getMessage()
    ]
    assert len(records) == 1
    assert 'outcome=failure' in records[0]
    assert 'email=anonymous' in records[0]
    assert 'correlation_id=request-4' in records[0]
    assert '-secret' not in records[0] + json.dumps(mounted.entries)


def test_mounted_slash_redirect_retains_private_event_without_creating_app(mounted):
    response = asyncio.run(
        mounted.request('POST', '/api/v1/apps/', json={'api_key': 'api-key-secret', 'content': 'body-secret'})
    )
    assert response.status_code == 307
    event = next(record.getMessage() for record in mounted.logs.records if 'action=APP_CREATE |' in record.getMessage())
    assert 'outcome=redirect' in event
    assert 'object=-:-' in event
    mounted.db.commit.assert_not_awaited()
    assert '-secret' not in mounted.logs.text + json.dumps(mounted.entries)


def test_excluded_health_probe_remains_an_unmodified_passthrough(mounted):
    sent = []

    async def endpoint(scope, receive, send):
        await send({'type': 'http.response.start', 'status': 200, 'headers': []})
        await send({'type': 'http.response.body', 'body': b'ok'})

    async def scenario():
        async def receive():
            return {'type': 'http.request', 'body': b''}

        async def send(message):
            sent.append(message)

        await access_log.AccessLogMiddleware(endpoint)({'type': 'http', 'path': '/health'}, receive, send)

    asyncio.run(scenario())
    assert sent[0]['headers'] == []
    assert not [record for record in mounted.logs.records if record.name == 'open_webui.access']


@pytest.mark.parametrize('fails_after_start', [False, True])
def test_access_logger_does_not_buffer_stream_or_report_failed_stream_as_success(mounted, fails_after_start):
    sent = []

    async def endpoint(scope, receive, send):
        await send({'type': 'http.response.start', 'status': 200, 'headers': []})
        await send({'type': 'http.response.body', 'body': b'ciphertext-secret', 'more_body': True})
        assert len(sent) == 2  # Already delivered, not buffered for logging.
        if fails_after_start:
            raise RuntimeError('private-error-secret')
        await send({'type': 'http.response.body', 'body': b'last-content-secret', 'more_body': False})

    async def scenario():
        scope = {
            'type': 'http',
            'method': 'GET',
            'path': '/api/v1/channels/channel/messages',
            'query_string': b'token=query-secret',
            'headers': [],
            'scheme': 'http',
            'server': ('testserver', 80),
            'client': ('127.0.0.1', 1234),
        }

        async def receive():
            return {'type': 'http.request', 'body': b''}

        async def send(message):
            sent.append(message)

        await access_log.AccessLogMiddleware(endpoint)(scope, receive, send)

    if fails_after_start:
        with pytest.raises(RuntimeError, match='private-error-secret'):
            asyncio.run(scenario())
    else:
        asyncio.run(scenario())
    events = [
        record.getMessage()
        for record in mounted.logs.records
        if record.name == 'open_webui.access' and 'action=CHANNEL_MESSAGES_READ |' in record.getMessage()
    ]
    assert len(events) == 1
    assert ('outcome=error' if fails_after_start else 'outcome=success') in events[0]
    assert '-secret' not in events[0]
    assert sent[1]['body'] == b'ciphertext-secret'


def test_mounted_trusted_oidc_state_is_still_bounded_and_allowlisted(mounted, monkeypatch):
    from open_webui.routers import files

    async def identity(request: Request):
        request.state.user = mounted.user
        request.state.oidc_audit_claims = {
            'sub': 'subject|\n' + 'x' * 500,
            'mfa': 'pwd|\notp',
            'auth_time': 123,
            'groups': ['group-secret'],
            'token': 'token-secret',
            'recovery_codes': ['recovery-secret'],
        }
        return mounted.user

    monkeypatch.setitem(app.dependency_overrides, auth.get_verified_user, identity)
    monkeypatch.setattr(files.Files, 'count_files_by_user_id', AsyncMock(return_value=4))
    response = asyncio.run(
        mounted.request('GET', '/api/v1/files/user/count', headers={'X-Request-ID': 'correlation|injected'})
    )
    assert response.status_code == 200
    assert 'correlation_id=correlation%7Cinjected' in mounted.logs.text
    assert 'oidc_sub=subject%7C%0A' in mounted.logs.text
    for entry in mounted.entries:
        claims = entry['oidc_claims']
        assert set(claims) == {'sub', 'mfa', 'auth_time'}
        assert all(len(value) <= 600 for value in claims.values())
        assert all('|' not in value and '\n' not in value for value in claims.values())
    assert '-secret' not in mounted.logs.text + json.dumps(mounted.entries)


@pytest.mark.parametrize('level', [audit.AuditLevel.REQUEST, audit.AuditLevel.REQUEST_RESPONSE])
@pytest.mark.parametrize('status', [200, 403, 500])
@pytest.mark.parametrize(
    ('method', 'path'),
    [
        ('GET', '/api/v1/apps/'),
        ('POST', '/api/v1/apps/manifest/preview/'),
        ('PATCH', '/api/v1/apps/app-target/'),
        ('POST', '/api/v1/apps/app-target/connect'),
        ('POST', '/api/v1/apps/app-target/interactions/'),
        ('DELETE', '/api/v1/apps/app-target'),
        ('POST', '/api/v1/channels/channel-target/apps/'),
        ('DELETE', '/api/v1/channels/channel-target/apps/app-target/'),
        ('POST', '/api/v1/channels/channel-target/access/update/'),
        ('POST', '/api/v1/channels/channel-target/members/active/'),
        ('POST', '/api/v1/channels/channel-target/members/mute'),
        ('POST', '/api/v1/channels/channel-target/messages/post/'),
        ('GET', '/api/v1/channels/channel-target/messages'),
        ('POST', '/api/v1/channels/webhooks/webhook-id/webhook-token-secret/'),
    ],
)
def test_upstream_audit_protects_both_payloads_but_retains_event(monkeypatch, level, status, method, path):
    monkeypatch.setattr(audit, 'AUDIT_LOG_LEVEL', level.value)
    entries = []
    monkeypatch.setattr(audit.AuditLogger, 'write', lambda self, entry: entries.append(asdict(entry)))
    monkeypatch.setattr(audit.AuditLoggingMiddleware, '_get_authenticated_user', AsyncMock(return_value=None))
    states = []

    async def endpoint(scope, receive, send):
        states.append(scope['state'].copy())
        assert (await receive())['body'] == b'api-key-secret interaction-context-secret ciphertext-secret'
        await send({'type': 'http.response.start', 'status': status, 'headers': []})
        await send({'type': 'http.response.body', 'body': b'response-content-secret', 'more_body': False})

    middleware = audit.AuditLoggingMiddleware(endpoint, audit_level=level, audit_get_requests=True)
    messages = []

    async def scenario():
        scope = {
            'type': 'http',
            'method': method,
            'path': path,
            'query_string': b'token=query-secret',
            'headers': [(b'x-request-id', b'correlation|injected')],
            'scheme': 'http',
            'server': ('testserver', 80),
            'client': ('127.0.0.1', 1234),
            'state': {'token': SimpleNamespace(credentials='token-secret')},
        }

        async def receive():
            return {'type': 'http.request', 'body': b'api-key-secret interaction-context-secret ciphertext-secret'}

        async def send(message):
            messages.append(message)

        await middleware(scope, receive, send)

    asyncio.run(scenario())
    assert len(entries) == 1
    entry = entries[0]
    assert entry['id'] == states[0]['audit_request_id']
    assert states[0]['audit_level'] == level.value
    assert entry['verb'] == method and entry['response_status_code'] == status
    assert entry['correlation_id'] == 'correlation%7Cinjected'
    assert entry['request_object'] == entry['response_object'] == ''
    assert '-secret' not in json.dumps(entry)
    assert messages[-1]['body'] == b'response-content-secret'


def test_model_usage_retains_upstream_state_link_without_query_secrets(monkeypatch):
    from starlette.requests import Request

    entries = []
    monkeypatch.setattr(audit.AuditLogger, 'write', lambda self, entry, **kw: entries.append((asdict(entry), kw)))
    user = UserModel(
        id='actor', email='actor@example.com', name='Actor', role='user', last_active_at=0, updated_at=0, created_at=0
    )
    request = Request(
        {
            'type': 'http',
            'method': 'POST',
            'path': '/api/chat/completions',
            'query_string': b'api_key=query-secret',
            'headers': [],
            'scheme': 'http',
            'server': ('testserver', 80),
            'client': ('127.0.0.1', 1234),
            'state': {'audit_request_id': 'request-link', 'audit_level': 'METADATA'},
        }
    )
    audit.log_model_usage(request, user, 'model-id', {'prompt_tokens': 3, 'completion_tokens': 4, 'total_tokens': 7})
    assert len(entries) == 1
    entry, options = entries[0]
    assert entry['usage'] == {'input_tokens': 3, 'output_tokens': 4, 'total_tokens': 7}
    assert entry['audit_level'] == 'METADATA' and entry['model_id'] == 'model-id'
    assert options['extra'] == {'event': 'model_usage', 'request_id': 'request-link'}
    assert 'query-secret' not in json.dumps(entry)


def _audit_wrapped_request(mounted, monkeypatch, method, path, body, headers=None):
    monkeypatch.setattr(audit, 'AUDIT_LOG_LEVEL', 'REQUEST_RESPONSE')
    inner = audit.AuditLoggingMiddleware(app, audit_level=audit.AuditLevel.REQUEST_RESPONSE, audit_get_requests=True)

    async def wrapped(scope, receive, send):
        # AppHTTPMiddleware sets the token inside the app, after the audit layer.
        scope.setdefault('state', {})['token'] = SimpleNamespace(credentials='token-secret')
        await inner(scope, receive, send)

    async def call():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=wrapped, raise_app_exceptions=False),
            base_url='http://testserver',
            headers={'Authorization': '******', **(headers or {})},
        ) as client:
            return await client.request(method, path, json=body)

    return asyncio.run(call())


@pytest.mark.parametrize(
    ('method', 'path'),
    [
        ('POST', '/openai/config/update'),
        ('POST', '/ollama/config/update'),
        ('POST', '/api/v1/configs/import'),
        ('POST', '/api/v1/retrieval/config/update'),
        ('POST', '/api/v1/audio/config/update'),
        ('POST', '/api/v1/images/config/update'),
        ('POST', '/api/v1/users/user/variables/update'),
    ],
)
def test_config_write_bodies_never_reach_the_audit_log(mounted, monkeypatch, method, path):
    body = {
        'ENABLE_OPENAI_API': True,
        'OPENAI_API_KEYS': ['sk-marker-secret'],
        'config': {'nested': [{'api_key': 'sk-marker-secret'}]},
    }
    _audit_wrapped_request(mounted, monkeypatch, method, path, body)
    assert mounted.entries
    assert 'sk-marker' not in json.dumps(mounted.entries) + mounted.logs.text


def test_secret_keys_are_redacted_recursively_in_captured_bodies():
    body = json.dumps(
        {
            'OPENAI_API_KEYS': ['sk-marker-secret'],
            'Authorization': 'Bearer sk-marker-secret',
            'items': [{'inner': {'client_secret': 'sk-marker-secret', 'token': 'sk-marker-secret'}}],
            'max_tokens': 128,
            'name': 'kept',
        }
    )
    redacted = audit.redact_passwords(body)
    assert 'sk-marker' not in redacted
    parsed = json.loads(redacted)
    assert parsed['max_tokens'] == 128 and parsed['name'] == 'kept'
    truncated = audit.redact_passwords('{"api_key": "sk-marker-secret", "OPENAI_API_KEYS": ["sk-marker-secret"], "x')
    assert 'sk-marker' not in truncated


def test_audit_identity_claims_ignore_forged_client_tokens(mounted, monkeypatch):
    forged = auth.create_token({'sub': 'forged-sub', 'amr': ['forged-mfa'], 'auth_time': 1})
    monkeypatch.setattr(
        access_log, '_resolve_user_context', AsyncMock(return_value=access_log._UserContext(None, None, None, None))
    )

    async def identity(request: Request):
        request.state.user = mounted.user
        return mounted.user

    monkeypatch.setitem(app.dependency_overrides, auth.get_admin_user, identity)
    monkeypatch.setitem(app.dependency_overrides, auth.get_verified_user, identity)
    _audit_wrapped_request(
        mounted,
        monkeypatch,
        'POST',
        '/api/v1/configs/banners',
        [],
        headers={'Authorization': 'Bearer ' + forged, 'Cookie': f'oauth_id_token={forged}; token={forged}'},
    )
    assert mounted.entries
    dumped = json.dumps(mounted.entries)
    assert 'forged-sub' not in dumped and 'forged-mfa' not in dumped
    assert all(not entry['oidc_claims'] for entry in mounted.entries)


def test_scheduled_activity_log_encodes_email_and_meta(caplog):
    caplog.set_level(logging.WARNING, logger='open_webui.access')
    access_log.log_scheduled_activity(
        action='TASK_AUTOMATION_SCHEDULED',
        user_email='a@b.co\nWARNING forged | action=AUTH_LOGIN',
        user_role='user\n|x',
        object_id='id\n|y',
        object_type='automation',
        status_code=200,
        duration_s=0.1,
        meta='trigger=scheduler|name=Daily\nReport | action=AUTH_LOGIN',
    )
    messages = [r.getMessage() for r in caplog.records if r.name == 'open_webui.access']
    assert len(messages) == 1
    message = messages[0]
    assert '\n' not in message
    assert message.count(' | action=') == 1  # only the real field separator
    assert 'email=a@b.co%0AWARNING%20forged%20%7C%20action' in message
