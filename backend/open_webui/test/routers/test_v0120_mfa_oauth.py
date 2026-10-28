"""Session and dual-audit contracts for the v0.12.0 reconciliation."""

import asyncio
import inspect
import json
import logging
import uuid
from dataclasses import asdict
from http.cookies import SimpleCookie
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from open_webui.middleware import access_log
from open_webui.utils.mfa import MfaConfigForm
from open_webui.models.users import UserModel, UserUpdateForm
from open_webui.routers import mfa as mfa_router, users as users_router
from open_webui.utils import audit, auth, mfa
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


def request(path, *, cookie=None):
    headers = [(b'user-agent', b'pytest')]
    if cookie:
        headers.append((b'cookie', f'token={cookie}'.encode()))
    req = Request(
        {
            'type': 'http',
            'method': 'GET' if path.startswith('/oauth/') else 'POST',
            'path': path,
            'query_string': b'',
            'headers': headers,
            'client': ('127.0.0.1', 1234),
            'scheme': 'http',
            'server': ('testserver', 80),
            'app': SimpleNamespace(state=SimpleNamespace(redis=None)),
        }
    )

    # Direct logger tests must supply the state normally set by __call__.
    req.state.audit_request_id = str(uuid.uuid4())
    return req


@pytest.fixture
def identity(monkeypatch):
    user = UserModel(
        id='audit-user',
        email='alice@example.com',
        name='Alice',
        role='user',
        last_active_at=0,
        updated_at=0,
        created_at=0,
    )
    credential = SimpleNamespace(
        session_stamp='current',
        password='hash',
        mfa=SimpleNamespace(secret='encrypted', reset_required=False),
    )
    monkeypatch.setattr(mfa, 'get_auth', AsyncMock(return_value=credential))
    monkeypatch.setattr(mfa, 'get_mfa_config', AsyncMock(return_value=MfaConfigForm(ENABLE_MFA=True)))

    async def config_get(key, default=None):
        return '1h' if key == 'auth.jwt_expiry' else default

    monkeypatch.setattr(auth.Config, 'get', config_get)
    monkeypatch.setattr(auth.Users, 'get_user_by_id', AsyncMock(return_value=user))
    from open_webui.models.oauth_sessions import OAuthSessions

    monkeypatch.setattr(OAuthSessions, 'get_sessions_by_user_id', AsyncMock(return_value=[]))
    from open_webui.utils import access_control

    monkeypatch.setattr(access_control, 'get_permissions', AsyncMock(return_value={}))
    access_log.invalidate_user_cache(user.id)
    yield user, credential
    access_log.invalidate_user_cache(user.id)


@pytest.fixture
def audit_file(tmp_path):
    import importlib

    from loguru import logger
    from open_webui.utils.logger import file_format

    importlib.import_module('open_webui.main')
    path = tmp_path / 'audit.jsonl'
    handler = logger.add(
        path,
        format=file_format,
        filter=lambda record: record['extra'].get('auditable') is True,
    )
    try:
        yield path
    finally:
        logger.remove(handler)


def test_audit_file_distinguishes_challenge_and_completed(audit_file):
    from loguru import logger

    writer = audit.AuditLogger(logger)
    for outcome in ('challenge', 'completed', None):
        writer.write(
            audit.AuditLogEntry(
                id='audit-entry',
                user={'id': 'audit-user'},
                audit_level='METADATA',
                verb='GET',
                request_uri='/oauth/provider/login/callback',
                auth_outcome=outcome,
            )
        )
    entries = [json.loads(line) for line in audit_file.read_text().splitlines()]
    assert entries[0]['auth_outcome'] == 'challenge'
    assert entries[1]['auth_outcome'] == 'completed'
    assert entries[0] != entries[1]
    assert 'auth_outcome' not in entries[2]


def test_pending_mfa_has_no_application_session(identity, monkeypatch, caplog):
    user, credential = identity
    monkeypatch.setattr(
        mfa,
        'start_mfa_login',
        AsyncMock(
            return_value={
                'next_step': 'verify',
                'challenge_token': 'challenge-secret',
            }
        ),
    )

    async def scenario():
        req = request('/api/v1/auths/signin')
        response = Response()

        async def endpoint(req):
            result = await auth.create_signin_response(req, user, response=response, set_cookie=True, auth=credential)
            assert 'token' not in result
            assert not response.headers.getlist('set-cookie')
            assert not await auth.is_valid_token({'id': user.id, 'typ': 'mfa', 'session_stamp': 'current'})
            return JSONResponse(result)

        await access_log.AccessLogMiddleware(None).dispatch(req, endpoint)

    with caplog.at_level(logging.INFO, logger='open_webui.access'):
        asyncio.run(scenario())
    assert 'action=AUTH_LOGIN_CHALLENGE | outcome=pending' in caplog.text
    assert 'action=AUTH_LOGIN | outcome=success' not in caplog.text
    app = FastAPI()

    @app.get('/protected')
    async def protected(user=Depends(auth.get_human_user)):
        return {'id': user.id}

    with TestClient(app) as client:
        assert client.get('/protected', headers={'Authorization': 'Bearer challenge-secret'}).status_code == 401


def test_pending_account_has_no_session_or_completed_login(identity, caplog):
    user, credential = identity
    user.role = 'pending'

    async def scenario():
        async def signin(req):
            result = await auth.create_signin_response(req, user, auth=credential)
            assert result == {'next_step': 'pending'}
            return JSONResponse(result)

        await access_log.AccessLogMiddleware(None).dispatch(request('/api/v1/auths/signin'), signin)

    with caplog.at_level(logging.INFO, logger='open_webui.access'):
        asyncio.run(scenario())
    assert 'action=AUTH_LOGIN_PENDING | outcome=pending' in caplog.text
    assert 'action=AUTH_LOGIN | outcome=success' not in caplog.text


def test_oauth_mfa_emits_one_completed_login(identity, monkeypatch, caplog):
    from open_webui import events

    user, credential = identity
    entries = []
    published = []

    async def collect_event(app, event, request=None):
        published.append(event)

    monkeypatch.setattr(events, 'EVENT_SINKS', [SimpleNamespace(handle_event=collect_event)])
    monkeypatch.setattr(audit.AuditLogger, 'write', lambda self, entry: entries.append(asdict(entry)))
    monkeypatch.setattr(audit.AuditLoggingMiddleware, '_get_authenticated_user', AsyncMock(return_value=None))
    monkeypatch.setattr(
        mfa,
        'start_mfa_login',
        AsyncMock(
            return_value={
                'next_step': 'verify',
                'challenge_token': 'challenge-secret',
            }
        ),
    )
    challenge = SimpleNamespace(auth_method='oauth', auth_time=123, oauth_session_id=None)

    async def scenario():
        callback = request('/oauth/provider/login/callback')

        async def oauth_callback(req):
            result = await auth.create_signin_response(req, user, source='oauth', auth=credential)
            assert result['next_step'] == 'verify'
            return Response(status_code=302, headers={'location': '/auth?next_step=verify'})

        await access_log.AccessLogMiddleware(None).dispatch(callback, oauth_callback)
        await audit.AuditLoggingMiddleware(None)._log_audit_entry(callback, audit.AuditContext())
        verify = request('/api/v1/auths/mfa/verify')

        async def finish(req):
            result = await mfa_router.finish_login(req, Response(), user, credential, challenge)
            claims = auth.decode_token(result['token'])
            assert claims['typ'] == 'session'
            assert claims['mfa_verified'] is True
            assert claims['auth_method'] == 'oauth'
            assert claims['auth_time'] == 123
            return JSONResponse(result)

        await access_log.AccessLogMiddleware(None).dispatch(verify, finish)
        await audit.AuditLoggingMiddleware(None)._log_audit_entry(verify, audit.AuditContext())

    with caplog.at_level(logging.INFO, logger='open_webui.access'):
        asyncio.run(scenario())
    assert 'action=AUTH_OIDC_LOGIN_CHALLENGE | outcome=pending' in caplog.text
    assert caplog.text.count('action=AUTH_LOGIN | outcome=success') == 1
    completed = next(record.getMessage() for record in caplog.records if 'action=AUTH_LOGIN |' in record.getMessage())
    assert all(field in completed for field in ('session_id=', 'correlation_id=', 'oidc_sub=', 'time='))
    assert 'email=alice@example.com' in caplog.text
    assert 'action=AUTH_MFA_VERIFY' in caplog.text
    assert [entry['auth_outcome'] for entry in entries] == ['challenge', 'completed']
    assert all(entry['user']['id'] == user.id for entry in entries)
    assert '-secret' not in json.dumps(entries) + caplog.text
    assert [event.event for event in published] == [events.EVENTS.AUTH_LOGIN.name]
    assert published[0].actor['id'] == user.id


def test_revoked_stamp_denies_live_and_derived_access(identity, caplog):
    user, _ = identity

    async def scenario():
        for typ in ('session', 'automation', 'subagent'):
            claims = {'id': user.id, 'typ': typ, 'session_stamp': 'revoked', 'mfa_verified': True}
            assert not await auth.is_valid_token(claims)
            assert await auth.get_verified_user_by_token(auth.create_token(claims)) is None
        token = auth.create_token({'id': user.id, 'typ': 'session', 'session_stamp': 'revoked'})

        async def denied(req):
            return Response(status_code=401)

        await access_log.AccessLogMiddleware(None).dispatch(request('/api/v1/auths/mfa/replace', cookie=token), denied)

    with caplog.at_level(logging.INFO, logger='open_webui.access'):
        asyncio.run(scenario())
    assert 'email=anonymous' in caplog.text
    assert 'alice@example.com' not in caplog.text


def test_auth_body_never_logged(monkeypatch, caplog):
    monkeypatch.setattr(audit, 'AUDIT_LOG_LEVEL', 'REQUEST_RESPONSE')
    entries = []
    monkeypatch.setattr(audit.AuditLogger, 'write', lambda self, entry: entries.append(asdict(entry)))
    monkeypatch.setattr(audit.AuditLoggingMiddleware, '_get_authenticated_user', AsyncMock(return_value=None))

    async def endpoint(scope, receive, send):
        await receive()
        await send({'type': 'http.response.start', 'status': 200, 'headers': []})
        await send(
            {'type': 'http.response.body', 'body': b'{"recovery_codes":["recovery-secret"],"token":"token-secret"}'}
        )

    app = audit.AuditLoggingMiddleware(endpoint, audit_level=audit.AuditLevel.REQUEST_RESPONSE, audit_get_requests=True)

    async def scenario():
        for path in ('/api/v1/auths/mfa/verify', '/oauth/provider/login/callback'):
            req = request(path)
            req.scope['query_string'] = b'challenge_token=query-secret'
            req.scope['headers'].append((b'authorization', b'Bearer token-secret'))

            async def receive():
                return {'type': 'http.request', 'body': b'{"password":"password-secret","code":"code-secret"}'}

            async def send(message):
                pass

            await app(req.scope, receive, send)

    asyncio.run(scenario())
    serialized = json.dumps(entries)
    assert len(entries) == 2
    assert all(entry['request_object'] == entry['response_object'] == '' for entry in entries)
    assert '-secret' not in serialized + caplog.text


@pytest.mark.parametrize('field,value', [('role', 'admin'), ('email', 'updated@example.com')])
@pytest.mark.parametrize('outcome', ['saved', 'not_saved', 'exception', 'noop'])
def test_user_update_evicts_context_only_after_persistence(monkeypatch, field, value, outcome):
    user = SimpleNamespace(id='role-user', email='alice@example.com', role='user')
    updated = SimpleNamespace(**{**vars(user), field: value})
    monkeypatch.setattr(users_router.Users, 'get_first_user', AsyncMock(return_value=SimpleNamespace(id='primary')))
    monkeypatch.setattr(users_router.Users, 'get_user_by_id', AsyncMock(return_value=user))
    monkeypatch.setattr(users_router.Users, 'get_user_by_email', AsyncMock(return_value=None))
    monkeypatch.setattr(users_router.Auths, 'update_email_by_id', AsyncMock(return_value=True))
    cached = (access_log._UserContext(user.email, None, None, 'user'), 0)

    async def persist(user_id, updates, *, db):
        assert access_log._cache_data[user_id] is cached, 'Do not evict before persistence'
        assert updates == {field: value}
        if outcome == 'exception':
            raise RuntimeError('persistence failed')
        return updated if outcome == 'saved' else None

    save = AsyncMock(side_effect=persist)
    monkeypatch.setattr(users_router.Users, 'update_user_by_id', save)

    async def publish(*args, **kwargs):
        assert user.id not in access_log._cache_data, 'Evict before publishing the persisted update'

    event = AsyncMock(side_effect=publish)
    monkeypatch.setattr(users_router, 'publish_event', event)
    access_log._cache_data[user.id] = cached
    try:

        def update():
            return asyncio.run(
                users_router.update_user_by_id(
                    request('/api/v1/users/role-user/update'),
                    user.id,
                    UserUpdateForm(**({} if outcome == 'noop' else {field: value})),
                    session_user=SimpleNamespace(id='primary'),
                    db=None,
                )
            )

        if outcome == 'not_saved':
            with pytest.raises(HTTPException) as error:
                update()
            assert error.value.status_code == 400
        elif outcome == 'exception':
            with pytest.raises(RuntimeError, match='persistence failed'):
                update()
        else:
            assert update() is (updated if outcome == 'saved' else user)
        if outcome == 'saved':
            assert user.id not in access_log._cache_data
            expected_event = (
                users_router.EVENTS.USER_ROLE_UPDATED if field == 'role' else users_router.EVENTS.USER_UPDATED
            )
            assert event.await_args.args[1] == expected_event
        else:
            assert access_log._cache_data[user.id] is cached
            event.assert_not_awaited()
        assert save.await_count == (0 if outcome == 'noop' else 1)
    finally:
        access_log.invalidate_user_cache(user.id)


def test_audit_context_awaits_async_models(identity):
    user, _ = identity

    async def scenario():
        pending = access_log._resolve_user_context(user.id)
        assert inspect.isawaitable(pending)
        result = await pending
        assert result.email == user.email
        assert result.role == user.role

    asyncio.run(scenario())


@pytest.mark.parametrize('status', [401, 422, 429, 503])
def test_mfa_failure_outcomes_are_private(status, monkeypatch, caplog):
    from sqlalchemy.exc import SQLAlchemyError

    monkeypatch.setattr(mfa, 'get_mfa_config', AsyncMock(return_value=MfaConfigForm(ENABLE_MFA=True)))
    monkeypatch.setattr(mfa_router.ip_limiter, 'is_limited', AsyncMock(return_value=status == 429))

    async def reject(*args, **kwargs):
        if status == 503:
            raise SQLAlchemyError('database-secret')
        raise HTTPException(401, 'Invalid authentication request.')

    monkeypatch.setattr(mfa, 'verify_mfa_challenge', reject)
    entries = []
    monkeypatch.setattr(audit, 'AUDIT_LOG_LEVEL', 'REQUEST_RESPONSE')
    monkeypatch.setattr(audit.AuditLogger, 'write', lambda self, entry: entries.append(asdict(entry)))
    monkeypatch.setattr(audit.AuditLoggingMiddleware, '_get_authenticated_user', AsyncMock(return_value=None))
    app = FastAPI()
    app.include_router(mfa_router.router, prefix='/api/v1/auths/mfa')
    app.add_middleware(audit.AuditLoggingMiddleware, audit_level=audit.AuditLevel.REQUEST_RESPONSE)
    app.add_middleware(access_log.AccessLogMiddleware)
    with caplog.at_level(logging.INFO, logger='open_webui.access'):
        with TestClient(app) as client:
            result = client.post(
                '/api/v1/auths/mfa/verify',
                json=(
                    {}
                    if status == 422
                    else {
                        'challenge_token': 'challenge-value-secret',
                        'code': '123456',
                    }
                ),
            )
    assert result.status_code == status
    assert result.headers['cache-control'] == 'no-store'
    assert 'action=AUTH_MFA_VERIFY' in caplog.text
    assert f'outcome={"error" if status == 503 else "failure"}' in caplog.text
    assert 'email=anonymous' in caplog.text
    assert all(entry['request_object'] == entry['response_object'] == '' for entry in entries)
    assert '-secret' not in json.dumps(entries) + caplog.text


def test_oidc_claims_are_bounded_identifiers_in_both_audits():
    token = auth.create_token(
        {
            'sub': 'identity\n|injected',
            'amr': ['pwd', 'otp'],
            'auth_time': 123,
            'groups': ['group-secret'],
            'password': 'password-secret',
            'recovery_codes': ['recovery-secret'],
        }
    )
    values = access_log._decode_allowed_oidc_audit_claims(token)
    assert set(values) == {'sub', 'mfa', 'auth_time'}
    assert '\n' not in values['sub'] and '|' not in values['sub']
    middleware = audit.AuditLoggingMiddleware(None)
    claims = middleware._decode_jwt_claims(token)
    assert claims == values
    assert '-secret' not in json.dumps(claims)


def test_upstream_password_redaction_is_preserved():
    body = '{"password":"password-secret","NEW_PASSWORD":"replacement-secret","data":"retained"}'
    redacted = audit.redact_passwords(body)
    assert '-secret' not in redacted
    assert json.loads(redacted) == {'password': '********', 'NEW_PASSWORD': '********', 'data': 'retained'}


@pytest.mark.parametrize(
    'path',
    [
        '/api/v1/skills/create',
        '/api/v1/files/file/content',
        '/api/v1/terminals/server/chats/chat/path',
        '/api/v1/skills/id/skill/update',
        '/api/v1/skills/id/skill',
        '/api/v1/functions/id/function',
        '/api/v1/skills/id/skill/files/content',
        '/api/v1/skills/id/skill/history/diff/file',
        '/api/v1/tools/id/tool/history/revision',
        '/api/v1/models/model/update/version',
        '/api/v1/skills/import/preview',
    ],
)
def test_workspace_audit_never_captures_content(path, monkeypatch):
    monkeypatch.setattr(audit, 'AUDIT_LOG_LEVEL', 'REQUEST_RESPONSE')
    monkeypatch.setattr(audit.AuditLoggingMiddleware, '_get_authenticated_user', AsyncMock(return_value=None))
    entries = []
    monkeypatch.setattr(audit.AuditLogger, 'write', lambda self, entry: entries.append(asdict(entry)))

    async def endpoint(scope, receive, send):
        await receive()
        await send({'type': 'http.response.start', 'status': 200, 'headers': []})
        await send({'type': 'http.response.body', 'body': b'file-content-secret'})

    app = audit.AuditLoggingMiddleware(endpoint, audit_level=audit.AuditLevel.REQUEST_RESPONSE)
    req = request(path)
    # AppHTTPMiddleware now extracts credentials before the audit middleware.
    req.state.token = SimpleNamespace(credentials='test-only')
    req.scope['headers'].append((b'authorization', b'Bearer opaque'))

    async def scenario():
        async def receive():
            return {'type': 'http.request', 'body': b'history-content-secret'}

        async def send(message):
            pass

        await app(req.scope, receive, send)

    asyncio.run(scenario())
    assert len(entries) == 1
    assert entries[0]['request_object'] == entries[0]['response_object'] == ''


@pytest.mark.parametrize('valid_sub', [True, False])
def test_oauth_callback_sanitizes_state_and_evicts_after_save(valid_sub, identity, monkeypatch, caplog):
    from open_webui.models.oauth_sessions import OAuthSessions
    from open_webui.utils import oauth

    user, credential = identity
    user.oauth = {'provider': {'sub': 'identity'}}
    config = SimpleNamespace(
        ENABLE_OAUTH=True,
        OAUTH_EMAIL_CLAIM='email',
        OAUTH_USERNAME_CLAIM='name',
        OAUTH_SUB_CLAIM='',
        OAUTH_ALLOWED_DOMAINS=['*'],
        OAUTH_MERGE_ACCOUNTS_BY_EMAIL=False,
        OAUTH_UPDATE_NAME_ON_LOGIN=False,
        OAUTH_UPDATE_EMAIL_ON_LOGIN=False,
        OAUTH_UPDATE_PICTURE_ON_LOGIN=False,
        ENABLE_OAUTH_GROUP_MANAGEMENT=False,
        JWT_EXPIRES_IN='1h',
    )
    monkeypatch.setattr(oauth, 'get_oauth_runtime_config', AsyncMock(return_value=config))
    monkeypatch.setattr(oauth, 'OAUTH_PROVIDERS', {'provider': {}})
    monkeypatch.setattr(oauth, 'ENABLE_OAUTH_ID_TOKEN_COOKIE', False)
    monkeypatch.setattr(oauth.Users, 'get_user_by_oauth_sub', AsyncMock(return_value=user))
    manager = oauth.OAuthManager.__new__(oauth.OAuthManager)
    token = {
        'access_token': 'provider-access-secret',
        'id_token': auth.create_token({'sub': 'identity\n|injected', 'amr': ['pwd', 'otp']}),
        'userinfo': {
            'sub': 'identity' if valid_sub else '',
            'email': user.email,
            'name': 'Alice',
            'password': 'userinfo-secret',
        },
    }
    manager._clients = {'provider': SimpleNamespace(authorize_access_token=AsyncMock(return_value=token))}
    monkeypatch.setattr(manager, 'update_user_role_from_oauth', AsyncMock(return_value=user))

    async def save(**kwargs):
        assert user.id in access_log._cache_data
        assert kwargs['token'] is token
        return SimpleNamespace(id='oauth-session')

    monkeypatch.setattr(OAuthSessions, 'create_session', save)
    monkeypatch.setattr(
        mfa,
        'start_mfa_login',
        AsyncMock(
            return_value={
                'next_step': 'verify',
                'challenge_token': 'challenge-secret',
            }
        ),
    )
    access_log._cache_data[user.id] = (access_log._UserContext(user.email, 'old', None, 'user'), 0)
    req = request('/oauth/provider/login/callback')
    with caplog.at_level(logging.INFO):
        response = asyncio.run(manager.handle_callback(req, 'provider', Response(), db=None))
    assert response.status_code == 307
    assert not hasattr(req.state, 'oidc_raw_id_token')
    assert '\n' not in req.state.oidc_audit_claims['sub']
    assert '|' not in req.state.oidc_audit_claims['sub']
    assert 'userinfo-secret' not in caplog.text
    if valid_sub:
        assert user.id not in access_log._cache_data
        assert response.headers['location'].endswith('?mfa=1')
        cookies = SimpleCookie()
        for header in response.headers.getlist('set-cookie'):
            cookies.load(header)
        assert not cookies['token'].value
    else:
        assert user.id in access_log._cache_data
        assert '?error=' in response.headers['location']
        assert getattr(req.state, 'auth_audit_outcome', None) == 'failed'


def test_oauth_failed_redirect_is_a_failed_login(caplog):
    async def scenario():
        async def failed(req):
            req.state.auth_audit_outcome = 'failed'
            return Response(status_code=307)

        await access_log.AccessLogMiddleware(None).dispatch(request('/oauth/provider/login/callback'), failed)

    with caplog.at_level(logging.INFO, logger='open_webui.access'):
        asyncio.run(scenario())
    assert 'action=AUTH_OIDC_LOGIN_FAIL | outcome=failure' in caplog.text


def test_first_admin_cannot_be_demoted(monkeypatch):
    monkeypatch.setattr(users_router.Users, 'get_first_user', AsyncMock(return_value=SimpleNamespace(id='primary')))
    with pytest.raises(HTTPException) as error:
        asyncio.run(
            users_router.update_user_by_id(
                request('/api/v1/users/primary/update'),
                'primary',
                UserUpdateForm(role='user'),
                session_user=SimpleNamespace(id='primary'),
                db=None,
            )
        )
    assert error.value.status_code == 403


@pytest.mark.parametrize('path', ['/api/v1/auths/admin/config', '/ollama/verify'])
def test_admin_mfa_policy_and_ollama_verification_reject_users(path):
    from open_webui.routers import auths, ollama

    app = FastAPI()
    app.include_router(auths.router, prefix='/api/v1/auths')
    app.include_router(ollama.router, prefix='/ollama')
    app.dependency_overrides[auth.get_current_user] = lambda: SimpleNamespace(role='user')
    with TestClient(app) as client:
        response = client.post(path, json={'ENABLE_MFA': False})
    assert response.status_code == 401


def test_shared_chat_requires_permission_and_owner(monkeypatch):
    from open_webui.routers import chats

    user = SimpleNamespace(id='actor', role='user')
    monkeypatch.setattr(chats.Config, 'get', AsyncMock(return_value={}))
    monkeypatch.setattr(chats, 'has_permission', AsyncMock(return_value=False))
    with pytest.raises(HTTPException) as denied:
        asyncio.run(chats.share_chat_by_id(request('/api/v1/chats/chat/share'), 'chat', user=user, db=None))
    assert denied.value.status_code == 401
    monkeypatch.setattr(chats, 'has_permission', AsyncMock(return_value=True))
    monkeypatch.setattr(chats.Chats, 'get_chat_by_id_and_user_id', AsyncMock(return_value=None))
    with pytest.raises(HTTPException) as not_owner:
        asyncio.run(chats.share_chat_by_id(request('/api/v1/chats/chat/share'), 'chat', user=user, db=None))
    assert not_owner.value.status_code == 401
    shared = SimpleNamespace(user_id='owner', chat_id='chat')
    assert not asyncio.run(chats.can_read_shared_chat(SimpleNamespace(role='pending'), shared, None))


@pytest.mark.parametrize('manager_name', ['OAuthManager', 'OAuthClientManager'])
@pytest.mark.parametrize('saved', [True, False])
def test_oauth_refresh_evicts_context_only_after_save(manager_name, saved, monkeypatch):
    from open_webui.models.oauth_sessions import OAuthSessions
    from open_webui.utils import oauth

    manager = getattr(oauth, manager_name).__new__(getattr(oauth, manager_name))
    manager.app = SimpleNamespace(state=SimpleNamespace(redis=None))
    manager._refresh_locks = {}
    session = SimpleNamespace(id='refresh-session', user_id='refresh-user', token={'id_token': 'old'})
    refreshed = {'id_token': 'new'}
    monkeypatch.setattr(manager, '_perform_token_refresh', AsyncMock(return_value=refreshed))
    monkeypatch.setattr(OAuthSessions, 'get_session_by_id', AsyncMock(return_value=session))

    async def save(*args):
        assert session.user_id in access_log._cache_data
        return SimpleNamespace(**{**vars(session), 'token': refreshed}) if saved else None

    monkeypatch.setattr(OAuthSessions, 'update_session_by_id', save)
    access_log._cache_data[session.user_id] = (access_log._UserContext(None, 'old', None, 'user'), 0)
    try:
        result = asyncio.run(manager._refresh_token(session))
        assert result == (refreshed if saved else None)
        assert (session.user_id not in access_log._cache_data) is saved
    finally:
        access_log.invalidate_user_cache(session.user_id)


def test_oauth_role_save_evicts_and_disconnects(identity, monkeypatch):
    from open_webui.utils import oauth
    from open_webui.socket import main as socket

    user, _ = identity
    manager = oauth.OAuthManager.__new__(oauth.OAuthManager)
    monkeypatch.setattr(manager, 'get_user_role', AsyncMock(return_value='admin'))
    monkeypatch.setattr(
        oauth.Users,
        'update_user_role_by_id',
        AsyncMock(
            return_value=SimpleNamespace(
                **{**vars(user), 'role': 'admin'},
            )
        ),
    )
    monkeypatch.setattr(oauth, 'publish_event', AsyncMock())
    disconnected = []

    async def disconnect(user_id):
        disconnected.append(user_id)

    monkeypatch.setattr(socket, 'disconnect_user_sessions', disconnect)
    access_log._cache_data[user.id] = (access_log._UserContext(user.email, None, None, 'user'), 0)
    asyncio.run(
        manager.update_user_role_from_oauth(
            request('/oauth/provider/login/callback'),
            user,
            {},
            'provider',
        )
    )
    assert user.id not in access_log._cache_data
    assert disconnected == [user.id]


def test_oauth_provider_errors_never_log_tokens(monkeypatch, caplog):
    from open_webui.utils import oauth

    monkeypatch.setattr(oauth, 'get_oauth_runtime_config', AsyncMock(return_value=SimpleNamespace(ENABLE_OAUTH=True)))
    monkeypatch.setattr(oauth, 'OAUTH_PROVIDERS', {'provider': {}})
    monkeypatch.setattr(oauth.Config, 'get', AsyncMock(return_value='http://testserver'))
    manager = oauth.OAuthManager.__new__(oauth.OAuthManager)
    manager._clients = {
        'provider': SimpleNamespace(
            authorize_access_token=AsyncMock(side_effect=ValueError('provider-access-secret')),
        )
    }
    with caplog.at_level(logging.DEBUG):
        result = asyncio.run(manager.handle_callback(request('/oauth/provider/login/callback'), 'provider', Response()))
    assert result.status_code == 307
    assert 'provider-access-secret' not in caplog.text


@pytest.mark.parametrize('saved', [True, False])
def test_oauth_client_callback_evicts_only_saved_sessions(saved, identity, monkeypatch):
    from open_webui.models.oauth_sessions import OAuthSessions
    from open_webui.utils import oauth

    user, _ = identity
    manager = oauth.OAuthClientManager.__new__(oauth.OAuthClientManager)
    framework = SimpleNamespace(
        get_state_data=AsyncMock(return_value={'user_id': user.id}),
        clear_state_data=AsyncMock(),
    )
    client = SimpleNamespace(
        framework=framework,
        authorize_access_token=AsyncMock(return_value={'access_token': 'provider-secret'}),
    )
    monkeypatch.setattr(manager, 'get_client', AsyncMock(return_value=client))
    monkeypatch.setattr(manager, 'get_client_info', AsyncMock(return_value=SimpleNamespace(resource=None)))
    monkeypatch.setattr(oauth, 'get_verified_user_by_id', AsyncMock(return_value=user))
    monkeypatch.setattr(oauth, 'get_optional_verified_user_from_request', AsyncMock(return_value=None))
    monkeypatch.setattr(
        OAuthSessions,
        'create_session',
        AsyncMock(
            return_value=SimpleNamespace(id='saved-session') if saved else None,
        ),
    )
    access_log._cache_data[user.id] = (access_log._UserContext(user.email, 'old', None, 'user'), 0)
    req = request('/oauth/clients/client/callback')
    req.scope['session'] = {}
    req.scope['query_string'] = b'state=valid'
    result = asyncio.run(manager.handle_callback(req, 'client', Response()))
    assert result.status_code == 307
    assert (user.id not in access_log._cache_data) is saved


@pytest.mark.parametrize(
    'result',
    [
        'saved',
        'not-saved',
        'save-error',
        'token-error',
        'invalid-token',
        'empty-token',
        'invalid-state',
        'unauthorized',
        'mismatched-user',
    ],
)
def test_oauth_client_callback_audits_provider_authorization(result, identity, monkeypatch, caplog, audit_file):
    import importlib

    from open_webui import events
    from open_webui.models.oauth_sessions import OAuthSessions
    from open_webui.utils import oauth
    from starlette.middleware.sessions import SessionMiddleware

    main = importlib.import_module('open_webui.main')
    user, _ = identity
    published = []

    async def collect_event(app, event, request=None):
        published.append(event)

    monkeypatch.setattr(events, 'EVENT_SINKS', [SimpleNamespace(handle_event=collect_event)])
    manager = oauth.OAuthClientManager.__new__(oauth.OAuthClientManager)
    framework = SimpleNamespace(
        get_state_data=AsyncMock(return_value=None if result == 'invalid-state' else {'user_id': user.id}),
        clear_state_data=AsyncMock(),
    )
    token = (
        {'error': 'provider-token-secret'}
        if result == 'invalid-token'
        else None if result == 'empty-token' else {'access_token': 'provider-token-secret'}
    )
    client = SimpleNamespace(
        framework=framework,
        authorize_access_token=AsyncMock(
            return_value=token,
            side_effect=ValueError('provider-token-secret') if result == 'token-error' else None,
        ),
    )
    monkeypatch.setattr(manager, 'get_client', AsyncMock(return_value=client))
    monkeypatch.setattr(manager, 'get_client_info', AsyncMock(return_value=SimpleNamespace(resource=None)))
    monkeypatch.setattr(
        oauth, 'get_verified_user_by_id', AsyncMock(return_value=None if result == 'unauthorized' else user)
    )
    monkeypatch.setattr(
        oauth,
        'get_optional_verified_user_from_request',
        AsyncMock(return_value=SimpleNamespace(id='other-user') if result == 'mismatched-user' else None),
    )
    monkeypatch.setattr(
        OAuthSessions,
        'create_session',
        AsyncMock(
            return_value=None if result == 'not-saved' else SimpleNamespace(id='provider-session'),
            side_effect=RuntimeError('database-token-secret') if result == 'save-error' else None,
        ),
    )
    monkeypatch.setattr(oauth.Config, 'get', AsyncMock(return_value='http://testserver'))
    monkeypatch.setattr(main, 'oauth_client_manager', manager)
    monkeypatch.setattr(main, 'ENABLE_TOOL_SERVERS', True)
    monkeypatch.setattr(audit, 'AUDIT_LOG_LEVEL', 'REQUEST_RESPONSE')
    monkeypatch.setattr(audit.AuditLoggingMiddleware, '_get_authenticated_user', AsyncMock(return_value=None))
    app = FastAPI()
    app.add_api_route('/oauth/clients/{client_id}/callback', main.oauth_client_callback, methods=['GET'])
    app.add_middleware(SessionMiddleware, secret_key='test-only')
    app.add_middleware(access_log.AccessLogMiddleware)
    app.add_middleware(
        audit.AuditLoggingMiddleware,
        audit_level=audit.AuditLevel.REQUEST_RESPONSE,
        audit_get_requests=True,
    )
    with caplog.at_level(logging.INFO, logger='open_webui.access'):
        with TestClient(app) as browser:
            response = browser.get(
                '/oauth/clients/client/callback?state=provider-state-secret&code=provider-code-secret',
                follow_redirects=False,
            )
    assert response.status_code == 307
    entries = [json.loads(line) for line in audit_file.read_text().splitlines()]
    assert len(entries) == 1
    entry = entries[0]
    assert entry['response_status_code'] == 307
    if result == 'saved':
        assert 'action=OAUTH_CLIENT_AUTHORIZE | outcome=success | nis2=Y' in caplog.text
        assert 'email=alice@example.com' in caplog.text
        assert entry['user']['id'] == user.id
        assert entry['auth_outcome'] == 'completed'
        assert 'error=' not in response.headers['location']
    else:
        assert 'action=OAUTH_CLIENT_AUTHORIZE_FAIL | outcome=failure | nis2=Y' in caplog.text
        assert 'outcome=success' not in caplog.text
        assert entry['user'] == {}
        assert entry['auth_outcome'] == 'failed'
        assert 'error=' in response.headers['location']
    assert 'AUTH_OIDC_LOGIN' not in caplog.text
    assert 'action=AUTH_LOGIN' not in caplog.text
    assert not any(event.event == events.EVENTS.AUTH_LOGIN.name for event in published)
    assert not response.headers.get_list('set-cookie')
    assert '-secret' not in audit_file.read_text() + caplog.text


def test_oauth_client_redirect_without_completion_is_pending(caplog):
    async def scenario():
        async def redirect(req):
            return Response(status_code=307)

        await access_log.AccessLogMiddleware(None).dispatch(request('/oauth/clients/client/callback'), redirect)

    with caplog.at_level(logging.INFO, logger='open_webui.access'):
        asyncio.run(scenario())
    assert 'action=OAUTH_CLIENT_AUTHORIZE_INCOMPLETE | outcome=pending | nis2=Y' in caplog.text
    assert 'outcome=success' not in caplog.text


@pytest.mark.parametrize('mode', ['permission-denied', 'stamp-revoked', 'connection-end'])
def test_realtime_permission_revocation_and_connection_end(mode, identity, monkeypatch):
    from open_webui.routers.audio import realtime
    from starlette.websockets import WebSocketDisconnect

    user, credential = identity
    token = auth.create_token(
        {
            'id': user.id,
            'typ': 'session',
            'session_stamp': 'current',
            'mfa_verified': True,
            'auth_method': 'oauth',
        }
    )
    permission_calls = []

    async def permission(user_id, permission, policy):
        permission_calls.append((user_id, permission, policy))
        return mode != 'permission-denied'

    monkeypatch.setattr(realtime, 'has_permission', permission)
    config = {
        'audio.realtime.enabled': True,
        'audio.realtime.openai.api_base_url': 'https://provider.example/v1',
        'audio.realtime.openai.api_key': 'provider-secret',
        'audio.realtime.model': 'voice-model',
        'audio.realtime.voice': 'voice',
        'audio.realtime.transcription_model': 'transcription',
        'user.permissions': {'chat': {'call': True}},
    }
    monkeypatch.setattr(realtime.Config, 'get_many', AsyncMock(return_value=config))
    monkeypatch.setattr(realtime.Config, 'get', AsyncMock(return_value=True))
    monkeypatch.setattr(realtime.Models, 'get_model_by_id', AsyncMock(return_value=None))
    monkeypatch.setattr(realtime, 'check_model_access', AsyncMock())
    sleep = asyncio.sleep

    async def revoke(seconds):
        assert seconds == 60
        credential.session_stamp = 'revoked'
        await sleep(0)

    if mode == 'stamp-revoked':
        monkeypatch.setattr(realtime.asyncio, 'sleep', revoke)

    class Socket:
        def __init__(self):
            self.app = SimpleNamespace(state=SimpleNamespace(redis=None, MODELS={'chat-model': {'id': 'chat-model'}}))
            self.first = True
            self.closed = False
            self.messages = []

        async def accept(self):
            pass

        async def receive_text(self):
            if self.first:
                self.first = False
                return json.dumps({'type': 'auth', 'token': token, 'model_id': 'chat-model'})
            if mode == 'connection-end':
                raise WebSocketDisconnect()
            await asyncio.Event().wait()

        async def send_json(self, data):
            self.messages.append(data)

        async def close(self):
            self.closed = True

    class Provider:
        def __init__(self):
            self.events = iter([{'type': 'session.created'}, {'type': 'session.updated'}])
            self.closed = False

        async def receive_json(self):
            return next(self.events)

        async def send_json(self, data):
            pass

        def __aiter__(self):
            return self

        async def __anext__(self):
            await asyncio.Event().wait()

        async def close(self):
            self.closed = True

    ws, provider = Socket(), Provider()
    provider_connections = []

    async def connect(*args, **kwargs):
        provider_connections.append(args)
        return provider

    monkeypatch.setattr(realtime, 'get_session', AsyncMock(return_value=SimpleNamespace(ws_connect=connect)))

    async def scenario():
        await asyncio.wait_for(realtime.realtime_call(ws), timeout=2)

    asyncio.run(scenario())
    assert permission_calls[0] == (user.id, 'chat.call', config['user.permissions'])
    assert ws.closed
    if mode == 'permission-denied':
        assert provider_connections == []
        assert ws.messages[-1]['message'] == 'Call permission denied'
    else:
        assert provider.closed
        assert any(message['type'] == 'bridge.ready' for message in ws.messages)
        if mode == 'stamp-revoked':
            assert ws.messages[-1]['message'] == 'Call authorization expired'
        else:
            assert not any(message['type'] == 'bridge.error' for message in ws.messages)
