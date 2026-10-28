import json
import re
import uuid
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import (
    TYPE_CHECKING,
    Any,
    AsyncGenerator,
    Dict,
    MutableMapping,
    Optional,
    cast,
)

from asgiref.typing import (
    ASGI3Application,
    ASGIReceiveCallable,
    ASGIReceiveEvent,
    ASGISendCallable,
    ASGISendEvent,
)
from asgiref.typing import (
    Scope as ASGIScope,
)
from loguru import logger
from open_webui.env import AUDIT_LOG_LEVEL, MAX_BODY_LOG_SIZE
from open_webui.middleware.audit_routes import audit_route_template, match_route_policy
from open_webui.models.users import UserModel
from open_webui.utils.auth import get_current_user, get_http_authorization_cred
from open_webui.utils.response import normalize_usage
from starlette.requests import Request

if TYPE_CHECKING:
    from loguru import Logger


@dataclass(frozen=True)
class OIDCClaims:
    """OIDC claims extracted from JWT for NIS2-compliant audit logging."""

    sub: Optional[str] = None  # OIDC persistent subject identifier
    auth_time: Optional[int] = None  # Timestamp of IdP authentication
    amr: Optional[list] = None  # Authentication Methods References (MFA)
    acr: Optional[str] = None  # Authentication Context Class Reference
    ad_groups: Optional[list] = None  # AD groups from token claims


@dataclass(frozen=True)
class AuditLogEntry:
    # `Metadata` audit level properties
    id: str
    user: Optional[dict[str, Any]]
    audit_level: str
    verb: str
    request_uri: str
    # NIS2 compliance fields
    correlation_id: Optional[str] = None  # X-Request-ID from WAF/ADSSPM
    oidc_claims: Optional[dict[str, Any]] = None  # OIDC claims for identity assurance
    user_agent: Optional[str] = None
    source_ip: Optional[str] = None
    model_id: Optional[str] = None
    usage: Optional[Dict[str, int]] = None
    # `Request` audit level properties
    request_object: Any = None
    # `Request Response` level
    response_object: Any = None
    response_status_code: Optional[int] = None
    auth_outcome: Optional[str] = None


class AuditLevel(str, Enum):
    NONE = 'NONE'
    METADATA = 'METADATA'
    REQUEST = 'REQUEST'
    REQUEST_RESPONSE = 'REQUEST_RESPONSE'


class AuditLogger:
    """
    A helper class that encapsulates audit logging functionality. It uses Loguru’s logger with an auditable binding to ensure that audit log entries are filtered correctly.

    Parameters:
    logger (Logger): An instance of Loguru’s logger.
    """

    def __init__(self, logger: 'Logger'):
        self.logger = logger.bind(auditable=True)

    def write(
        self,
        audit_entry: AuditLogEntry,
        *,
        log_level: str = 'INFO',
        extra: Optional[dict] = None,
    ):
        entry = asdict(audit_entry)

        if extra:
            entry['extra'] = extra

        self.logger.log(
            log_level,
            '',
            **entry,
        )


class AuditContext:
    """
    Captures and aggregates the HTTP request and response bodies during the processing of a request. It ensures that only a configurable maximum amount of data is stored to prevent excessive memory usage.

    Attributes:
    request_body (bytearray): Accumulated request payload.
    response_body (bytearray): Accumulated response payload.
    max_body_size (int): Maximum number of bytes to capture.
    metadata (Dict[str, Any]): A dictionary to store additional audit metadata (user, http verb, user agent, etc.).
    """

    def __init__(self, max_body_size: int = MAX_BODY_LOG_SIZE):
        self.request_body = bytearray()
        self.response_body = bytearray()
        self.max_body_size = max_body_size
        self.metadata: Dict[str, Any] = {}

    def add_request_chunk(self, chunk: bytes):
        if len(self.request_body) < self.max_body_size:
            self.request_body.extend(chunk[: self.max_body_size - len(self.request_body)])

    def add_response_chunk(self, chunk: bytes):
        if len(self.response_body) < self.max_body_size:
            self.response_body.extend(chunk[: self.max_body_size - len(self.response_body)])


def log_model_usage(request: Request, user: UserModel, model_id: str, usage: Optional[Dict]):
    """Write a model call's usage separately from its originating HTTP request."""
    request_id = getattr(request.state, 'audit_request_id', None)
    if not request_id or not usage:
        return
    try:
        usage = normalize_usage(usage)
        AuditLogger(logger).write(
            AuditLogEntry(
                id=str(uuid.uuid4()),
                user=user.model_dump(include={'id', 'name', 'email', 'role'}),
                audit_level=request.state.audit_level,
                verb=request.method,
                request_uri=audit_route_template(request.method, request.url.path),
                source_ip=request.client.host if request.client else None,
                user_agent=request.headers.get('user-agent'),
                model_id=model_id,
                usage={key: usage[key] for key in ('input_tokens', 'output_tokens', 'total_tokens')},
            ),
            extra={'event': 'model_usage', 'request_id': request_id},
        )
    except Exception as e:
        logger.error('Failed to log model usage: {}', e)


_SECRET_NAME = r'(?:\w*(?:password|passwd|secret|credential|authorization|api[_-]?keys?|tokens?)|keys?|\w+_keys?)'
_SECRET_KEY = re.compile(_SECRET_NAME, re.IGNORECASE)
_SECRET_JSON_FALLBACK = re.compile(
    r'"(' + _SECRET_NAME + r')"\s*:\s*(?:"(?:[^"\\]|\\.)*"|\[[^\]]*\])',
    re.IGNORECASE,
)


def _redact_secret_values(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                '********'
                if isinstance(key, str) and _SECRET_KEY.fullmatch(key) and isinstance(item, (str, list, dict))
                else _redact_secret_values(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_secret_values(item) for item in value]
    return value


def redact_passwords(body: str) -> str:
    """Mask credential-like values (passwords, API keys, tokens, secrets) in a JSON body."""
    if not body:
        return body
    try:
        parsed = json.loads(body)
    except ValueError:
        # Truncated or non-JSON payloads: fall back to pattern masking.
        return _SECRET_JSON_FALLBACK.sub(r'"\1": "********"', body)
    if not isinstance(parsed, (dict, list)):
        return body
    return json.dumps(_redact_secret_values(parsed), ensure_ascii=False)


class AuditLoggingMiddleware:
    """
    ASGI middleware that intercepts HTTP requests and responses to perform audit logging. It captures request/response bodies (depending on audit level), headers, HTTP methods, and user information, then logs a structured audit entry at the end of the request cycle.
    """

    DEFAULT_AUDITED_METHODS = {'PUT', 'PATCH', 'DELETE', 'POST'}

    def __init__(
        self,
        app: ASGI3Application,
        *,
        excluded_paths: Optional[list[str]] = None,
        included_paths: Optional[list[str]] = None,
        max_body_size: int = MAX_BODY_LOG_SIZE,
        audit_level: AuditLevel = AuditLevel.NONE,
        audit_get_requests: bool = False,
    ) -> None:
        self.app = app
        self.audit_logger = AuditLogger(logger)

        def normalize_paths(paths: Optional[list[str]]) -> list[str]:
            return [path for path in (path.strip().lstrip('/') for path in paths or []) if path]

        self.excluded_paths = normalize_paths(excluded_paths)
        self.included_paths = normalize_paths(included_paths)
        self.max_body_size = max_body_size
        self.audited_methods = set(self.DEFAULT_AUDITED_METHODS)
        if audit_get_requests:
            self.audited_methods.add('GET')
        self.audit_level = audit_level

        # Paths are fixed for the process lifetime; compile once instead of
        # per request. None means the corresponding mode has nothing to match.
        self._included_pattern = (
            re.compile(r'^/api(?:/v1)?/(' + '|'.join(self.included_paths) + r')\b') if self.included_paths else None
        )
        self._excluded_pattern = (
            re.compile(r'^/api(?:/v1)?/(' + '|'.join(self.excluded_paths) + r')\b') if self.excluded_paths else None
        )

        if self.included_paths and self.excluded_paths:
            logger.warning(
                'Both AUDIT_INCLUDED_PATHS and AUDIT_EXCLUDED_PATHS are set. '
                'AUDIT_INCLUDED_PATHS (whitelist) takes precedence.'
            )

    async def __call__(
        self,
        scope: ASGIScope,
        receive: ASGIReceiveCallable,
        send: ASGISendCallable,
    ) -> None:
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)

        request = Request(scope=cast(MutableMapping, scope))

        if self._should_skip_auditing(request):
            return await self.app(scope, receive, send)

        request.state.audit_request_id = str(uuid.uuid4())
        request.state.audit_level = self.audit_level.value
        policy = match_route_policy(request.method, request.url.path)
        private_payload = policy and (
            policy.action.startswith(('APP_', 'CHANNEL_', 'CONFIG_', 'USER_VARIABLES_'))
            or policy.action in {'CALENDAR_ACCESS_UPDATE', 'INTERFACE_VISIBILITY_UPDATE', 'WORKSPACE_SEARCH_READ'}
        )
        capture_body = not private_payload and not (
            request.url.path.startswith(
                (
                    '/api/v1/auths',
                    '/oauth/',
                    '/api/v1/functions',
                    '/api/v1/tools',
                    '/api/v1/models',
                    '/api/v1/skills',
                    '/api/v1/prompts',
                    '/api/v1/files',
                    '/api/v1/terminals',
                    '/api/v1/chats',
                    '/api/v1/chat/',
                )
            )
        )
        async with self._audit_context(request) as context:

            async def send_wrapper(message: ASGISendEvent) -> None:
                if message['type'] == 'http.response.start' or (
                    capture_body and self.audit_level == AuditLevel.REQUEST_RESPONSE
                ):
                    await self._capture_response(message, context)

                await send(message)

            original_receive = receive

            async def receive_wrapper() -> ASGIReceiveEvent:
                nonlocal original_receive
                message = await original_receive()

                if capture_body and self.audit_level in (
                    AuditLevel.REQUEST,
                    AuditLevel.REQUEST_RESPONSE,
                ):
                    await self._capture_request(message, context)

                return message

            await self.app(scope, receive_wrapper, send_wrapper)

    @asynccontextmanager
    async def _audit_context(self, request: Request) -> AsyncGenerator[AuditContext, None]:
        """
        async context manager that ensures that an audit log entry is recorded after the request is processed.
        """
        context = AuditContext()
        try:
            yield context
        except BaseException:
            context.metadata.setdefault('response_status_code', 500)
            raise
        finally:
            await self._log_audit_entry(request, context)

    async def _get_authenticated_user(self, request: Request) -> Optional[UserModel]:
        # get_current_user stashes the resolved user on the scope-backed state;
        # reuse it instead of running the full auth pipeline (JWT decode, Redis
        # revocation checks, DB fetch, last-active write) a second time.
        user = getattr(request.state, 'user', None)
        if isinstance(user, UserModel):
            return user

        auth_header = request.headers.get('Authorization')

        try:
            user = await get_current_user(request, None, None, get_http_authorization_cred(auth_header))
            return user
        except Exception as e:
            logger.debug('Failed to get authenticated user: {}', type(e).__name__)

        return None

    def _extract_correlation_id(self, request: Request) -> Optional[str]:
        """Extract X-Request-ID header passed by WAF/ADSSPM for NIS2 correlation."""
        from open_webui.middleware.access_log import AccessLogMiddleware

        return AccessLogMiddleware._get_correlation_id(self, request)

    def _extract_client_ip(self, request: Request) -> Optional[str]:
        """
        Extract the real client IP address, traversing Azure WAF / reverse proxy headers.

        Priority:
          1. X-Azure-ClientIP   — set by Azure Front Door / Application Gateway
          2. X-Original-Forwarded-For — original client IP before WAF rewrite
          3. X-Forwarded-For    — standard proxy header (first IP = real client)
          4. X-Real-IP          — set by some reverse proxies (nginx)
          5. request.client.host — direct ASGI connection IP (container-internal)
        """
        from open_webui.middleware.access_log import AccessLogMiddleware

        return AccessLogMiddleware._get_client_ip(self, request)

    async def _resolve_oidc_claims(self, request: Request, user: dict) -> dict[str, Any]:
        """Identity-assurance claims from trusted server state only, never client-supplied tokens."""
        claims = getattr(request.state, 'oidc_audit_claims', None)
        if not claims and user.get('id'):
            from open_webui.middleware.access_log import _resolve_user_context

            try:
                ctx = await _resolve_user_context(user['id'])
                claims = {'sub': ctx.oidc_sub, 'mfa': ctx.mfa_status}
            except Exception:
                claims = None
        return claims or {}

    ALWAYS_LOG_ENDPOINTS = (
        '/api/v1/auths/signin',
        '/api/v1/auths/signout',
        '/api/v1/auths/signup',
        '/api/v1/auths/mfa',
        '/oauth/',
    )

    def _should_skip_auditing(self, request: Request) -> bool:
        if AUDIT_LOG_LEVEL == 'NONE':
            return True

        if request.method not in self.audited_methods:
            return True

        if request.url.path.startswith('/ws/socket.io'):
            return True

        path = request.url.path.lower()
        for endpoint in self.ALWAYS_LOG_ENDPOINTS:
            if path.startswith(endpoint):
                return False  # Do NOT skip logging for auth endpoints

        # Skip logging if the request is not authenticated
        # Token is set by AppHTTPMiddleware from any accepted credential
        if not getattr(request.state, 'token', None):
            return True

        # Whitelist mode: only log paths that match included_paths
        if self._included_pattern:
            return not self._included_pattern.match(request.url.path)

        # Blacklist mode: skip paths that match excluded_paths
        if self._excluded_pattern and self._excluded_pattern.match(request.url.path):
            return True

        return False

    async def _capture_request(self, message: ASGIReceiveEvent, context: AuditContext):
        if message['type'] == 'http.request':
            body = message.get('body', b'')
            context.add_request_chunk(body)

    async def _capture_response(self, message: ASGISendEvent, context: AuditContext):
        if message['type'] == 'http.response.start':
            context.metadata['response_status_code'] = message['status']

        elif message['type'] == 'http.response.body':
            body = message.get('body', b'')
            context.add_response_chunk(body)

    async def _log_audit_entry(self, request: Request, context: AuditContext):
        try:
            user = getattr(request.state, 'auth_audit_user', None) or getattr(request.state, 'user', None)
            if user is None:
                user = await self._get_authenticated_user(request)

            user = user.model_dump(include={'id', 'name', 'email', 'role'}) if user else {}

            # NIS2: Extract correlation ID and OIDC claims
            correlation_id = self._extract_correlation_id(request)
            from open_webui.middleware.access_log import _bounded_oidc_audit_claims

            oidc_claims = _bounded_oidc_audit_claims(await self._resolve_oidc_claims(request, user)) or None

            request_body = context.request_body.decode('utf-8', errors='replace')
            response_body = context.response_body.decode('utf-8', errors='replace')

            # Redact sensitive information
            request_body = redact_passwords(request_body)
            response_body = redact_passwords(response_body)

            entry = AuditLogEntry(
                id=request.state.audit_request_id,
                user=user,
                audit_level=self.audit_level.value,
                verb=request.method,
                request_uri=audit_route_template(request.method, request.url.path),
                correlation_id=correlation_id,
                oidc_claims=oidc_claims,
                response_status_code=context.metadata.get('response_status_code', None),
                source_ip=self._extract_client_ip(request),
                user_agent=request.headers.get('user-agent'),
                model_id=getattr(request.state, 'model_id', None),
                request_object=request_body,
                response_object=response_body,
                auth_outcome=getattr(request.state, 'auth_audit_outcome', None),
            )

            self.audit_logger.write(entry)
        except Exception as e:
            logger.error(f'Failed to log audit entry: {str(e)}')
