"""
Custom Access Logging Middleware per Open WebUI
NIS2-compliant: include correlation ID, OIDC subject, MFA status
Soluzione che FUNZIONA - bypassa completamente il logging di Uvicorn
"""

import hashlib
import uuid
import logging
import sys
import time
import threading
from typing import Callable, Optional, NamedTuple
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

try:
    import jwt as pyjwt
except ImportError:
    pyjwt = None

# ---------------------------------------------------------------------------
# Thread-safe cache: resolve user UUID → (email, oidc_sub, mfa_status) via DB.
#
# Design notes for 2 000 users / 200 concurrent:
#   - maxsize=2048 covers the full user base → ~100 % hit rate after warm-up.
#   - TTL of 300 s ensures changes propagate within 5 min.
#   - threading.Lock protects the dict; released during I/O.
#   - DB lookups are synchronous but fast (PK index, single row).
#     They run inside BaseHTTPMiddleware's worker thread, so the
#     asyncio event loop is NOT blocked.
# ---------------------------------------------------------------------------

_log = logging.getLogger(__name__)


class _UserContext(NamedTuple):
    email: Optional[str]
    oidc_sub: Optional[str]
    mfa_status: Optional[str]


_CACHE_MAX = 2048
_CACHE_TTL = 300  # seconds
_CACHE_TTL_SHORT = 10  # seconds — for entries missing OIDC claims (login race)
_cache_lock = threading.Lock()
_cache_data: dict[str, tuple[_UserContext, float]] = {}  # user_id → (ctx, ts)


def invalidate_user_cache(user_id: str) -> None:
    """Invalidate cached user context so the next request re-fetches from DB.

    Call this after saving/updating an OAuth session for the user.
    """
    with _cache_lock:
        _cache_data.pop(user_id, None)
    _log.debug("Invalidated access-log cache for user %s", user_id)


# ---------------------------------------------------------------------------
# NIS2-required claims inside the OIDC id_token.
#   sub  — unique subject identifier (mandatory per OIDC Core)
#   amr  — Authentication Methods References (RFC 8176) — proves MFA
#   acr  — Authentication Context Class Reference — alternative MFA signal
# If any of these are absent the access-log cannot be fully NIS2-compliant.
# ---------------------------------------------------------------------------
_NIS2_REQUIRED_CLAIMS = ("sub",)
_NIS2_MFA_CLAIMS = ("amr", "acr")  # at least one must be present


def _decode_id_token_claims(id_token_raw: str, user_hint: str = "") -> tuple[Optional[str], Optional[str]]:
    """Decode an OIDC id_token (without signature verification) and extract sub + MFA claims.

    Emits a WARNING when claims required for NIS2 compliance are missing.
    *user_hint* is included in warnings to ease troubleshooting.
    """
    if not id_token_raw or pyjwt is None:
        return None, None
    try:
        decoded = pyjwt.decode(
            id_token_raw,
            options={"verify_signature": False},
            algorithms=["RS256", "HS256", "ES256", "PS256", "EdDSA"],
        )

        # --- NIS2 compliance check ----------------------------------------
        missing_required = [c for c in _NIS2_REQUIRED_CLAIMS if not decoded.get(c)]
        has_mfa_claim = any(decoded.get(c) for c in _NIS2_MFA_CLAIMS)

        if missing_required:
            _log.warning(
                "NIS2-COMPLIANCE: OIDC id_token for user [%s] is missing required claim(s): %s. "
                "The IdP (ManageEngine ADSSPM) must be configured to include these claims. "
                "Available claims: %s",
                user_hint or "unknown",
                ", ".join(missing_required),
                ", ".join(sorted(decoded.keys())),
            )
        if not has_mfa_claim:
            _log.warning(
                "NIS2-COMPLIANCE: OIDC id_token for user [%s] contains neither 'amr' nor 'acr'. "
                "MFA status cannot be determined. "
                "Configure the IdP (ManageEngine ADSSPM) to emit 'amr' (RFC 8176) or 'acr' claims. "
                "Available claims: %s",
                user_hint or "unknown",
                ", ".join(sorted(decoded.keys())),
            )
        # ------------------------------------------------------------------

        oidc_sub = decoded.get("sub")
        amr = decoded.get("amr")
        acr = decoded.get("acr")
        if amr:
            mfa_status = ",".join(amr) if isinstance(amr, list) else str(amr)
        elif acr:
            mfa_status = str(acr)
        else:
            mfa_status = None
        return oidc_sub, mfa_status
    except Exception as e:
        _log.warning(
            "NIS2-COMPLIANCE: Failed to decode OIDC id_token for user [%s]: %s. "
            "OIDC sub and MFA status will be unavailable.",
            user_hint or "unknown", e,
        )
        return None, None


def _resolve_user_context(user_id: str) -> _UserContext:
    """Resolve email, oidc_sub and mfa_status for a user UUID.

    Uses the Users table for email and the OAuthSessions table for OIDC claims
    (decrypts the stored id_token server-side — no dependency on browser cookies).
    Thread-safe, bounded cache with TTL.
    """
    now = time.monotonic()

    with _cache_lock:
        entry = _cache_data.get(user_id)
        if entry is not None:
            ctx, ts = entry
            # Use shorter TTL when OIDC claims are missing (login race condition)
            ttl = _CACHE_TTL if ctx.oidc_sub else _CACHE_TTL_SHORT
            if now - ts < ttl:
                return ctx
            del _cache_data[user_id]

    # --- DB lookups (outside lock) ---
    email: Optional[str] = None
    oidc_sub: Optional[str] = None
    mfa_status: Optional[str] = None

    # 1) Resolve email from Users table
    try:
        from open_webui.models.users import Users
        user = Users.get_user_by_id(user_id)
        if user and getattr(user, "email", None):
            email = str(user.email)
    except Exception:
        pass

    # 2) Resolve OIDC claims from server-side OAuth session
    try:
        from open_webui.models.oauth_sessions import OAuthSessions
        sessions = OAuthSessions.get_sessions_by_user_id(user_id)
        if sessions:
            # Take the most recent session
            session = sessions[0]
            token_dict = session.token  # already decrypted by the model
            if isinstance(token_dict, dict):
                id_token_raw = token_dict.get("id_token")
                if id_token_raw and isinstance(id_token_raw, str):
                    oidc_sub, mfa_status = _decode_id_token_claims(
                        id_token_raw, user_hint=email or user_id
                    )
                else:
                    _log.warning(
                        "NIS2-COMPLIANCE: OAuth session for user [%s] does not contain an id_token. "
                        "The IdP (ManageEngine ADSSPM) token response must include an id_token "
                        "for NIS2-compliant logging. Token keys present: %s",
                        email or user_id,
                        ", ".join(sorted(token_dict.keys())) if token_dict else "(empty)",
                    )
                # Fallback: some providers put userinfo directly in the token response
                if not oidc_sub:
                    userinfo = token_dict.get("userinfo")
                    if isinstance(userinfo, dict):
                        oidc_sub = userinfo.get("sub")
        else:
            # User is authenticated but has no OAuth session — local account or API key
            _log.debug(
                "No OAuth session found for user %s — OIDC claims unavailable (local auth?)",
                user_id,
            )
    except Exception as e:
        _log.debug("Failed to resolve OIDC claims from OAuth session for user %s: %s", user_id, e)

    ctx = _UserContext(email=email, oidc_sub=oidc_sub, mfa_status=mfa_status)

    with _cache_lock:
        while len(_cache_data) >= _CACHE_MAX:
            _cache_data.pop(next(iter(_cache_data)))
        _cache_data[user_id] = (ctx, time.monotonic())

    return ctx


class AccessLogMiddleware(BaseHTTPMiddleware):
    """
    Middleware che logga TUTTE le richieste con user_id e session_id
    Bypassa completamente il logging di Uvicorn
    """
    
    def __init__(self, app, logger_name: str = "open_webui.access", exclude_paths: list = None):
        super().__init__(app)
        self.logger = logging.getLogger(logger_name)
        # Percorsi da escludere dal logging (es. health checks)
        self.exclude_paths = exclude_paths or ["/health", "/api/health"]
        
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Salta logging per percorsi esclusi (opzionale)
        if request.url.path in self.exclude_paths:
            return await call_next(request)
        
        # Genera o recupera session_id
        session_id = self._get_session_id(request)
        
        # Estrai user UUID dal JWT, poi risolvi email + OIDC claims dal DB (con cache)
        user_uuid = self._extract_user_uuid(request)
        if user_uuid:
            ctx = _resolve_user_context(user_uuid)
            user_display = ctx.email or user_uuid
            oidc_sub = ctx.oidc_sub
            mfa_status = ctx.mfa_status
        else:
            user_display = "anonymous"
            # Fast path: try to extract OIDC claims from cookies (pre-login, API keys, etc.)
            oidc_sub, mfa_status = self._get_oidc_claims_from_cookies(request)

        # NIS2: Extract correlation ID from WAF/ADSSPM
        correlation_id = self._get_correlation_id(request)
        
        # Client info: prefer Azure WAF / proxy headers over direct connection
        client_host = self._get_client_ip(request)
        # Only append port if using direct connection (not proxy headers)
        # Proxy headers like X-Forwarded-For may already include port info
        _has_proxy_header = any(
            request.headers.get(h) for h in (
                "X-Azure-ClientIP", "X-Original-Forwarded-For",
                "X-Forwarded-For", "X-Real-IP",
            )
        )
        if _has_proxy_header:
            client_display = client_host
        else:
            client_port = request.client.port if request.client else 0
            client_display = f"{client_host}:{client_port}"
        
        # Timestamp inizio
        start_time = time.time()
        
        # Esegui la richiesta
        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception as e:
            # Log anche in caso di eccezione
            process_time = time.time() - start_time
            self.logger.error(
                f"email={user_display} | session_id={session_id[:8]} | "
                f"correlation_id={correlation_id or '-'} | "
                f"oidc_sub={oidc_sub or '-'} | mfa={mfa_status or '-'} | "
                f"{client_display} - "
                f'"{request.method} {request.url.path}" EXCEPTION - '
                f"{str(e)[:100]} | time={process_time:.3f}s"
            )
            raise
        
        # Calcola tempo di elaborazione
        process_time = time.time() - start_time
        
        # Log NIS2-compliant con correlation ID, OIDC subject e MFA status
        self.logger.info(
            f"email={user_display} | session_id={session_id[:8]} | "
            f"correlation_id={correlation_id or '-'} | "
            f"oidc_sub={oidc_sub or '-'} | mfa={mfa_status or '-'} | "
            f"{client_display} - "
            f'"{request.method} {request.url.path}" {status_code} | '
            f"time={process_time:.3f}s"
        )
        
        # Aggiungi header alla risposta (opzionale)
        response.headers["X-Session-ID"] = session_id
        
        return response
    
    def _get_correlation_id(self, request: Request) -> Optional[str]:
        """Extract correlation ID from WAF/ADSSPM/Azure Front Door."""
        return (
            request.headers.get("X-Request-ID")
            or request.headers.get("X-Correlation-ID")
            or request.headers.get("X-Azure-Ref")
            or None
        )

    def _get_client_ip(self, request: Request) -> str:
        """
        Extract real client IP from Azure WAF / reverse proxy headers.

        Priority:
          1. X-Azure-ClientIP    — Azure Front Door / Application Gateway
          2. X-Original-Forwarded-For — original before WAF rewrite
          3. X-Forwarded-For     — standard proxy (first entry = real client)
          4. X-Real-IP           — nginx-style
          5. request.client.host — direct ASGI connection (container-internal)
        """
        for header in (
            "X-Azure-ClientIP",
            "X-Original-Forwarded-For",
            "X-Forwarded-For",
            "X-Real-IP",
        ):
            value = request.headers.get(header)
            if value:
                return value.split(",")[0].strip()

        return request.client.host if request.client else "-"

    def _get_oidc_claims_from_cookies(self, request: Request) -> tuple[Optional[str], Optional[str]]:
        """
        Fast path: extract OIDC sub + MFA from cookies without DB access.
        Used only for unauthenticated requests (no user UUID available).
        Tries oauth_id_token and Authorization Bearer tokens.
        """
        tokens_to_try = []

        oauth_id_token = request.cookies.get("oauth_id_token")
        if oauth_id_token:
            tokens_to_try.append(("oauth_id_token cookie", oauth_id_token))

        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            bearer = auth_header[len("Bearer "):]
            if not bearer.startswith("sk-"):
                tokens_to_try.append(("Bearer token", bearer))

        for source, token_value in tokens_to_try:
            oidc_sub, mfa_status = _decode_id_token_claims(token_value)
            if oidc_sub or mfa_status:
                return oidc_sub, mfa_status

        return None, None

    def _extract_user_uuid(self, request: Request) -> Optional[str]:
        """Extract the user UUID from request.state.user or from the session JWT cookie.

        Returns the UUID string, or None if the user is not authenticated.
        Does NOT do any DB lookups — that is deferred to _resolve_user_context.
        """
        try:
            # Method 1: request.state.user (set by auth middleware upstream)
            if hasattr(request.state, "user") and request.state.user:
                user = request.state.user
                uid = user.get("id") if isinstance(user, dict) else getattr(user, "id", None)
                if uid:
                    return str(uid)

            # Method 2: decode session JWT cookie
            token = request.cookies.get("token")
            if token and pyjwt is not None:
                decoded = pyjwt.decode(token, options={"verify_signature": False})
                uid = decoded.get("id")
                if uid:
                    return str(uid)
        except Exception:
            pass
        return None

    def _get_session_id(self, request: Request) -> str:
        """
        Recupera o genera un session_id
        La session_id dovrebbe essere persistente per tutta la sessione dell'utente
        """
        # PRIORITÀ 1: Cookie 'session_id' (più persistente)
        session_id = request.cookies.get("session_id")
        if session_id:
            return session_id
        
        # PRIORITÀ 2: Cookie 'token' (JWT token come session ID)
        token = request.cookies.get("token")
        if token:
            return hashlib.md5(token.encode()).hexdigest()[:16]
        
        # PRIORITÀ 3: Header 'X-Session-ID'
        session_id = request.headers.get("X-Session-ID")
        if session_id:
            return session_id
        
        # PRIORITÀ 4: Combinazione IP + User-Agent come identificatore temporaneo
        try:
            user_agent = request.headers.get("user-agent", "")
            client_ip = request.client.host if request.client else "unknown"
            composite = f"{client_ip}:{user_agent}"
            return hashlib.md5(composite.encode()).hexdigest()[:16]
        except Exception:
            pass
        
        # FALLBACK: Genera nuovo UUID
        return str(uuid.uuid4())[:16]
    

def setup_access_logging(app, log_level: str = "INFO", exclude_paths: list = None):
    """
    Setup del logging per l'applicazione
    Da chiamare in main.py DOPO aver creato l'app FastAPI
    
    Args:
        app: FastAPI application
        log_level: Livello di logging (INFO, DEBUG, WARNING, ERROR)
        exclude_paths: Lista di percorsi da escludere dal logging (es. ["/health"])
    """
    # Crea logger personalizzato
    logger = logging.getLogger("open_webui.access")
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Handler per stdout (esplicito sys.stdout per Azure Container Apps console)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(getattr(logging, log_level.upper()))
    
    # Formato semplice e leggibile
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    logger.propagate = False
    
    # Aggiungi il middleware all'app con percorsi da escludere
    if exclude_paths is None:
        exclude_paths = ["/health", "/api/health"]
    
    app.add_middleware(AccessLogMiddleware, exclude_paths=exclude_paths)
    
    # DISABILITA il logging di Uvicorn per evitare duplicati
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").propagate = False
    
    logger.info(f"Custom access logging attivato - Percorsi esclusi: {exclude_paths}")

