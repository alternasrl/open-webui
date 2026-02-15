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
from typing import Callable, Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

try:
    import jwt as pyjwt
except ImportError:
    pyjwt = None


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
        
        # Estrai user_id dall'autenticazione
        user_id = await self._get_user_id(request)

        # NIS2: Extract correlation ID from WAF/ADSSPM
        correlation_id = self._get_correlation_id(request)

        # NIS2: Extract OIDC claims (sub, MFA status)
        oidc_sub, mfa_status = self._get_oidc_nis2_fields(request)
        
        # Client info: prefer Azure WAF / proxy headers over direct connection
        client_host = self._get_client_ip(request)
        client_port = request.client.port if request.client else 0
        
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
                f"email={user_id} | session_id={session_id[:8]} | "
                f"correlation_id={correlation_id or '-'} | "
                f"oidc_sub={oidc_sub or '-'} | mfa={mfa_status or '-'} | "
                f"{client_host}:{client_port} - "
                f'"{request.method} {request.url.path}" EXCEPTION - '
                f"{str(e)[:100]} | time={process_time:.3f}s"
            )
            raise
        
        # Calcola tempo di elaborazione
        process_time = time.time() - start_time
        
        # Log NIS2-compliant con correlation ID, OIDC subject e MFA status
        self.logger.info(
            f"email={user_id} | session_id={session_id[:8]} | "
            f"correlation_id={correlation_id or '-'} | "
            f"oidc_sub={oidc_sub or '-'} | mfa={mfa_status or '-'} | "
            f"{client_host}:{client_port} - "
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

    def _get_oidc_nis2_fields(self, request: Request) -> tuple[Optional[str], Optional[str]]:
        """
        Extract NIS2-relevant OIDC fields from JWT tokens.
        Returns (oidc_sub, mfa_status) tuple.

        Tries:
          1. oauth_id_token cookie (OIDC ID token)
          2. Authorization Bearer token
          3. token cookie (session JWT)
        """
        tokens_to_try = []

        oauth_id_token = request.cookies.get("oauth_id_token")
        if oauth_id_token:
            tokens_to_try.append(oauth_id_token)

        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            bearer = auth_header[len("Bearer "):]
            if not bearer.startswith("sk-"):
                tokens_to_try.append(bearer)

        session_token = request.cookies.get("token")
        if session_token:
            tokens_to_try.append(session_token)

        for token in tokens_to_try:
            try:
                if pyjwt is None:
                    continue
                decoded = pyjwt.decode(
                    token,
                    options={"verify_signature": False},
                    algorithms=["RS256", "HS256", "ES256"],
                )
                oidc_sub = decoded.get("sub")
                # MFA status: amr is a list of methods, acr is a single value
                amr = decoded.get("amr")
                acr = decoded.get("acr")
                if amr:
                    mfa_status = ",".join(amr) if isinstance(amr, list) else str(amr)
                elif acr:
                    mfa_status = str(acr)
                else:
                    mfa_status = None

                if oidc_sub or mfa_status:
                    return oidc_sub, mfa_status
            except Exception:
                continue

        return None, None

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
    
    async def _get_user_id(self, request: Request) -> str:
        """Estrae email (o user_id come fallback) dalla richiesta"""
        try:
            # Metodo 1: request.state.user (dopo autenticazione)
            if hasattr(request.state, "user") and request.state.user:
                user = request.state.user
                if isinstance(user, dict):
                    # PRIORITÀ: email > username > id
                    email = user.get("email")
                    if email:
                        return str(email)
                    username = user.get("username")
                    if username:
                        return str(username)
                    user_id = user.get("id")
                    if user_id:
                        return str(user_id)
                elif hasattr(user, "email"):
                    return str(user.email)
                elif hasattr(user, "username"):
                    return str(user.username)
                elif hasattr(user, "id"):
                    return str(user.id)
            
            # Metodo 2: JWT token nei cookies - estrai l'email
            token = request.cookies.get("token")
            if token:
                try:
                    if pyjwt is not None:
                        decoded = pyjwt.decode(token, options={"verify_signature": False})
                        # PRIORITÀ: email > username > sub > user_id > id
                        email = (
                            decoded.get("email") or
                            decoded.get("username") or 
                            decoded.get("sub") or 
                            decoded.get("user_id") or
                            decoded.get("id")
                        )
                        if email:
                            return str(email)
                except Exception as e:
                    self.logger.debug(f"Errore decodifica JWT: {e}")
        
        except Exception as e:
            self.logger.debug(f"Errore estrazione user: {e}")
        
        return "anonymous"


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

