import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

sys.path.append(str(Path(__file__).resolve().parents[3]))

from open_webui.routers import ollama as ollama_router
from open_webui.routers import openai as openai_router


@pytest.mark.parametrize(
    ('endpoint', 'kwargs'),
    [
        (openai_router.get_models, {}),
        (ollama_router.get_openai_models, {'db': None}),
        (ollama_router.get_ollama_tags, {}),
        (ollama_router.get_ollama_versions, {}),
    ],
)
def test_provider_index_routes_reject_non_admin_with_url_idx(endpoint, kwargs):
    async def scenario():
        with pytest.raises(HTTPException) as exc_info:
            await endpoint(
                request=SimpleNamespace(),
                url_idx=0,
                user=SimpleNamespace(role='user'),
                **kwargs,
            )
        assert exc_info.value.status_code == 401

    asyncio.run(scenario())


def test_openai_provider_index_allows_admin_past_inline_guard(monkeypatch):
    async def fake_get(key, default=None):
        if key == 'openai.enable':
            return False
        return default

    async def scenario():
        monkeypatch.setattr(openai_router.Config, 'get', fake_get)
        with pytest.raises(HTTPException) as exc_info:
            await openai_router.get_models(
                request=SimpleNamespace(),
                url_idx=0,
                user=SimpleNamespace(role='admin'),
            )
        assert exc_info.value.status_code == 503

    asyncio.run(scenario())


def test_ollama_openai_compat_models_allows_admin_past_inline_guard(monkeypatch):
    async def fake_get(key, default=None):
        if key == 'ollama.base_urls':
            return ['http://ollama.example']
        return default

    async def fake_send_request(*args, **kwargs):
        return {'models': []}

    async def scenario():
        monkeypatch.setattr(ollama_router.Config, 'get', fake_get)
        monkeypatch.setattr(ollama_router, 'send_request', fake_send_request)
        result = await ollama_router.get_openai_models(
            request=SimpleNamespace(),
            url_idx=0,
            user=SimpleNamespace(role='admin'),
            db=None,
        )
        assert result == {'data': [], 'object': 'list'}

    asyncio.run(scenario())


def test_ollama_tags_allows_admin_past_inline_guard(monkeypatch):
    async def fake_get(key, default=None):
        if key == 'ollama.enable':
            return False
        return default

    async def scenario():
        monkeypatch.setattr(ollama_router.Config, 'get', fake_get)
        with pytest.raises(HTTPException) as exc_info:
            await ollama_router.get_ollama_tags(
                request=SimpleNamespace(),
                url_idx=0,
                user=SimpleNamespace(role='admin'),
            )
        assert exc_info.value.status_code == 503

    asyncio.run(scenario())


def test_ollama_versions_allows_admin_past_inline_guard(monkeypatch):
    async def fake_get(key, default=None):
        if key == 'ollama.enable':
            return False
        return default

    async def scenario():
        monkeypatch.setattr(ollama_router.Config, 'get', fake_get)
        result = await ollama_router.get_ollama_versions(
            request=SimpleNamespace(),
            url_idx=0,
            user=SimpleNamespace(role='admin'),
        )
        assert result == {'version': False}

    asyncio.run(scenario())
