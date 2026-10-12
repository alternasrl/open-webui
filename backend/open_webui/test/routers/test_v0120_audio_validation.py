"""Audio package validation preserved across the upstream module split."""

import asyncio
import io
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, UploadFile
from starlette.datastructures import Headers
from starlette.requests import Request
from open_webui.routers import audio


def request(body=b'{}'):
    async def receive():
        return {'type': 'http.request', 'body': body}

    return Request(
        {
            'type': 'http',
            'method': 'POST',
            'path': '/speech',
            'headers': [],
            'app': SimpleNamespace(state=SimpleNamespace()),
        },
        receive=receive,
    )


@pytest.fixture
def config(monkeypatch):
    values = {
        'audio.tts.engine': 'openai',
        'audio.tts.model': 'tts-model',
        'audio.tts.voice': 'voice',
        'audio.tts.openai.api_base_url': 'https://api.example.com/v1',
        'audio.stt.supported_content_types': ['audio/mpeg'],
        'audio.stt.allowed_extensions': ['mp3'],
    }

    async def get(key, default=None):
        return values.get(key, default)

    monkeypatch.setattr(audio.Config, 'get', get)
    monkeypatch.setattr(audio, 'publish_event', AsyncMock())
    monkeypatch.setattr(audio, 'USE_SLIM', False)
    return values


@pytest.mark.parametrize('engine', ['openai', 'openai-realtime'])
def test_invalid_json_speech_is_rejected(config, engine):
    config['audio.tts.engine'] = engine
    with pytest.raises(HTTPException) as exc:
        asyncio.run(audio.speech(request(b'{invalid'), SimpleNamespace(role='admin')))
    assert exc.value.status_code == 400


@pytest.mark.parametrize('body', [b'[]', b'null', b'"text"', b'42'])
def test_non_object_speech_payload_is_rejected_before_dispatch(config, monkeypatch, body):
    async def no_dispatch(*args):
        pytest.fail('Non-object payload must not reach TTS')

    monkeypatch.setattr(audio, '_TTS_ENGINES', {'openai': no_dispatch})
    with pytest.raises(HTTPException) as exc:
        asyncio.run(audio.speech(request(body), SimpleNamespace(role='admin')))
    assert exc.value.status_code == 400


@pytest.mark.parametrize(
    'base_url',
    [
        'file:///private',
        'https://user:secret@example.com/v1',
        'https://example.com/v1?key=secret',
        'https://example.com:invalid/v1',
    ],
)
def test_realtime_rejects_invalid_api_url(config, base_url):
    config.update({'audio.tts.engine': 'openai-realtime', 'audio.tts.openai.api_base_url': base_url})
    with pytest.raises(HTTPException) as exc:
        asyncio.run(audio.speech(request(b'{"input":"hello"}'), SimpleNamespace(role='admin')))
    assert exc.value.status_code == 400


@pytest.mark.parametrize('payload', [b'{}', b'{"input":""}', b'{"input":"  "}', b'{"input":42}'])
def test_realtime_rejects_missing_or_non_text_input(config, payload):
    config['audio.tts.engine'] = 'openai-realtime'
    with pytest.raises(HTTPException) as exc:
        asyncio.run(audio.speech(request(payload), SimpleNamespace(role='admin')))
    assert exc.value.status_code == 400


def upload(filename, mime='audio/mpeg'):
    return UploadFile(io.BytesIO(b'audio'), filename=filename, headers=Headers({'content-type': mime}))


@pytest.mark.parametrize(
    ('filename', 'mime'),
    [
        ('voice.exe', 'audio/mpeg'),
        ('voice.mp3', 'application/pdf'),
        ('voice.mp3/../../escape', 'audio/mpeg'),
        (None, 'audio/mpeg'),
    ],
)
def test_transcription_rejects_unsupported_mime_or_extension(config, filename, mime):
    with pytest.raises(HTTPException) as exc:
        asyncio.run(audio.transcription(request(), upload(filename, mime), user=SimpleNamespace(role='admin')))
    assert exc.value.status_code == 400


def test_transcription_rejects_symlink_escape(config, monkeypatch, tmp_path):
    monkeypatch.setattr(audio, 'CACHE_DIR', tmp_path)
    monkeypatch.setattr(audio.uuid, 'uuid4', lambda: 'fixed')
    directory = tmp_path / 'audio' / 'transcriptions'
    directory.mkdir(parents=True)
    outside = tmp_path / 'outside.mp3'
    (directory / 'fixed.mp3').symlink_to(outside)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(audio.transcription(request(), upload('voice.mp3'), user=SimpleNamespace(role='admin')))
    assert exc.value.status_code == 400
    assert not outside.exists()


def test_transcription_sanitizes_extension_and_keeps_generated_path(config, monkeypatch, tmp_path):
    monkeypatch.setattr(audio, 'CACHE_DIR', tmp_path)
    monkeypatch.setattr(audio.uuid, 'uuid4', lambda: 'fixed')
    paths = []

    async def transcribe(req, path, metadata, user):
        paths.append(path)
        assert path.read_bytes() == b'audio'
        assert metadata == {'language': 'it'}
        return {'text': 'transcript'}

    monkeypatch.setattr(audio, 'transcribe', transcribe)
    result = asyncio.run(
        audio.transcription(
            request(),
            upload('../../voice.M-P3'),
            language='it',
            user=SimpleNamespace(role='admin'),
        )
    )
    assert result == {'text': 'transcript', 'filename': 'fixed.mp3'}
    assert paths == [tmp_path / 'audio' / 'transcriptions' / 'fixed.mp3']


@pytest.mark.parametrize('operation', ['speech', 'transcription'])
def test_audio_permission_denied_before_processing(config, monkeypatch, operation):
    monkeypatch.setattr(audio, 'has_permission', AsyncMock(return_value=False))
    user = SimpleNamespace(role='user', id='user')
    with pytest.raises(HTTPException) as exc:
        if operation == 'speech':
            asyncio.run(audio.speech(request(b'{"input":"hello"}'), user))
        else:
            asyncio.run(audio.transcription(request(), upload('voice.mp3'), user=user))
    assert exc.value.status_code == 403


def test_valid_speech_object_reaches_engine(config, monkeypatch, tmp_path):
    from starlette.responses import Response

    monkeypatch.setattr(audio, 'SPEECH_CACHE_DIR', tmp_path)

    async def handler(req, payload, file_path, file_body_path, user):
        assert payload == {'input': 'hello'}
        assert file_path.parent == tmp_path
        assert file_path.suffix == '.mp3'
        assert file_body_path.parent == tmp_path
        return Response(b'audio', media_type='audio/mpeg')

    monkeypatch.setattr(audio, '_TTS_ENGINES', {'openai': handler})
    result = asyncio.run(audio.speech(request(b'{"input":"hello"}'), SimpleNamespace(role='admin')))
    assert result.body == b'audio'
