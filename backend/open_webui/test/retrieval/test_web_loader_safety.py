import ipaddress
import sys
import asyncio
import socket
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests
from langchain_core.documents import Document

sys.path.append(str(Path(__file__).resolve().parents[3]))

from open_webui.constants import ERROR_MESSAGES
from open_webui.retrieval.utils import _is_text_content_type
from open_webui.retrieval.web import utils as web_utils
from open_webui.retrieval import utils as retrieval_utils


@pytest.fixture
def public_dns(monkeypatch):
    monkeypatch.setattr(web_utils, 'ENABLE_LOCAL_WEB_FETCH', False)
    monkeypatch.setattr(web_utils, 'WEB_FETCH_FILTER_LIST', [])
    monkeypatch.setattr(web_utils, 'resolve_hostname', lambda host: (['8.8.8.8'], []))


@pytest.mark.parametrize(
    'url',
    [
        'ftp://example.com/file',
        'http://127.0.0.1\\@example.com/',
        'http://example.com/\tprivate',
        'https://example.com/\r\nprivate',
    ],
)
def test_ambiguous_or_non_http_urls_are_rejected(public_dns, url):
    with pytest.raises(ValueError):
        web_utils.validate_url(url)


@pytest.mark.parametrize(
    'address',
    [
        '::ffff:127.0.0.1',
        '2002:7f00:0001::',
        '::127.0.0.1',
        '64:ff9b::7f00:1',
        '64:ff9b:1:7f00:0:100::',
    ],
)
def test_embedded_private_ipv4_is_blocked(public_dns, monkeypatch, address):
    monkeypatch.setattr(web_utils, 'resolve_hostname', lambda host: ([], [address]))
    with pytest.raises(ValueError):
        web_utils.validate_url('https://example.com/')


def test_connection_rechecks_dns_before_creating_socket(public_dns, monkeypatch):
    monkeypatch.setattr(
        socket,
        'getaddrinfo',
        lambda *args: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443)),
        ],
    )

    def no_socket(*args):
        pytest.fail('A rejected DNS answer must not open a socket')

    monkeypatch.setattr(socket, 'socket', no_socket)
    assert web_utils.validate_url('https://example.com/')
    with pytest.raises(ValueError):
        web_utils._ssrf_safe_new_conn(SimpleNamespace(host='example.com', port=443))


def test_requests_adapter_rechecks_redirect_target(public_dns, monkeypatch):
    monkeypatch.setattr(web_utils, 'WEB_FETCH_FILTER_LIST', ['!blocked.example.com'])
    request = requests.Request('GET', 'https://blocked.example.com/private').prepare()
    with pytest.raises(ValueError):
        web_utils._SSRFSafeAdapter().send(request)


@pytest.mark.parametrize('follow_redirects', [False, True])
def test_requests_redirect_is_disabled_or_rechecked(public_dns, monkeypatch, follow_redirects):
    monkeypatch.setattr(web_utils, 'WEB_FETCH_FILTER_LIST', ['!blocked.example.com'])
    response = requests.Response()
    response.status_code = 302
    response.headers['Location'] = 'https://blocked.example.com/private'
    response._content = b''
    response.close = Mock()
    sent = []

    def send(adapter, request, **kwargs):
        sent.append(request.url)
        response.request = request
        response.url = request.url
        return response

    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    with web_utils.get_ssrf_safe_requests_session(trust_env=False) as session:
        if follow_redirects:
            with pytest.raises(ValueError):
                session.get('https://example.com/', allow_redirects=True)
            assert response.close.call_count == 1
        else:
            result = session.get('https://example.com/', allow_redirects=False)
            assert result.status_code == 302
    assert sent == ['https://example.com/']


def test_async_connector_rechecks_resolved_private_address(public_dns, monkeypatch):
    import aiohttp

    async def resolve(*args, **kwargs):
        return [
            {
                'host': '127.0.0.1',
                'hostname': 'example.com',
                'port': 443,
                'family': socket.AF_INET,
                'proto': 0,
                'flags': 0,
            }
        ]

    monkeypatch.setattr(aiohttp.TCPConnector, '_resolve_host', resolve)

    async def run():
        connector = web_utils._SSRFSafeConnector()
        try:
            with pytest.raises(ValueError):
                await connector._resolve_host('example.com', 443)
        finally:
            await connector.close()

    asyncio.run(run())


@pytest.fixture
def loader_config():
    return {
        'web.loader.engine': 'safe_web',
        'web.loader.ssl_verification': False,
        'web.loader.concurrent_requests': 3,
        'web.search.trust_env': False,
        'web.loader.timeout': 7,
        'rag.youtube_loader_language': ['it'],
        'rag.youtube_loader_proxy_url': 'http://proxy.example.com',
        'rag.file.max_size': 1,
    }


@pytest.mark.parametrize('trust_env', [False, True])
def test_safe_loader_uses_explicit_config(public_dns, loader_config, trust_env):
    loader_config['web.search.trust_env'] = trust_env
    loader = web_utils.get_web_loader('https://example.com/', loader_config)
    try:
        assert loader.session.trust_env is trust_env
        assert loader.session.verify is False
        assert loader.session.headers == web_utils.WEB_LOADER_HEADERS
        assert loader.requests_kwargs['timeout'] == 7
        assert loader.requests_per_second == 3
        assert isinstance(loader.session.get_adapter('https://'), web_utils._SSRFSafeAdapter)
    finally:
        loader.session.close()


def test_youtube_short_link_skips_mime_probe(public_dns, monkeypatch, loader_config):
    def no_probe(*args, **kwargs):
        pytest.fail('YouTube short links must not be probed')

    monkeypatch.setattr(web_utils, 'get_ssrf_safe_requests_session', no_probe)

    class TranscriptLoader:
        def __init__(self, url, language, proxy_url):
            assert url == 'https://youtu.be/video'
            assert language == ['it']
            assert proxy_url == 'http://proxy.example.com'

        def load(self):
            return [Document(page_content='transcript', metadata={'source': 'youtube'})]

    monkeypatch.setattr(retrieval_utils, 'YoutubeLoader', TranscriptLoader)
    content, docs = asyncio.run(
        retrieval_utils.get_content_from_url(
            None,
            'https://youtu.be/video',
            config=loader_config,
        )
    )
    assert content == 'transcript'
    assert docs[0].metadata == {'source': 'youtube'}


@pytest.mark.parametrize(
    'mode', ['text', 'binary', 'http_error', 'get_error', 'loader_factory_error', 'load_error', 'extract_error']
)
def test_probe_closes_response_and_session(public_dns, monkeypatch, loader_config, mode):
    response = requests.Response()
    response.status_code = 500 if mode == 'http_error' else 200
    response.headers['Content-Type'] = 'application/pdf' if 'binary' in mode or mode == 'extract_error' else 'text/html'
    response.close = Mock()
    session = requests.Session()
    session.get = Mock(return_value=response)
    if mode == 'get_error':
        session.get.side_effect = requests.ConnectionError('probe failed')
    session.close = Mock()
    monkeypatch.setattr(web_utils, 'get_ssrf_safe_requests_session', lambda **kwargs: session)

    class Loader:
        def load(self):
            if mode == 'load_error':
                raise ValueError('loader failed')
            if mode != 'get_error':
                assert response.close.called, 'Close the probe before starting another loader'
            return [Document(page_content='html')]

    def get_loader(request, url, config):
        if mode == 'loader_factory_error':
            raise ValueError('loader construction failed')
        return Loader()

    monkeypatch.setattr(retrieval_utils, 'get_loader', get_loader)

    def extract(request, res, url, config):
        assert res is response
        assert config is loader_config
        if mode == 'extract_error':
            raise ValueError('extract failed')
        return 'pdf', [Document(page_content='pdf')]

    monkeypatch.setattr(retrieval_utils, '_extract_text_from_binary_response', extract)
    if mode in {'loader_factory_error', 'load_error', 'extract_error'}:
        with pytest.raises(ValueError):
            retrieval_utils._get_content_from_url_sync(None, 'https://example.com/', loader_config)
    else:
        content, docs = retrieval_utils._get_content_from_url_sync(None, 'https://example.com/', loader_config)
        assert content == ('pdf' if mode == 'binary' else 'html')
        assert docs[0].page_content == content
    assert response.close.call_count == (0 if mode == 'get_error' else 1)
    assert session.close.call_count == 1


@pytest.mark.parametrize('trust_env', [False, True])
def test_probe_honors_explicit_proxy_and_ssl_settings(public_dns, monkeypatch, loader_config, trust_env):
    loader_config['web.search.trust_env'] = trust_env
    session = requests.Session()
    observed = {}
    response = requests.Response()
    response.status_code = 200
    response.headers['Content-Type'] = 'text/plain'
    response.close = Mock()

    def factory(*, trust_env=True, **kwargs):
        session.trust_env = trust_env
        return session

    def get(url, **kwargs):
        observed.update(trust_env=session.trust_env, verify=session.verify, headers=dict(session.headers), **kwargs)
        return response

    monkeypatch.setattr(web_utils, 'get_ssrf_safe_requests_session', factory)
    monkeypatch.setattr(session, 'get', get)
    monkeypatch.setattr(
        retrieval_utils,
        'get_loader',
        lambda *args: SimpleNamespace(
            load=lambda: [Document(page_content='configured')],
        ),
    )
    assert retrieval_utils._get_content_from_url_sync(None, 'https://example.com/', loader_config)[0] == 'configured'
    assert observed['trust_env'] is trust_env
    assert observed['verify'] is False
    assert observed['headers'] == web_utils.WEB_LOADER_HEADERS
    assert observed['allow_redirects'] is web_utils.AIOHTTP_CLIENT_ALLOW_REDIRECTS


def test_binary_download_uses_explicit_config_and_deletes_file(monkeypatch, loader_config):
    response = requests.Response()
    response.headers['Content-Type'] = 'application/pdf'
    response.iter_content = lambda size: iter([b'pdf-body'])
    saved_paths = []

    class BinaryLoader:
        def load(self, filename, content_type, path):
            assert filename == 'document.pdf'
            assert content_type == 'application/pdf'
            assert Path(path).read_bytes() == b'pdf-body'
            saved_paths.append(Path(path))
            return [Document(page_content='extracted', metadata={'page': 1})]

    def factory(config):
        assert config is loader_config
        return BinaryLoader()

    monkeypatch.setattr(retrieval_utils, 'build_loader_from_config', factory)
    text, docs = retrieval_utils._extract_text_from_binary_response(
        None,
        response,
        'https://example.com/document.pdf',
        loader_config,
    )
    assert text == 'extracted'
    assert docs[0].metadata == {'page': 1, 'source': 'https://example.com/document.pdf'}
    assert saved_paths and all(not path.exists() for path in saved_paths)


def test_binary_size_limit_cleans_partial_download(monkeypatch, loader_config):
    import tempfile

    created = []
    original = tempfile.mkstemp

    def mkstemp(**kwargs):
        fd, path = original(**kwargs)
        created.append(Path(path))
        return fd, path

    monkeypatch.setattr(tempfile, 'mkstemp', mkstemp)
    response = requests.Response()
    response.headers['Content-Type'] = 'application/pdf'
    response.iter_content = lambda size: iter([b'x' * (1024 * 1024), b'x'])
    with pytest.raises(ValueError):
        retrieval_utils._extract_text_from_binary_response(
            None,
            response,
            'https://example.com/document.pdf',
            loader_config,
        )
    assert created and all(not path.exists() for path in created)


def test_validate_url_rejects_non_http_scheme():
    with pytest.raises(ValueError, match=ERROR_MESSAGES.INVALID_URL):
        web_utils.validate_url('file:///etc/passwd')


def test_validate_url_rejects_parser_confusing_characters():
    with pytest.raises(ValueError, match=ERROR_MESSAGES.INVALID_URL):
        web_utils.validate_url('http://127.0.0.1\\@example.com/')


def test_embedded_ipv4_detection_covers_mapped_and_6to4_addresses():
    mapped = ipaddress.ip_address('::ffff:127.0.0.1')
    sixtofour = ipaddress.ip_address('2002:7f00:0001::')

    assert ipaddress.ip_address('127.0.0.1') in web_utils._embedded_ipv4(mapped)
    assert ipaddress.ip_address('127.0.0.1') in web_utils._embedded_ipv4(sixtofour)


def test_playwright_loader_drops_heavy_resource_types():
    assert {'font', 'image', 'media'} <= web_utils._DROPPED_RESOURCE_TYPES


@pytest.mark.parametrize(
    ('content_type', 'expected'),
    [
        ('text/html; charset=utf-8', True),
        ('application/json', True),
        ('application/problem+json', True),
        (' APPLICATION/XML; charset=utf-8', True),
        ('application/atom+xml', True),
        ('', True),
        ('application/pdf', False),
        ('font/woff2', False),
        ('image/png', False),
    ],
)
def test_binary_probe_content_type_filter(content_type, expected):
    assert _is_text_content_type(content_type) is expected
