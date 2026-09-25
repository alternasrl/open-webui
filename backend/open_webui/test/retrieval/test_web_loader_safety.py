import ipaddress
import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parents[3]))

from open_webui.constants import ERROR_MESSAGES
from open_webui.retrieval.utils import _is_text_content_type
from open_webui.retrieval.web import utils as web_utils


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
        ('application/pdf', False),
        ('font/woff2', False),
        ('image/png', False),
    ],
)
def test_binary_probe_content_type_filter(content_type, expected):
    assert _is_text_content_type(content_type) is expected
