import re
from pathlib import Path

from bs4 import BeautifulSoup
import markdown


def test_every_changelog_h2_has_version_and_date_as_env_py_requires():
    changelog = next(p for p in Path(__file__).resolve().parents if (p / 'CHANGELOG.md').exists()) / 'CHANGELOG.md'
    html = markdown.markdown(changelog.read_text())
    headings = [h.get_text().strip() for h in BeautifulSoup(html, 'html.parser').find_all('h2')]
    assert headings
    for heading in headings:
        parts = heading.split(' - ')
        assert len(parts) >= 2 and re.fullmatch(r'\[[^\]]+\]', parts[0]), heading
        assert re.match(r'\d{4}-\d{2}-\d{2}', parts[1]), heading
