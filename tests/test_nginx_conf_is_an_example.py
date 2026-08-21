"""#576 — nginx.conf is the operator's file, nginx.conf.example is ours.

A tracked nginx.conf with <your-domain> placeholders forced every deployment
to edit a tracked file: a permanently dirty tree and a conflict on every
pull. Same pattern as .env.example / .env now.
"""
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

# The tracked/ignored checks need a git checkout; an sdist or a vendored copy
# has none, and that is not what is under test here.
pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(not (REPO / '.git').exists(), reason='not a git checkout'),
]


def _git(*args):
    return subprocess.run(['git', *args], cwd=REPO, capture_output=True, text=True, timeout=30)


def _tracked(path):
    return _git('ls-files', '--error-unmatch', path).returncode == 0


def test_the_example_is_tracked_and_carries_the_placeholders():
    example = REPO / 'nginx.conf.example'
    assert example.exists()
    assert _tracked('nginx.conf.example')
    assert '<your-domain>' in example.read_text(encoding='utf-8')


def test_the_operators_copy_is_ignored_not_tracked():
    assert not _tracked('nginx.conf'), 'nginx.conf must not be tracked any more'
    assert _git('check-ignore', '-q', 'nginx.conf').returncode == 0, 'nginx.conf must be gitignored'


def test_compose_and_docs_say_to_copy_it_first():
    compose = (REPO / 'docker-compose.yml').read_text(encoding='utf-8')
    assert 'nginx.conf.example' in compose
    assert './nginx.conf:/etc/nginx/nginx.conf:ro' in compose
    docs = (REPO / 'docs' / 'installation.md').read_text(encoding='utf-8')
    assert 'cp nginx.conf.example nginx.conf' in docs
