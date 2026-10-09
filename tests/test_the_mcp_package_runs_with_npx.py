"""The MCP server is a package an MCP client can run with npx (#1017).

Checked by running it: `npm pack`, then `npx -y --package <tarball>
certmate-mcp-server` from an empty directory, then a real MCP handshake
against a running CertMate (initialize, tools/list, a tools/call that reached
the API). What that run depended on is pinned here, because each is a way the
published package could install fine and then not start:

* `bin` names the command `npx certmate-mcp-server` runs, and index.js starts
  with a shebang, without which the bin is not executable as a command;
* `files` ships index.js (and the README, which is the npm page);
* the version the server reports is package.json's, not a second copy;
* `repository.url` is this repository, which npm trusted publishing requires
  to match exactly;
* the publish workflow refuses a tag that disagrees with package.json, and is
  the only workflow that can mint an OIDC token for npm.
"""
import json
import re
from pathlib import Path

import pytest
import yaml

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
PKG = json.loads((REPO / 'mcp' / 'package.json').read_text())
INDEX = (REPO / 'mcp' / 'index.js').read_text()
WORKFLOW = REPO / '.github' / 'workflows' / 'publish-mcp.yml'


def test_npx_has_a_command_to_run():
    assert PKG['bin'] == {'certmate-mcp-server': 'index.js'}
    assert INDEX.startswith('#!/usr/bin/env node\n')


def test_the_tarball_ships_the_server_and_its_page():
    assert set(PKG['files']) == {'index.js', 'README.md'}
    assert (REPO / 'mcp' / 'README.md').exists()


def test_the_reported_version_is_package_json():
    assert 'require("./package.json")' in INDEX
    assert not re.search(r'version:\s*"\d+\.\d+\.\d+"', INDEX), (
        'index.js hard-codes a version again; it will drift from package.json')


def test_the_repository_is_this_one():
    assert PKG['repository']['url'] == 'git+https://github.com/fabriziosalmi/certmate.git'
    assert PKG['repository']['directory'] == 'mcp'
    assert PKG['publishConfig'] == {'access': 'public'}


def test_the_publish_workflow_gates_the_version_and_alone_mints_npm_tokens():
    wf = yaml.safe_load(WORKFLOW.read_text())
    job = wf['jobs']['publish']
    assert job['permissions'] == {'contents': 'read', 'id-token': 'write'}
    assert job['environment'] == 'npm'
    gate = next(s for s in job['steps'] if s.get('name') == 'Fail unless the tag matches package.json')
    assert 'refs/tags/mcp-v*' in gate['run']
    # `on:` parses as True in YAML 1.1.
    triggers = wf.get('on', wf.get(True))
    assert triggers['push']['tags'] == ['mcp-v*']
