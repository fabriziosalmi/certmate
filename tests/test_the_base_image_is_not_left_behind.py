"""A release does not ship a base image that its own tag has left a month behind (#403).

The Dockerfile pins its base by digest, which makes a rebuild byte-identical and means nothing
ever moves the pin. On 2026-10-02 the published image had 308 findings in Trivy (65 high) and the
same Dockerfile rebuilt on the digest the tag pointed at that day had 254 (53 high), with no change
to CertMate: the pin was 31 days old, put there by hand on 2026-09-07 (#722).

`scripts/check_base_image.py` says so, and `scripts/release.sh prepare` runs it. The decision is a
pure function of the Dockerfile text, the digest the tag points at and the pin's creation dates, so
it is tested here with no network; the one function that talks to the registry is exercised through
a stand-in `docker` that prints what `docker buildx imagetools inspect` prints.
"""
import datetime as dt
import importlib.util
import json
import os
import pathlib
import re
import stat

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = REPO / 'scripts' / 'check_base_image.py'

OLD = 'a' * 64
NEW = 'b' * 64
NOW = dt.datetime(2026, 10, 2, 12, 0, tzinfo=dt.UTC)


def _load():
    spec = importlib.util.spec_from_file_location('check_base_image', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = _load()


def _dockerfile(builder=OLD, runtime=OLD, image='python:3.12-slim-trixie'):
    return (f'# comment quoting @sha256:{"c" * 64} is not a pin\n'
            f'FROM {image}@sha256:{builder} AS builder\nRUN true\n'
            f'FROM {image}@sha256:{runtime}\nRUN true\n')


def _created(days_old):
    # Five minutes past the whole days, so the age is exactly `days_old`; nine fractional digits, as the registry writes them.
    stamp = (NOW - dt.timedelta(days=days_old, minutes=5)).strftime('%Y-%m-%dT%H:%M:%S.000000000Z')
    return {'linux/amd64': stamp, 'linux/arm64': stamp, 'linux/386': '2026-10-01T00:00:00Z'}


# --- the Dockerfile ----------------------------------------------------------

def test_every_stage_of_the_real_dockerfile_pins_the_same_base():
    image, digest = check.single_pin((REPO / 'Dockerfile').read_text(encoding='utf-8'))
    assert re.fullmatch(r'python:3\.12-slim-trixie', image) and re.fullmatch(r'[0-9a-f]{64}', digest)


def test_two_stages_on_different_bases_are_refused():
    with pytest.raises(check.BaseImageError, match='different bases'):
        check.single_pin(_dockerfile(builder=OLD, runtime=NEW))


def test_a_stage_with_no_digest_is_refused_by_name():
    text = 'FROM python:3.12-slim-trixie AS builder\nFROM python:3.12-slim-trixie@sha256:' + OLD + '\n'
    with pytest.raises(check.BaseImageError, match=re.escape('python:3.12-slim-trixie has no sha256 digest')):
        check.pins(text)


def test_scratch_is_not_a_base_and_a_file_with_no_from_is_refused():
    assert check.pins('FROM scratch\nFROM python:3.12@sha256:' + OLD + '\n') == [('python:3.12', OLD)]
    with pytest.raises(check.BaseImageError, match='no FROM'):
        check.pins('RUN true\n')


# --- the decision ------------------------------------------------------------

def test_a_pin_the_tag_has_not_moved_past_is_fine_at_any_age():
    ok, lines = check.evaluate(_dockerfile(), f'sha256:{OLD}', _created(400), NOW)
    assert ok and 'nothing to fix' in '\n'.join(lines)


def test_a_pin_behind_the_tag_but_young_is_fine():
    ok, lines = check.evaluate(_dockerfile(), f'sha256:{NEW}', _created(check.MAX_AGE_DAYS), NOW)
    assert ok and 'within' in '\n'.join(lines)


def test_a_pin_behind_the_tag_and_older_than_allowed_fails_and_says_how_to_fix_it():
    ok, lines = check.evaluate(_dockerfile(), f'sha256:{NEW}', _created(check.MAX_AGE_DAYS + 1), NOW)
    text = '\n'.join(lines)
    assert not ok
    assert f'{check.MAX_AGE_DAYS + 1} days old' in text and '--update' in text and '--allow-stale' in text


def test_the_measured_case_would_have_failed():
    """2026-10-02: a pin 31 days old, the tag moved on."""
    ok, _ = check.evaluate(_dockerfile(), f'sha256:{NEW}', _created(31), NOW)
    assert not ok


def test_an_override_passes_and_the_reason_is_in_the_output():
    ok, lines = check.evaluate(_dockerfile(), f'sha256:{NEW}', _created(31), NOW, allow_stale='hotfix, rebuilding later')
    assert ok and 'hotfix, rebuilding later' in '\n'.join(lines)


def test_the_age_is_the_oldest_of_the_published_platforms_and_ignores_the_others():
    created = {'linux/amd64': (NOW - dt.timedelta(days=3)).isoformat(),
               'linux/arm64': (NOW - dt.timedelta(days=20)).isoformat(),
               'linux/386': (NOW - dt.timedelta(days=900)).isoformat()}
    assert check.age_days(created, NOW) == 20
    with pytest.raises(check.BaseImageError, match='no creation date'):
        check.age_days({'linux/386': NOW.isoformat()}, NOW)


# --- the update --------------------------------------------------------------

def test_update_moves_every_stage_and_nothing_else():
    text = _dockerfile()
    moved = check.update(text, f'sha256:{NEW}')
    assert moved.count(f'@sha256:{NEW}') == 2 and f'@sha256:{OLD}' not in moved
    assert f'@sha256:{"c" * 64}' in moved, 'a digest quoted in a comment was rewritten'
    assert check.update(moved, f'sha256:{NEW}') == moved, 'not idempotent'


def test_update_refuses_what_it_cannot_do_safely():
    with pytest.raises(check.BaseImageError, match='not a digest'):
        check.update(_dockerfile(), 'latest')
    with pytest.raises(check.BaseImageError, match='different bases'):
        check.update(_dockerfile(runtime=NEW), f'sha256:{NEW}')


# --- the command, with a stand-in for docker ---------------------------------

def _fake_docker(tmp_path, digest_by_ref, created_days_by_ref, fail=False):
    """A `docker` that answers `buildx imagetools inspect <ref> --format {{json .}}` the way the
    real one does, for the references given."""
    answers = {ref: {'name': ref, 'manifest': {'digest': digest_by_ref[ref]},
                     'image': {p: {'created': c} for p, c in _created(created_days_by_ref[ref]).items()}}
               for ref in digest_by_ref}
    script = tmp_path / 'docker'
    script.write_text(
        '#!/usr/bin/env python3\nimport json, sys\n'
        f'if {fail!r}: sys.exit(1)\n'
        f'answers = json.loads({json.dumps(json.dumps(answers))})\n'
        'ref = sys.argv[4]\nprint(json.dumps(answers[ref]))\n')
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return tmp_path


def _command(tmp_path, dockerfile_text, args, fake):
    """Run main() with the real docker call, and the stand-in on PATH."""
    dockerfile = tmp_path / 'Dockerfile'
    dockerfile.write_text(dockerfile_text)
    saved = os.environ['PATH']
    os.environ['PATH'] = f'{fake}{os.pathsep}{saved}'
    try:
        code = check.main(list(args), now=NOW, dockerfile=dockerfile)
    finally:
        os.environ['PATH'] = saved
    return code, dockerfile.read_text()


def test_the_command_fails_for_a_stale_pin_through_the_real_docker_call(tmp_path, capsys):
    fake = _fake_docker(tmp_path, {'python:3.12-slim-trixie': f'sha256:{NEW}',
                                   f'python:3.12-slim-trixie@sha256:{OLD}': f'sha256:{OLD}'},
                        {'python:3.12-slim-trixie': 1, f'python:3.12-slim-trixie@sha256:{OLD}': 31})
    code, _ = _command(tmp_path, _dockerfile(), [], fake)
    assert code == 1 and 'BEHIND the tag' in capsys.readouterr().out


def test_the_command_passes_with_a_logged_override_and_rewrites_with_update(tmp_path, capsys):
    fake = _fake_docker(tmp_path, {'python:3.12-slim-trixie': f'sha256:{NEW}',
                                   f'python:3.12-slim-trixie@sha256:{OLD}': f'sha256:{OLD}'},
                        {'python:3.12-slim-trixie': 1, f'python:3.12-slim-trixie@sha256:{OLD}': 31})
    code, _ = _command(tmp_path, _dockerfile(), ['--allow-stale', 'because'], fake)
    assert code == 0 and '--allow-stale: because' in capsys.readouterr().out
    code, text = _command(tmp_path, _dockerfile(), ['--update'], fake)
    assert code == 0 and text.count(f'@sha256:{NEW}') == 2


def test_an_unreachable_registry_is_a_refusal_that_says_what_is_needed(tmp_path, capsys):
    fake = _fake_docker(tmp_path, {}, {}, fail=True)
    code, _ = _command(tmp_path, _dockerfile(), [], fake)
    err = capsys.readouterr().err
    assert code == 1 and 'could not read' in err and 'Docker and the network' in err


# --- it is wired into the release --------------------------------------------

def test_release_prepare_runs_the_check_and_offers_the_logged_override():
    script = (REPO / 'scripts' / 'release.sh').read_text(encoding='utf-8')
    assert 'scripts/check_base_image.py' in script
    assert '--allow-stale-base' in script.split('cmd_prepare()')[1].split('# --- gates')[0], (
        'the override is not parsed by prepare')
    # Before the build: a stale base should fail in seconds, not after the image is built.
    gate = script.index('base image digest (not left behind its tag)')
    assert gate < script.index('gate "Docker build"')


def test_the_threshold_is_two_weeks_and_a_change_to_it_is_a_decision():
    assert check.MAX_AGE_DAYS == 14
