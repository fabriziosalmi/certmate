#!/usr/bin/env python3
"""Say how far behind the Dockerfile's pinned base image is, and refuse a release that ships a stale one.

The Dockerfile pins its base by digest (`FROM python:3.12-slim-trixie@sha256:...`), on purpose: the
tag moves, the digest does not, so a rebuild is byte-identical. The price is that **nothing moves
the pin**. Debian publishes fixes and the tag follows; the pin stays where it was put. Measured on
2026-10-02, after 31 days: the published image had 308 findings in Trivy (65 high), and the same
Dockerfile rebuilt on the current digest had 254 (53 high) with no change to CertMate (#403). The
last re-pin was by hand on 2026-09-07 (#722) and Dependabot has not moved it since.

So the release says it. `scripts/release.sh prepare` runs this, and it fails when the pinned digest
is not the one the tag points at today AND the pinned image is older than MAX_AGE_DAYS. A pin that
the tag has not moved past is fine at any age (nothing to fix), and a pin that is behind but young
is fine (a base moves weekly; a release must not be refused for a tag that moved yesterday).

    scripts/check_base_image.py                 check, exit 1 when stale
    scripts/check_base_image.py --update        write the current digest into the Dockerfile
    scripts/check_base_image.py --allow-stale "reason"
                                                pass, and say why (logged, like --skip-real-cert)

The decision is a pure function of text and dates (`evaluate`), tested without a network; only
`inspect_with_docker` touches the registry, and it is handed in.
"""
import argparse
import datetime as dt
import json
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
DOCKERFILE = REPO / 'Dockerfile'

# Two weeks. A Debian base is rebuilt about weekly; two weeks is "missed one", not "the tag moved
# yesterday". The 31 days that produced 54 more findings is far past it.
MAX_AGE_DAYS = 14

# The platforms CertMate publishes. The age of a pin is the OLDEST creation date among them.
PLATFORMS = ('linux/amd64', 'linux/arm64')

FROM = re.compile(r'^FROM\s+(?P<ref>\S+)(?P<rest>.*)$', re.M)
PINNED = re.compile(r'^(?P<image>[^@\s]+)@sha256:(?P<digest>[0-9a-f]{64})$')


class BaseImageError(Exception):
    """Something the gate refuses, with the sentence that says what to do."""


def pins(dockerfile_text):
    """[(image_with_tag, digest)] for every FROM line, in order. A FROM with no digest is an error:
    the Dockerfile's own comment says the base is pinned, and an unpinned stage is the pin gone."""
    found = []
    for match in FROM.finditer(dockerfile_text):
        ref = match.group('ref')
        if ref.lower() == 'scratch':
            continue
        pinned = PINNED.match(ref)
        if not pinned:
            raise BaseImageError(
                f'FROM {ref} has no sha256 digest. Every stage of the Dockerfile pins its base by digest, '
                'so that a rebuild is byte-identical; `scripts/check_base_image.py --update` writes one.')
        found.append((pinned.group('image'), pinned.group('digest')))
    if not found:
        raise BaseImageError('the Dockerfile has no FROM line')
    return found


def single_pin(dockerfile_text):
    """The one (image, digest) every stage uses. Stages that disagree are an error: the builder
    would compile against one Debian and the runtime would run on another."""
    found = pins(dockerfile_text)
    if len(set(found)) != 1:
        raise BaseImageError('the stages of the Dockerfile pin different bases: '
                             + ', '.join(f'{image}@{digest[:12]}' for image, digest in found))
    return found[0]


def age_days(created, now):
    """Whole days between *now* and the oldest of the published platforms' creation dates."""
    stamps = [dt.datetime.fromisoformat(created[p].replace('Z', '+00:00')) for p in PLATFORMS if p in created]
    if not stamps:
        raise BaseImageError('the registry gave no creation date for any published platform')
    return (now - min(stamps)).days


def evaluate(dockerfile_text, current, pinned_info, now, allow_stale=None):
    """(ok, lines). *current* is the digest the tag points at today; *pinned_info* is the
    {platform: created} of the pinned digest."""
    image, digest = single_pin(dockerfile_text)
    age = age_days(pinned_info, now)
    lines = [f'base image: {image}', f'  pinned:  sha256:{digest[:16]}... (created {age} days ago)',
             f'  current: {current[:23]}...' if current.startswith('sha256:') else f'  current: {current}']
    if current == f'sha256:{digest}':
        lines.append('  the tag has not moved past the pin: nothing to fix')
        return True, lines
    if age <= MAX_AGE_DAYS:
        lines.append(f'  behind the tag, but {age} days old is within the {MAX_AGE_DAYS} allowed')
        return True, lines
    lines.append(f'  BEHIND the tag by a pin {age} days old; the most allowed is {MAX_AGE_DAYS}.')
    if allow_stale:
        lines.append(f'  --allow-stale: {allow_stale}')
        return True, lines
    lines.append('  Re-pin it: `scripts/check_base_image.py --update`, read the diff, and let the real-certificate '
                 'gate run on it; or pass `--allow-stale "reason"` (logged) to ship this one anyway.')
    return False, lines


def update(dockerfile_text, current_digest):
    """The Dockerfile text with every pinned FROM moved to *current_digest* (`sha256:...`)."""
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', current_digest):
        raise BaseImageError(f'not a digest: {current_digest!r}')
    single_pin(dockerfile_text)           # refuses unpinned and disagreeing stages first
    # Only the FROM lines: a digest quoted in a comment is not a pin.
    return FROM.sub(lambda m: re.sub(r'@sha256:[0-9a-f]{64}', '@' + current_digest, m.group(0)), dockerfile_text)


def inspect_with_docker(reference):
    """{'digest': 'sha256:...', 'created': {platform: iso}} for *reference*, from the registry."""
    try:
        # Fixed arguments and `docker` from PATH, as release.sh runs it; `reference` is read out of the Dockerfile.
        out = subprocess.run(  # noqa: S603
            ['docker', 'buildx', 'imagetools', 'inspect', reference, '--format', '{{json .}}'],  # noqa: S607
            capture_output=True, text=True, check=True, timeout=120, stdin=subprocess.DEVNULL).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise BaseImageError(f'could not read {reference} from the registry ({exc}); '
                             'this gate needs Docker and the network, as the image build does') from exc
    data = json.loads(out)
    return {'digest': data['manifest']['digest'],
            'created': {platform: image.get('created') for platform, image in (data.get('image') or {}).items()
                        if image.get('created')}}


def main(argv=None, inspect=inspect_with_docker, now=None, dockerfile=DOCKERFILE):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--update', action='store_true', help='write the digest the tag points at into the Dockerfile')
    parser.add_argument('--allow-stale', metavar='REASON', help='pass although the pin is stale, and log why')
    args = parser.parse_args(argv)
    now = now or dt.datetime.now(dt.UTC)
    try:
        text = pathlib.Path(dockerfile).read_text(encoding='utf-8')
        image, digest = single_pin(text)
        current = inspect(image)['digest']
        if args.update:
            if current == f'sha256:{digest}':
                print(f'already on the current digest ({current[:23]}...)')
                return 0
            pathlib.Path(dockerfile).write_text(update(text, current), encoding='utf-8')
            print(f'{image}: sha256:{digest[:16]}... -> {current[:23]}...')
            return 0
        pinned_info = inspect(f'{image}@sha256:{digest}')['created']
        ok, lines = evaluate(text, current, pinned_info, now, args.allow_stale)
    except BaseImageError as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1
    print('\n'.join(lines))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
