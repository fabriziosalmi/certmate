#!/usr/bin/env bash
#
# Regenerate the resolved dependency lockfiles, with uv.
#
# Run this after changing any pin in requirements.txt or requirements-minimal.txt
# — including a Dependabot bump. `scripts/lockfile.py check` runs in the unit
# suite and in the image build, so forgetting is a failing check rather than a
# security patch that quietly does not ship.
#
# uv resolves for each published platform (linux x86_64 and aarch64, glibc
# wheels) and for the Python the Dockerfile's builder runs, read from the
# Dockerfile rather than repeated here. It needs no Docker and no emulation, and
# takes about a second a file where the pip-in-the-base-image version took
# minutes. Measured against the lock this replaced: the same 123 packages for
# both architectures.
#
# The existing lock is handed to uv as its output file, and uv treats the pins
# already in that file as preferences. A regeneration therefore moves what the
# change under review needs moved (the bumped pin, and whatever depends on it)
# and nothing else. The pip-based version re-resolved everything and moved
# transitive pins the change had nothing to do with (#1076 had four).
#
# Both platforms are resolved and compared. One lockfile is only correct while
# they agree; the moment they stop agreeing this refuses to write rather than
# silently pick the one it happened to run first.
#
# pip remains the judge of what pip installs: the image build runs `pip install
# -r` on the lock for both architectures, and CI resolves every requirements
# file with pip for both. A lock uv wrote and pip cannot install fails there.
#
# Needs uv (https://docs.astral.sh/uv/): `pip install uv` or `brew install uv`.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v uv >/dev/null 2>&1; then
    echo "uv is required (https://docs.astral.sh/uv/): pip install uv, or brew install uv" >&2
    exit 1
fi

PYTHON_VERSION="$(sed -n 's/^FROM python:\([0-9][0-9]*\.[0-9][0-9]*\)[^ ]* AS builder$/\1/p' Dockerfile | head -1)"
if [ -z "$PYTHON_VERSION" ]; then
    echo "could not read the builder's Python version out of the Dockerfile" >&2
    exit 1
fi

# The platform tag CI resolves with (ci.yml, "Resolve the optional requirements
# for both published architectures"); the glibc of the base image is newer, and
# resolving for 2_28 and for 2_40 gave the same set.
PLATFORMS="x86_64-manylinux_2_28 aarch64-manylinux_2_28"

echo "uv:     $(uv --version)"
echo "python: $PYTHON_VERSION"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

for req in requirements.txt requirements-minimal.txt; do
    lock="${req%.txt}.lock"
    echo
    echo "=== $req -> $lock ==="

    for platform in $PLATFORMS; do
        echo "  resolving for $platform"
        # The current lock is the starting point: its pins are uv's preferences.
        cp "$lock" "$WORK/$platform.txt"
        uv pip compile "$req" --python-version "$PYTHON_VERSION" --python-platform "$platform" \
            --no-header --no-annotate --quiet --output-file "$WORK/$platform.txt"
        # Only the pins, sorted, for the comparison.
        sed 's/ *#.*//' "$WORK/$platform.txt" | grep -E '^[A-Za-z0-9._-]+==' | sort > "$WORK/$platform.pins"
    done

    first="$(echo "$PLATFORMS" | cut -d' ' -f1)"
    for platform in $PLATFORMS; do
        if ! diff -u "$WORK/$first.pins" "$WORK/$platform.pins" > "$WORK/skew.diff"; then
            echo "::error::$req resolves differently on the two published architectures." >&2
            echo "One lockfile can no longer speak for both. The difference:" >&2
            cat "$WORK/skew.diff" >&2
            exit 1
        fi
    done
    echo "  both architectures resolve identically"

    python3 scripts/lockfile.py write "$req" "$WORK/$first.pins" "$lock"
done

echo
python3 scripts/lockfile.py check \
    requirements.txt:requirements.lock \
    requirements-minimal.txt:requirements-minimal.lock
