#!/usr/bin/env bash
#
# Regenerate the resolved dependency lockfiles.
#
# Run this after changing any pin in requirements.txt or requirements-minimal.txt
# — including a Dependabot bump. `scripts/lockfile.py check` runs in the unit
# suite and in the image build, so forgetting is a failing check rather than a
# security patch that quietly does not ship.
#
# The resolution happens inside the base image the project actually publishes
# from, at the digest the Dockerfile pins and with the pip version it pins, both
# read from the Dockerfile rather than repeated here. Resolving on the host
# instead would produce a lock for the host's Python and the host's platform,
# which is not what any image installs.
#
# Both published architectures are resolved and compared. One lockfile is only
# correct while they agree; the moment they stop agreeing this refuses to write
# rather than silently pick the architecture it happened to run on first.
#
# Requires Docker with binfmt/QEMU for the non-native architecture (Docker
# Desktop has it). Only metadata is downloaded — nothing is emulated at speed
# that matters, so the emulated pass is not much slower than the native one.
set -euo pipefail

cd "$(dirname "$0")/.."

BASE_IMAGE="$(sed -n 's/^FROM \(python:[^ ]*\) AS builder$/\1/p' Dockerfile | head -1)"
PIP_VERSION="$(sed -n 's/^ARG PIP_VERSION=\(.*\)$/\1/p' Dockerfile | head -1)"

if [ -z "$BASE_IMAGE" ] || [ -z "$PIP_VERSION" ]; then
    echo "could not read the base image or pip pin out of the Dockerfile" >&2
    exit 1
fi

echo "base image: $BASE_IMAGE"
echo "pip:        $PIP_VERSION"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

resolve() {
    # $1 = requirements file, $2 = platform, $3 = output report path
    docker run --rm --platform "$2" -v "$PWD:/w:ro" -w /w "$BASE_IMAGE" \
        sh -c "pip install --quiet 'pip==$PIP_VERSION' >/dev/null 2>&1 &&
               pip install --dry-run --no-cache-dir --ignore-installed --quiet \
                   --report /tmp/report.json -r '$1' >/dev/null &&
               cat /tmp/report.json" > "$3"
}

for req in requirements.txt requirements-minimal.txt; do
    lock="${req%.txt}.lock"
    echo
    echo "=== $req -> $lock ==="

    for platform in linux/amd64 linux/arm64; do
        slug="$(echo "$platform" | tr / -)"
        echo "  resolving for $platform"
        resolve "$req" "$platform" "$WORK/$slug.json"
        python3 - "$WORK/$slug.json" "$WORK/$slug.txt" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
lines = sorted(f"{i['metadata']['name'].lower()}=={i['metadata']['version']}"
               for i in report['install'])
open(sys.argv[2], 'w').write('\n'.join(lines) + '\n')
PY
    done

    if ! diff -u "$WORK/linux-amd64.txt" "$WORK/linux-arm64.txt" > "$WORK/skew.diff"; then
        echo "::error::$req resolves differently on the two published architectures." >&2
        echo "One lockfile can no longer speak for both. The difference:" >&2
        cat "$WORK/skew.diff" >&2
        exit 1
    fi
    echo "  both architectures resolve identically"

    python3 scripts/lockfile.py write "$req" "$WORK/linux-amd64.json" "$lock"
done

echo
python3 scripts/lockfile.py check \
    requirements.txt:requirements.lock \
    requirements-minimal.txt:requirements-minimal.lock
