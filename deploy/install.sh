#!/bin/sh
# CertMate bare-metal installer (systemd). Debian, Ubuntu, Fedora, RHEL,
# Rocky and Alma Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/fabriziosalmi/certmate/main/deploy/install.sh | sudo sh
#
# Options (after `sh -s --` when piped):
#   --version X.Y.Z   install that release instead of the latest one
#   --source DIR      install from a local checkout instead of a release
#                     (development and testing)
#
# Run it again to upgrade: the code and its virtualenv are replaced, while
# the certificates, data, backups, logs and /etc/certmate/certmate.env stay.
#
# Python: CertMate is built and tested on Python 3.12, which Debian 12 and
# RHEL 9 do not ship. The installer uses uv to fetch a standalone Python 3.12
# into /opt/certmate, so the system Python is never touched and every
# distribution runs the same interpreter. Dependencies come from the same
# requirements.lock the container image is built from.
set -eu

REPO="fabriziosalmi/certmate"
PREFIX="/opt/certmate"
ENV_FILE="/etc/certmate/certmate.env"
UNIT="/etc/systemd/system/certmate.service"
UV_VERSION="0.12.21"
PYTHON_VERSION="3.12"
# Everything under PREFIX that belongs to the installation rather than to a
# release. An upgrade deletes the rest and unpacks the new release in its place.
STATE_DIRS="certificates data backups logs letsencrypt"
TOOL_DIRS="venv .uv .python"

version=""
source_dir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version) version="${2:?--version needs X.Y.Z}"; shift 2 ;;
    --source) source_dir="${2:?--source needs a directory}"; shift 2 ;;
    -h|--help) echo "usage: install.sh [--version X.Y.Z] [--source DIR]"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

say() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"

# --- system packages ---------------------------------------------------------
# Only what the installer itself needs. Python comes from uv, and every
# Python dependency ships as a wheel.
if command -v apt-get >/dev/null 2>&1; then
  say "Installing curl, tar and openssl (apt)"
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates tar gzip openssl >/dev/null
elif command -v dnf >/dev/null 2>&1; then
  say "Installing curl, tar and openssl (dnf)"
  dnf install -y -q curl ca-certificates tar gzip openssl >/dev/null
else
  die "unsupported distribution: needs apt-get or dnf"
fi

# --- the code ------------------------------------------------------------------
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [ -n "$source_dir" ]; then
  [ -f "$source_dir/app.py" ] || die "$source_dir is not a CertMate checkout"
  say "Using the checkout at $source_dir"
  src="$source_dir"
  version="$(sed -n "s/^__version__ = '\(.*\)'/\1/p" "$source_dir/modules/__init__.py")"
else
  if [ -z "$version" ]; then
    version="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
      | sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -n 1)"
    [ -n "$version" ] || die "could not find the latest release; pass --version X.Y.Z"
  fi
  say "Downloading CertMate $version"
  curl -fsSL "https://github.com/$REPO/archive/refs/tags/v$version.tar.gz" -o "$work/src.tar.gz" \
    || die "release v$version not found"
  mkdir "$work/src"
  tar -xzf "$work/src.tar.gz" -C "$work/src" --strip-components=1
  src="$work/src"
fi

if ! id certmate >/dev/null 2>&1; then
  say "Creating the certmate system user"
  nologin="$(command -v nologin || echo /usr/sbin/nologin)"
  useradd --system --home-dir "$PREFIX" --no-create-home --shell "$nologin" certmate
fi

mkdir -p "$PREFIX"
if systemctl is-active --quiet certmate 2>/dev/null; then
  say "Stopping the running service for the upgrade"
  systemctl stop certmate
fi

# Replace the release, keep the installation. `find` lists what is directly
# under PREFIX; anything named in STATE_DIRS or TOOL_DIRS survives.
keep_args=""
for d in $STATE_DIRS $TOOL_DIRS; do keep_args="$keep_args ! -name $d"; done
# shellcheck disable=SC2086
find "$PREFIX" -mindepth 1 -maxdepth 1 $keep_args -exec rm -rf {} +
# Excludes are anchored with ./ : a bare `--exclude=data` would also drop any
# directory named data anywhere inside the code.
(cd "$src" && tar -cf - --exclude=./.git --exclude=./node_modules --exclude=./.venv \
  --exclude=./certificates --exclude=./data --exclude=./backups --exclude=./logs \
  --exclude=./letsencrypt .) | (cd "$PREFIX" && tar -xf -)
chown -R root:root "$PREFIX"
chmod -R go-w "$PREFIX"

for d in $STATE_DIRS; do
  mkdir -p "$PREFIX/$d"
  chown certmate:certmate "$PREFIX/$d"
  chmod 750 "$PREFIX/$d"
done

# --- Python 3.12 and the dependencies -------------------------------------------
export UV_INSTALL_DIR="$PREFIX/.uv/bin"
export UV_PYTHON_INSTALL_DIR="$PREFIX/.python"
export UV_NO_MODIFY_PATH=1
export UV_CACHE_DIR="$work/uv-cache"
if [ "$("$UV_INSTALL_DIR/uv" --version 2>/dev/null | awk '{print $2}')" != "$UV_VERSION" ]; then
  say "Installing uv $UV_VERSION"
  curl -fsSL "https://astral.sh/uv/$UV_VERSION/install.sh" | sh >/dev/null
fi
uv="$UV_INSTALL_DIR/uv"

say "Installing Python $PYTHON_VERSION and the pinned dependencies"
"$uv" python install --quiet "$PYTHON_VERSION"
if [ ! -x "$PREFIX/venv/bin/python" ] \
   || ! "$PREFIX/venv/bin/python" -c "import sys; sys.exit(sys.version_info[:2] != (3, 12))"; then
  rm -rf "$PREFIX/venv"
  "$uv" venv --quiet --python "$PYTHON_VERSION" "$PREFIX/venv"
fi
# `sync`, not `install`: the virtualenv ends up holding exactly the lock, so
# a package dropped between releases is removed on upgrade.
"$uv" pip sync --quiet --python "$PREFIX/venv/bin/python" "$PREFIX/requirements.lock"
"$PREFIX/venv/bin/certbot" --version >/dev/null 2>&1 \
  || die "certbot does not start in the new virtualenv"
chown -R root:root "$PREFIX/venv" "$PREFIX/.uv" "$PREFIX/.python"
chmod -R go-w "$PREFIX/venv" "$PREFIX/.python"

# --- configuration ----------------------------------------------------------------
if [ ! -f "$ENV_FILE" ]; then
  say "Writing $ENV_FILE with generated secrets"
  mkdir -p "$(dirname "$ENV_FILE")"
  umask 027
  cat > "$ENV_FILE" <<EOF
# CertMate configuration, read by certmate.service.
# Generated by deploy/install.sh on $(date -u +%Y-%m-%d). Keep a copy: without
# CERTMATE_BACKUP_PASSPHRASE a backup cannot restore this instance.
API_BEARER_TOKEN=$(openssl rand -hex 32)
SECRET_KEY=$(openssl rand -hex 32)
CERTMATE_BACKUP_PASSPHRASE=$(openssl rand -hex 32)
# Where the service listens. Loopback by default: put a reverse proxy in front
# (and set BEHIND_PROXY=true), or use 0.0.0.0:8000 to listen on every interface.
CERTMATE_BIND=127.0.0.1:8000
BEHIND_PROXY=false
# Optional: CLOUDFLARE_TOKEN=... bootstraps a Cloudflare DNS account on first start.
EOF
  chown root:certmate "$ENV_FILE"
  chmod 640 "$ENV_FILE"
  umask 022
else
  say "Keeping the existing $ENV_FILE"
fi

say "Installing the systemd unit"
install -m 644 "$PREFIX/certmate.service" "$UNIT"
systemctl daemon-reload
systemctl enable --quiet certmate
systemctl restart certmate

bind="$(sed -n 's/^CERTMATE_BIND=//p' "$ENV_FILE" | tail -n 1)"
bind="${bind:-127.0.0.1:8000}"
probe="http://127.0.0.1:${bind##*:}/health"
say "Waiting for CertMate to answer on $probe"
i=0
until curl -fsS "$probe" >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    journalctl -u certmate -n 30 --no-pager >&2 || true
    die "CertMate did not become healthy; the journal is above"
  fi
  sleep 2
done

cat <<EOF

CertMate $version is running (systemctl status certmate).

  Listening on:  $bind
  Configuration: $ENV_FILE
  Data:          $PREFIX/{certificates,data,backups}

Open http://$bind (or your reverse proxy). The first page creates the
administrator account and asks for the API_BEARER_TOKEN stored in:

  sudo grep API_BEARER_TOKEN $ENV_FILE

Upgrade later by running this installer again.
EOF
