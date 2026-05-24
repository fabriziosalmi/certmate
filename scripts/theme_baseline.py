#!/usr/bin/env python3
"""Capture a light+dark screenshot baseline for the theme migration.

Part of docs/THEME_MIGRATION.md Phase 0. Builds the Docker image with an
isolated, fresh data dir (no real settings/secrets — satisfies the
"never run against real data" rule), boots it, bootstraps a throwaway admin,
and screenshots every real UI page in both themes. Re-run after each migration
phase and diff the images to catch unintended visual drift.

The dead routes /certificates and /audit are intentionally excluded: their
templates (certificates.html, audit.html) do not exist and the routes 500.

Setup:
    pip install playwright requests
    playwright install chromium

Run:
    python scripts/theme_baseline.py                 # build, boot, capture
    CERTMATE_SKIP_BUILD=1 python scripts/theme_baseline.py   # reuse image
    python scripts/theme_baseline.py --out theme-baseline/after-phase1

Output: <out>/<page>-<light|dark>.png  (default out dir: theme-baseline/)
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent
IMAGE = os.environ.get("CERTMATE_IMAGE", "certmate:baseline")
CONTAINER = "certmate-theme-baseline"
PORT = int(os.environ.get("CERTMATE_BASELINE_PORT", "18889"))
BASE_URL = f"http://localhost:{PORT}"
ADMIN = {"username": "admin", "password": "Baseline123!", "role": "admin"}
VIEWPORT = {"width": 1440, "height": 900}

# Pages visible before any user exists (/ renders setup.html in this state).
FRESH_PAGES = [("setup", "/"), ("login", "/login")]
# Pages reachable once authenticated.
AUTH_PAGES = [
    ("index", "/"),
    ("settings", "/settings"),
    ("help", "/help"),
    ("activity", "/activity"),
    ("redoc", "/redoc"),
]


def docker(*args, check=True):
    return subprocess.run(["docker", *args], check=check,
                          capture_output=True, text=True, timeout=600)


def wait_healthy(timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if requests.get(f"{BASE_URL}/health", timeout=5).status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(1)
    raise TimeoutError(f"container not healthy after {timeout}s")


def start_container():
    if os.environ.get("CERTMATE_SKIP_BUILD") != "1":
        print(f"[baseline] building {IMAGE} ...")
        docker("build", "-t", IMAGE, str(PROJECT_ROOT))
    docker("rm", "-f", CONTAINER, check=False)
    # No volume mounts: the container gets a fresh, ephemeral data dir, so the
    # app writes a default settings.json and we never touch real data.
    print(f"[baseline] starting {CONTAINER} on :{PORT} ...")
    docker("run", "-d", "--name", CONTAINER, "-p", f"{PORT}:8000", IMAGE)
    wait_healthy()
    print("[baseline] healthy.")


def stop_container():
    docker("rm", "-f", CONTAINER, check=False)
    print("[baseline] container removed.")


def bootstrap_admin() -> str | None:
    """Create admin, enable auth, log in, mark setup complete. Returns cookie."""
    h = {"Origin": BASE_URL, "Content-Type": "application/json"}
    requests.post(f"{BASE_URL}/api/web/settings/users", json=ADMIN, headers=h)
    requests.post(f"{BASE_URL}/api/auth/config",
                  json={"local_auth_enabled": True}, headers=h)
    login = requests.post(f"{BASE_URL}/api/auth/login",
                          json={k: ADMIN[k] for k in ("username", "password")},
                          headers=h)
    cookie = login.cookies.get("certmate_session")
    if cookie:
        s = requests.Session()
        s.headers.update(h)
        s.cookies.set("certmate_session", cookie)
        r = s.get(f"{BASE_URL}/api/web/settings", timeout=10)
        if r.status_code == 200:
            data = r.json()
            data["setup_completed"] = True
            s.post(f"{BASE_URL}/api/web/settings", json=data, timeout=10)
    return cookie


def capture(pw, out: Path, cookie: str | None, pages, modes=("light", "dark")):
    browser = pw.chromium.launch(headless=True)
    try:
        for mode in modes:
            ctx = browser.new_context(viewport=VIEWPORT, ignore_https_errors=True)
            # Set the theme before any page script runs (base.html reads
            # localStorage 'theme' pre-paint), so there is no flash to capture.
            ctx.add_init_script(f"localStorage.setItem('theme', '{mode}');")
            if cookie:
                ctx.add_cookies([{"name": "certmate_session",
                                  "value": cookie, "url": BASE_URL}])
            page = ctx.new_page()
            for name, path in pages:
                try:
                    page.goto(f"{BASE_URL}{path}", wait_until="networkidle",
                              timeout=20000)
                except Exception:
                    page.goto(f"{BASE_URL}{path}", wait_until="load", timeout=20000)
                # The first-run wizard overlay intercepts the page; drop it.
                page.evaluate(
                    "() => { const w = document.getElementById('setupWizard');"
                    " if (w) w.remove(); }")
                page.wait_for_timeout(900)  # let Alpine.js settle
                dest = out / f"{name}-{mode}.png"
                page.screenshot(path=str(dest), full_page=True)
                print(f"[baseline] {dest.relative_to(PROJECT_ROOT)}")
            ctx.close()
    finally:
        browser.close()


def main(argv) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="theme-baseline",
                    help="output directory (default: theme-baseline/)")
    ap.add_argument("--keep", action="store_true",
                    help="leave the container running after capture")
    args = ap.parse_args(argv)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("playwright not installed. Run:\n"
              "  pip install playwright requests && playwright install chromium",
              file=sys.stderr)
        return 2

    out = (PROJECT_ROOT / args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    start_container()
    try:
        with sync_playwright() as pw:
            # Capture the no-users state (setup + login) before bootstrapping.
            capture(pw, out, None, FRESH_PAGES)
            cookie = bootstrap_admin()
            if not cookie:
                print("[baseline] WARNING: login failed; auth pages may redirect.",
                      file=sys.stderr)
            capture(pw, out, cookie, AUTH_PAGES)
    finally:
        if not args.keep:
            stop_container()

    print(f"\n[baseline] done — {len(list(out.glob('*.png')))} images in {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
