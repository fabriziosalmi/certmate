#!/usr/bin/env python3
"""
Record a happy-path walkthrough of the CertMate UI.

Drives a fresh-ish CertMate instance via Playwright and emits:

  - docs/walkthrough.mp4               — single muted clip, ~40-50s, 1280x720
  - docs/walkthrough-{N}-{slug}.png    — one frame per logical step

The output is meant to live in the README as the visual hero shot
(replacing the December screenshot_1.png that no longer matches the
v2.5.x UI). Re-run after every UI-touching release.

Pre-requisites:
  - Container running at CERTMATE_URL (default http://127.0.0.1:18999)
  - An admin account with credentials in the env vars below
  - Local auth enabled OR setup wizard completed
  - `playwright install chromium` already run (one-off)

Usage:
    CERTMATE_URL=http://127.0.0.1:18999 \
    CERTMATE_USER=preview@local \
    CERTMATE_PASS=preview1234 \
    python scripts/record_walkthrough.py

Iteration model: the script is intentionally linear and step-based.
Each step is a small function with one screenshot at the end, so when
the UI changes the diff is localised to one step. Add or reorder
steps freely; the numbering in filenames comes from the step index.

The script does NOT issue a real certificate — the DNS credentials
are intentionally placeholder values so the create-cert form lands
on a validation error rather than hitting Let's Encrypt. That keeps
the recording deterministic and avoids rate-limit consumption.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

try:
    from playwright.sync_api import Page, sync_playwright
except ModuleNotFoundError:
    sys.stderr.write(
        "playwright is not installed in this venv. Run:\n"
        "    pip install playwright && playwright install chromium\n"
    )
    sys.exit(1)


URL = os.environ.get("CERTMATE_URL", "http://127.0.0.1:18999").rstrip("/")
USER = os.environ.get("CERTMATE_USER", "preview@local")
PASS = os.environ.get("CERTMATE_PASS", "preview1234")

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "docs"
VIDEO_OUT = OUT_DIR / "walkthrough.mp4"

# 720p — small file, sharp enough for README, big enough that nav text
# remains legible. Width matches the README's max content column.
VIEWPORT = {"width": 1280, "height": 720}

# Per-step pause budget. Playwright mouse moves are linear and fast;
# without a pause the cursor teleports between elements and the
# viewer can't follow. 800ms feels human without dragging.
HUMAN_PAUSE_MS = 800


def shot(page: Page, idx: int, slug: str) -> None:
    """Save a still frame at the end of a logical step."""
    out = OUT_DIR / f"walkthrough-{idx:02d}-{slug}.png"
    page.screenshot(path=str(out), full_page=False)
    print(f"  -> {out.relative_to(REPO_ROOT)}")


def pause(page: Page, ms: int = HUMAN_PAUSE_MS) -> None:
    page.wait_for_timeout(ms)


def step_01_login(page: Page) -> None:
    print("[01] login")
    page.goto(f"{URL}/login")
    page.locator("#username").fill(USER)
    pause(page, 400)
    page.locator("#password").fill(PASS)
    pause(page, 400)
    page.locator("#loginBtn").click()
    page.wait_for_url(lambda u: "/login" not in u, timeout=10_000)
    pause(page)
    shot(page, 1, "dashboard")


def step_02_open_create_form(page: Page) -> None:
    print("[02] open create-cert form")
    # Top-right Create New Certificate button (v2.5.1 single-row layout).
    page.locator("#toggleCreateForm").click()
    pause(page)
    shot(page, 2, "create-form")


def step_03_fill_domain(page: Page) -> None:
    print("[03] fill domain + SAN")
    page.locator("#domain").fill("demo.example.com")
    pause(page, 400)
    page.locator("#san_domains").fill("www.demo.example.com")
    pause(page)
    shot(page, 3, "create-form-filled")


def step_04_close_form_visit_settings(page: Page) -> None:
    print("[04] settings -> DNS tab")
    # Re-collapse the form so the dashboard returns to its compact state
    # in the next-but-one frame.
    page.locator("#toggleCreateForm").click()
    pause(page, 400)
    page.goto(f"{URL}/settings")
    page.wait_for_load_state("networkidle")
    pause(page)
    shot(page, 4, "settings-dns")


def step_05_settings_backup(page: Page) -> None:
    print("[05] settings -> backup tab")
    # The Backup tab is the rightmost; click it via the nav role.
    page.get_by_role("tab", name="Backup").click()
    pause(page)
    shot(page, 5, "settings-backup")


def step_06_help_page(page: Page) -> None:
    print("[06] help page (v2.5.1 single-row section nav)")
    page.goto(f"{URL}/help")
    page.wait_for_load_state("networkidle")
    pause(page)
    shot(page, 6, "help")


def step_07_report_issue_section(page: Page) -> None:
    print("[07] help -> Report an issue (diagnostics checklist)")
    # The section nav has an anchor jump to the new v2.5.1 block.
    page.locator('a[href="#report-issue"]').first.click()
    pause(page)
    shot(page, 7, "help-report-issue")


STEPS = [
    step_01_login,
    step_02_open_create_form,
    step_03_fill_domain,
    step_04_close_form_visit_settings,
    step_05_settings_backup,
    step_06_help_page,
    step_07_report_issue_section,
]


def main() -> int:
    OUT_DIR.mkdir(exist_ok=True)
    print(f"Recording walkthrough against {URL}")
    print(f"Output dir: {OUT_DIR}")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            viewport=VIEWPORT,
            record_video_dir=str(OUT_DIR),
            record_video_size=VIEWPORT,
        )
        page = context.new_page()

        try:
            for fn in STEPS:
                fn(page)
        finally:
            # Closing the context flushes the video to disk. Playwright
            # writes a .webm regardless of the requested extension; we
            # rename to .mp4 below for README compatibility — most
            # browsers' <video> tags accept both, but .mp4 is the safer
            # default. For real VP9/H.264 transcoding, pipe through ffmpeg.
            context.close()
            browser.close()

        # Find the generated video (Playwright names it with a uuid).
        videos = sorted(OUT_DIR.glob("*.webm"), key=lambda p: p.stat().st_mtime)
        if videos:
            latest = videos[-1]
            target = VIDEO_OUT.with_suffix(".webm")
            latest.rename(target)
            print(f"\nVideo: {target.relative_to(REPO_ROOT)}")
            print("To transcode to MP4 (H.264) for broader browser compat:")
            print(f"  ffmpeg -i {target.relative_to(REPO_ROOT)} -c:v libx264 -preset slow -crf 23 -an {VIDEO_OUT.relative_to(REPO_ROOT)}")
        else:
            print("\nNo video file was generated — check Playwright was started with record_video_dir.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
