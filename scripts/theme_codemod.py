#!/usr/bin/env python3
"""Theme-token codemod for the light/dark migration (docs/THEME_MIGRATION.md).

Collapses the recurring `light + dark:` Tailwind color pairs that are
duplicated across the templates into the single var-backed semantic tokens
defined in input.css / tailwind.config.js:

    bg-white  dark:bg-gray-800   ->  bg-surface
    text-gray-900 dark:text-white ->  text-foreground
    border-gray-200 dark:border-gray-700 -> border-border
    ... (see MAPPINGS below)

It parses every `class="..."` attribute, treats the classes as a set (the two
halves of a pair need not be adjacent), and where both halves of a known pair
are present, removes them and inserts the token.

Default mode is a DRY-RUN report:
  * how many pairs would collapse, per file and per mapping;
  * the "long tail" of dark: color variants that match no known pair and so
    need a human decision (the ambiguity report).

Run `--apply` to rewrite files in place. Intended to be run one phase / one
file-glob at a time, never all at once:

    python scripts/theme_codemod.py                       # report, all templates
    python scripts/theme_codemod.py templates/base.html   # report, one file
    python scripts/theme_codemod.py --apply templates/base.html

After --apply, always: rebuild CSS (npm run css:build), diff against the
visual baseline, review the residual dark: variants the tool left untouched.
"""
from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

# Canonical pair table. Each entry: (light_class, dark_class, token).
# Order is not significant — pairs are matched against a set of classes.
# Only unambiguous, high-frequency pairs live here; anything not listed is
# surfaced in the ambiguity report for manual review rather than guessed.
MAPPINGS: list[tuple[str, str, str]] = [
    # ── Surfaces ──────────────────────────────────────────────────────
    ("bg-surface-light", "dark:bg-surface-dark", "bg-background"),  # page body
    ("bg-white", "dark:bg-gray-800", "bg-surface"),
    ("bg-white", "dark:bg-gray-900", "bg-surface"),
    ("bg-white", "dark:bg-surface-card", "bg-surface"),
    ("bg-gray-50", "dark:bg-gray-900", "bg-background"),
    ("bg-gray-50", "dark:bg-surface-dark", "bg-background"),
    ("bg-gray-100", "dark:bg-gray-800", "bg-surface-2"),
    ("bg-gray-100", "dark:bg-gray-700", "bg-surface-2"),
    # ── Text ──────────────────────────────────────────────────────────
    ("text-gray-900", "dark:text-white", "text-foreground"),
    ("text-gray-900", "dark:text-gray-100", "text-foreground"),
    ("text-gray-800", "dark:text-white", "text-foreground"),
    ("text-gray-500", "dark:text-gray-400", "text-muted"),
    ("text-gray-600", "dark:text-gray-400", "text-muted"),
    ("text-gray-600", "dark:text-gray-300", "text-muted"),
    # ── Borders ───────────────────────────────────────────────────────
    ("border-gray-200", "dark:border-gray-700", "border-border"),
    ("border-gray-300", "dark:border-gray-600", "border-border"),
    ("border-gray-200", "dark:border-gray-800", "border-border"),
    ("border-gray-200", "dark:border-gray-600", "border-border"),
    ("border-gray-300", "dark:border-gray-500", "border-border"),
]

# Classes that are deliberately NOT auto-mapped (status colors carry meaning,
# variant-prefixed colors like hover:/focus: need their own pairs). They are
# excluded from the "ambiguous" tally so the report stays focused on the plain
# base-color dark: variants that a token could replace.
_VARIANT_PREFIXES = ("hover:", "focus:", "group-hover:", "focus-within:",
                      "active:", "disabled:", "peer-")
_STATUS_RE = re.compile(
    r"-(red|green|blue|yellow|amber|emerald|rose|indigo|purple|orange|teal|cyan)-")

CLASS_ATTR_RE = re.compile(r'class="([^"]*)"')
DARK_COLOR_RE = re.compile(
    r"^dark:(bg|text|border|ring|divide|placeholder|from|to|via)-"
    r"(gray|slate|zinc|neutral|white|black)")


def transform(class_value: str) -> tuple[str, Counter]:
    """Return (new_class_value, Counter of token->hits) for one class attr."""
    classes = class_value.split()
    present = set(classes)
    hits: Counter = Counter()
    consumed: set[str] = set()
    inserts: list[str] = []

    for light, dark, token in MAPPINGS:
        if light in present and dark in present:
            consumed.update((light, dark))
            if token not in inserts and token not in present:
                inserts.append(token)
            hits[token] += 1

    if not consumed:
        return class_value, hits

    # Rebuild preserving original order; drop consumed, splice token where the
    # first consumed class was.
    out: list[str] = []
    spliced = False
    for c in classes:
        if c in consumed:
            if not spliced:
                out.extend(inserts)
                spliced = True
            continue
        out.append(c)
    return " ".join(out), hits


def ambiguous_darks(class_value: str) -> list[str]:
    """Plain base-color dark: variants that no mapping consumed."""
    out = []
    for c in class_value.split():
        if not c.startswith("dark:"):
            continue
        if any(c.startswith("dark:" + p) for p in _VARIANT_PREFIXES):
            continue
        if _STATUS_RE.search(c):
            continue
        if DARK_COLOR_RE.match(c):
            out.append(c)
    return out


def process(path: Path, apply: bool) -> tuple[Counter, Counter]:
    text = path.read_text(encoding="utf-8")
    file_hits: Counter = Counter()
    leftover: Counter = Counter()

    def repl(m: re.Match) -> str:
        original = m.group(1)
        new_value, hits = transform(original)
        file_hits.update(hits)
        # After the (hypothetical) transform, what dark: variants remain?
        for d in ambiguous_darks(new_value):
            leftover[d] += 1
        return f'class="{new_value}"' if apply else m.group(0)

    new_text = CLASS_ATTR_RE.sub(repl, text)
    if apply and new_text != text:
        path.write_text(new_text, encoding="utf-8")
    return file_hits, leftover


def main(argv: list[str]) -> int:
    apply = "--apply" in argv
    args = [a for a in argv if not a.startswith("--")]
    targets = args or ["templates"]

    files: list[Path] = []
    for t in targets:
        p = Path(t)
        files.extend(sorted(p.rglob("*.html")) if p.is_dir() else [p])

    total_hits: Counter = Counter()
    total_leftover: Counter = Counter()
    print(f"{'PAIRS':>6}  FILE")
    print("-" * 60)
    for f in files:
        hits, leftover = process(f, apply)
        total_hits.update(hits)
        total_leftover.update(leftover)
        if sum(hits.values()):
            print(f"{sum(hits.values()):>6}  {f}")

    print("\n=== collapsible pairs by token "
          f"({'APPLIED' if apply else 'dry-run'}) ===")
    for token, n in total_hits.most_common():
        print(f"{n:>6}  -> {token}")
    print(f"{sum(total_hits.values()):>6}  TOTAL pairs")

    print("\n=== ambiguity report: unmapped base-color dark: variants ===")
    print("(no known pair — decide a token or add a MAPPINGS entry)")
    for cls, n in total_leftover.most_common(40):
        print(f"{n:>6}  {cls}")
    print(f"{len(total_leftover):>6}  distinct unmapped variants, "
          f"{sum(total_leftover.values())} occurrences")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
