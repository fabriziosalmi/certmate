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

    python scripts/theme_codemod.py                       # report (templates + first-party JS)
    python scripts/theme_codemod.py templates/base.html   # report, one file
    python scripts/theme_codemod.py --apply templates/base.html
    python scripts/theme_codemod.py --check               # CI gate: exit 1 if any pair remains

Two passes run per file: a boundary-aware literal pass that collapses adjacent
`LIGHT DARK` substrings in ANY context (class="...", className='...', JS string
concatenation, Alpine :class ternaries), and a set-based pass within class="..."
attributes that also handles non-adjacent pairs and reports the leftover tail.

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
    # Form-field fill (Phase 7): white in light, gray-700 in dark so inputs
    # read one step lighter than the card they sit on. Exact value match.
    ("bg-white", "dark:bg-gray-700", "bg-input"),
    # Recessed fill (Phase 8): gray-50 / gray-700. Exact value match.
    ("bg-gray-50", "dark:bg-gray-700", "bg-sunken"),
    # ── Hover state (Phase 8) ─────────────────────────────────────────
    # Exact-value hover tokens; minority hover shades (gray-50 fills,
    # gray-600 darks, mid-weight text hovers) are left literal to avoid
    # value shifts rather than normalised onto the nearest token.
    ("hover:bg-gray-100", "dark:hover:bg-gray-700", "hover:bg-hover"),
    ("hover:border-gray-300", "dark:hover:border-gray-500", "hover:border-border-strong"),
    ("hover:text-gray-900", "dark:hover:text-white", "hover:text-foreground"),
    # ── Text ──────────────────────────────────────────────────────────
    ("text-gray-900", "dark:text-white", "text-foreground"),
    ("text-gray-900", "dark:text-gray-100", "text-foreground"),
    ("text-gray-800", "dark:text-white", "text-foreground"),
    ("text-gray-500", "dark:text-gray-400", "text-muted"),
    ("text-gray-600", "dark:text-gray-400", "text-muted"),
    ("text-gray-600", "dark:text-gray-300", "text-muted"),
    # Label / mid-weight body text — its own token so the gray-700 weight is
    # preserved exactly (foreground would over-darken it). See THEME_MIGRATION.
    ("text-gray-700", "dark:text-gray-300", "text-label"),
    # ── Borders ───────────────────────────────────────────────────────
    ("border-gray-200", "dark:border-gray-700", "border-border"),
    ("border-gray-300", "dark:border-gray-600", "border-border"),
    ("border-gray-200", "dark:border-gray-800", "border-border"),
    ("border-gray-200", "dark:border-gray-600", "border-border"),
    ("border-gray-300", "dark:border-gray-500", "border-border"),
]


# ── Status callouts (Phase 6) ──────────────────────────────────────
# Generated hue x shade -> status-token pairs. The hue picks the state;
# the LIGHT shade picks the role (50/100 = surface, 200-400 = line,
# 600/700 = body fg, 800/900 = heading strong). Surface intensities and
# dark-alpha variants (/10../50) all normalise to one surface token,
# folding the 50-vs-100 / 700-vs-800 drift the inline callouts carried.
def _expand_status() -> list[tuple[str, str, str]]:
    hue_state = {
        "blue": "info",
        "green": "success", "emerald": "success",
        "yellow": "warning", "amber": "warning",
        "red": "danger", "rose": "danger",
    }
    out: list[tuple[str, str, str]] = []
    for hue, st in hue_state.items():
        for light in ("50", "100"):
            for alpha in ("", "/10", "/20", "/30", "/40", "/50"):
                out.append((f"bg-{hue}-{light}", f"dark:bg-{hue}-900{alpha}",
                            f"bg-{st}-surface"))
        for light in ("200", "300", "400"):
            for dark in ("600", "700", "800"):
                out.append((f"border-{hue}-{light}", f"dark:border-{hue}-{dark}",
                            f"border-{st}-line"))
        for light in ("600", "700"):
            for dark in ("300", "400"):
                out.append((f"text-{hue}-{light}", f"dark:text-{hue}-{dark}",
                            f"text-{st}-fg"))
        for light in ("800", "900"):
            for dark in ("100", "200", "300"):
                out.append((f"text-{hue}-{light}", f"dark:text-{hue}-{dark}",
                            f"text-{st}-strong"))
    return out


MAPPINGS += _expand_status()

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

# Boundary-aware patterns for the literal adjacent-pair pass. These catch
# "LIGHT DARK" as a literal substring in ANY context — class="...",
# className='...', JS string concatenation, Alpine :class ternaries — which the
# class-attribute pass alone misses (it only sees double-quoted class attrs).
# The lookbehind/lookahead stop it matching inside a larger token (e.g.
# hover:LIGHT) or an opacity-suffixed DARK (dark:...-400/50); \s+ spans the
# newline+indent used by multi-line class attributes.
_LITERAL_PAIRS = [
    (re.compile(r"(?<![\w:/-])" + re.escape(light) + r"\s+"
                + re.escape(dark) + r"(?![\w/-])"), token)
    for light, dark, token in MAPPINGS
]

# Dark-ONLY override pairs — no light counterpart, so they don't fit MAPPINGS
# (which keys on a light class being present). Form inputs historically carried
# `dark:bg-gray-700 dark:text-white` with NO light class, relying on inherited
# light-mode colors; the semantic equivalent is `bg-input text-foreground`
# (one class set covering both modes). Ratchet the canonical adjacent form here
# so the Phase-9 input migration can't silently regress. The boundary guards
# match _LITERAL_PAIRS: don't fire inside a larger token or on an opacity suffix.
_DARK_ONLY_PAIRS = [
    (re.compile(r"(?<![\w:/-])dark:bg-gray-700\s+dark:text-white(?![\w/-])"),
     "bg-input text-foreground"),
    # Card/label text that only overrode the dark side (`font-medium
    # dark:text-white`), relying on inherited gray-900 in light mode. The
    # foreground token is gray-900 / pure-white, so this collapses with ZERO
    # value shift while making the light colour explicit instead of inherited.
    (re.compile(r"(?<![\w:/-])font-medium\s+dark:text-white(?![\w/-])"),
     "font-medium text-foreground"),
]


def literal_pass(text: str) -> tuple[str, "Counter"]:
    """Collapse adjacent LIGHT+DARK (and dark-only) pairs in the raw text."""
    hits: Counter = Counter()
    for pat, token in _LITERAL_PAIRS + _DARK_ONLY_PAIRS:
        text, n = pat.subn(token, text)
        if n:
            hits[token] += n
    return text, hits


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

    # Pass 1: literal adjacent pairs, context-independent.
    work, lit_hits = literal_pass(text)
    file_hits.update(lit_hits)

    # Pass 2: set-based within class="..." — catches non-adjacent pairs and
    # reports the leftover dark: tail for review.
    def repl(m: re.Match) -> str:
        new_value, hits = transform(m.group(1))
        file_hits.update(hits)
        for d in ambiguous_darks(new_value):
            leftover[d] += 1
        return f'class="{new_value}"'

    work = CLASS_ATTR_RE.sub(repl, work)
    if apply and work != text:
        path.write_text(work, encoding="utf-8")
    return file_hits, leftover


_VENDORED = ("alpine.min.js", "redoc.standalone.js")


def collect(target: str) -> list[Path]:
    p = Path(target)
    if p.is_file():
        return [p]
    out: list[Path] = []
    for ext in ("*.html", "*.js"):
        for f in p.rglob(ext):
            if f.name.endswith(".min.js") or f.name in _VENDORED:
                continue
            out.append(f)
    return sorted(out)


def main(argv: list[str]) -> int:
    apply = "--apply" in argv
    check = "--check" in argv
    args = [a for a in argv if not a.startswith("--")]
    # Default scope spans templates + first-party JS so --check is a complete
    # regression gate, not just an HTML scan.
    targets = args or ["templates", "static/js"]

    files: list[Path] = []
    for t in targets:
        files.extend(collect(t))

    total_hits: Counter = Counter()
    total_leftover: Counter = Counter()
    # --check is a dry-run gate: never write.
    print(f"{'PAIRS':>6}  FILE")
    print("-" * 60)
    for f in files:
        hits, leftover = process(f, apply and not check)
        total_hits.update(hits)
        total_leftover.update(leftover)
        if sum(hits.values()):
            print(f"{sum(hits.values()):>6}  {f}")

    if check:
        total = sum(total_hits.values())
        if total:
            print(f"\nFAIL: {total} collapsible light+dark pair(s) found — run "
                  "'python scripts/theme_codemod.py --apply' and commit.")
            return 1
        print("\nOK: no collapsible light+dark pairs remain.")
        return 0

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
