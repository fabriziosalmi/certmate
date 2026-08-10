"""`.env.example` is copied verbatim by every operator. It must be true.

The guard this replaces named two variables — `HOST` and `FLASK_DEBUG` — and
looked for them in two markdown files. It never looked at `.env.example`, the
one file the installation docs in all five languages tell you to copy. So the
template kept advertising, long after #429:

  * `FLASK_DEBUG=False` — read by nothing;
  * `HOST=0.0.0.0` — read by nothing, and it reads as a binding control. An
    operator setting `HOST=127.0.0.1` believed they had bound to loopback while
    the service listened on every interface.

An unreferenced second copy, `.env.template`, was worse still: `LOG_LEVEL`
(the app reads `CERTMATE_LOG_LEVEL`), `CLOUDFLARE_API_TOKEN` (the app reads
`CLOUDFLARE_TOKEN`, so following that file produced a bootstrap that silently
saw no token at all), and ten commented variables promising environment
configuration for Route53, Azure, Google Cloud DNS and PowerDNS — none of which
has ever existed. It was deleted; the docs all point here.

Naming the offenders one at a time is how the previous guard ended up shorter
than the defect. This one asks the general question instead: does anything read
this?
"""
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
ENV_EXAMPLE = REPO_ROOT / ".env.example"

# Where a variable can legitimately be consumed: the application, and the
# container plumbing that turns an environment into a running process.
_SOURCE_GLOBS = ("modules/**/*.py", "app.py", "Dockerfile", "docker-compose*.yml",
                 "docker-entrypoint.sh", "entrypoint.sh", "gunicorn*.py",
                 "scripts/*.sh")


def _sources():
    found = []
    for pattern in _SOURCE_GLOBS:
        found.extend(REPO_ROOT.glob(pattern))
    return [p for p in found if p.is_file()]


def _blobs():
    return {p: p.read_text(encoding="utf-8", errors="replace") for p in _sources()}


def _readers(name, blobs):
    """Files that read `name` — matched exactly, never as a substring.

    A substring check would report `HOST` as read because `HOSTNAME` appears
    somewhere, and `LOG_LEVEL` as read because of `CERTMATE_LOG_LEVEL`. Both
    are dead. That is the mistake this function exists to not make.
    """
    patterns = [
        rf"""getenv\(\s*['"]{name}['"]""",
        rf"""environ\.get\(\s*['"]{name}['"]""",
        rf"""environ\[\s*['"]{name}['"]""",
        rf"""\$\{{{name}[}}:]""",
        rf"""\${name}\b""",
        rf"""^\s*(ENV|ARG)\s+{name}\b""",
    ]
    hits = []
    for path, blob in blobs.items():
        if any(re.search(p, blob, re.M) for p in patterns):
            hits.append(str(path.relative_to(REPO_ROOT)))
    return hits


def _declared():
    """Every variable the template offers, commented-out ones included.

    A commented variable is still an offer — it is what someone uncomments when
    they want the feature. `.env.template` promised ten provider variables that
    way, all fictional.
    """
    out = []
    for number, line in enumerate(
            ENV_EXAMPLE.read_text(encoding="utf-8").splitlines(), 1):
        match = re.match(r"^\s*#?\s*([A-Z][A-Z0-9_]*)=", line)
        if match:
            out.append((match.group(1), number, line.strip()))
    return out


def test_the_template_declares_something():
    """A parametrised test over an empty list is a green build over nothing."""
    assert len(_declared()) >= 5, (
        f".env.example declares {len(_declared())} variables — the parser below "
        f"is not seeing the file's format, so every check would vacuously pass."
    )


@pytest.mark.parametrize("name,number,line", _declared(),
                         ids=[d[0] for d in _declared()])
def test_every_variable_in_the_template_is_read_by_something(name, number, line):
    blobs = _blobs()
    assert _readers(name, blobs), (
        f".env.example:{number} offers `{line}`, which nothing in the "
        f"application reads. Either wire it up or delete the line: a template "
        f"that lists settings with no effect is how `HOST` spent months "
        f"looking like a way to bind to loopback."
    )


def test_the_second_template_stays_deleted():
    """`.env.template` was an unreferenced copy that had drifted into fiction."""
    assert not (REPO_ROOT / ".env.template").exists(), (
        ".env.template is back. It was deleted because nothing referenced it "
        "and it had drifted: CLOUDFLARE_API_TOKEN instead of CLOUDFLARE_TOKEN, "
        "so anyone following it configured a token CertMate never read. One "
        "template, the one the installation docs name."
    )


def test_the_docs_point_at_the_template_that_exists():
    """Five installation guides tell you to copy a file. It must be there."""
    referencing = [
        p for p in REPO_ROOT.rglob("*.md")
        if not any(part in p.parts for part in
                   (".venv", "node_modules", ".git", "scratch", ".claude", "backups"))
        and ".env.example" in p.read_text(encoding="utf-8", errors="replace")
    ]
    assert referencing, "no documentation points at .env.example any more"
    assert ENV_EXAMPLE.exists(), (
        f"{len(referencing)} documents tell operators to copy .env.example, "
        f"which does not exist."
    )


def test_no_documented_variable_contradicts_the_template():
    """The one that bit: a doc naming a variable the template does not have.

    `CLOUDFLARE_API_TOKEN` lived in a template while `CLOUDFLARE_TOKEN` lived in
    the code. Both look right in isolation.
    """
    template = ENV_EXAMPLE.read_text(encoding="utf-8")
    blobs = _blobs()
    for name in ("CLOUDFLARE_TOKEN", "API_BEARER_TOKEN", "SECRET_KEY", "PORT"):
        assert re.search(rf"^\s*#?\s*{name}=", template, re.M), (
            f"{name} is read by {_readers(name, blobs)} but is not offered in "
            f".env.example, so nobody copying the template will set it."
        )
