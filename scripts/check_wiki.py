#!/usr/bin/env python3
"""Check the GitHub wiki against the facts this repository holds.

The wiki is a separate git repository, so nothing in CI has ever looked at it.
It has now drifted three times, and each time in the same way: it keeps a
second copy of something the repo has since corrected, and nobody notices until
someone reads it. The last sweep found four claims that were already fixed in
`docs/` — Python 3.9, a DigiCert host that stopped resolving in February, an
endpoint that returns 404, and an environment variable read by nothing.

This reads the truth from the repository — `app.py`, the `Dockerfile`, the
requirements files — rather than from a list maintained here, so it cannot say
"correct" about a number that has moved on.

    scripts/check_wiki.py [path-to-wiki-clone]

Exits non-zero with one line per finding. Intended for the weekly CI job, and
for anyone about to edit the wiki.
"""
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Hosts that no longer resolve, with what replaced them.
RETIRED_HOSTS = {
    "acme.digicert.com":
        "retired by DigiCert on 2026-02-24; use "
        "https://one.digicert.com/mpki/api/v1/acme/v2/directory (regional)",
}

# Paths the documentation has advertised that no route serves.
PHANTOM_PATHS = {
    r"/\{domain\}/tls":
        "no such route; use /api/certificates/{domain}/download",
}

# Environment variables nothing reads.
DEAD_VARIABLES = ("HOST", "FLASK_DEBUG")


def _truth():
    """The facts, read from the code rather than restated here."""
    app = (REPO_ROOT / "app.py").read_text(encoding="utf-8")
    port = re.search(r"--port['\"].*?default=(\d+)", app)
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    python = re.search(r"^FROM python:(\d+\.\d+)", dockerfile, re.M)
    if not port or not python:
        raise SystemExit("cannot read the port or the Python version from the "
                         "repository — this script is checking nothing")

    requirements = "".join(
        p.read_text(encoding="utf-8") for p in REPO_ROOT.glob("requirements*.txt"))
    pins = {
        re.sub(r"[-_.]+", "-", name).lower(): version
        for name, version in re.findall(r"^([A-Za-z0-9_.-]+)==([\w.]+)",
                                        requirements, re.M)
    }
    if len(pins) < 20:
        raise SystemExit(f"only {len(pins)} pins parsed — the requirements "
                         f"format changed and the pin check would pass over "
                         f"nothing")
    return port.group(1), python.group(1), pins


def check(wiki):
    port, python_version, pins = _truth()
    pages = sorted(wiki.glob("*.md"))
    if not pages:
        raise SystemExit(f"no wiki pages found under {wiki}")

    findings = []
    for page in pages:
        fenced = False
        for number, line in enumerate(
                page.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if line.lstrip().startswith("```"):
                fenced = not fenced
                continue
            where = f"{page.name}:{number}"

            for match in re.finditer(
                    r"https?://(?:localhost|127\.0\.0\.1):(\d{2,5})", line):
                if match.group(1) != port:
                    findings.append(
                        f"{where}: {match.group(0)} — the app listens on {port}")

            # Only inside fences: prose may legitimately name an old version
            # while explaining why it moved.
            if fenced:
                for match in re.finditer(r"\b([A-Za-z][\w.-]*)==([\w.]+)", line):
                    shipped = pins.get(re.sub(r"[-_.]+", "-", match.group(1)).lower())
                    if shipped and shipped != match.group(2):
                        findings.append(
                            f"{where}: {match.group(0)} — we ship {shipped}")

            for match in re.finditer(r"[Pp]ython[- ](\d+\.\d+)", line):
                # A version stated about a third-party package is not a claim
                # about what CertMate runs on.
                if re.search(r"`[\w.-]*(?:certbot|dns)[\w.-]*`", line):
                    continue
                if match.group(1) != python_version:
                    findings.append(
                        f"{where}: Python {match.group(1)} — the image is built "
                        f"on {python_version}")

            for variable in DEAD_VARIABLES:
                if re.search(rf"\b{variable}\s*=", line):
                    findings.append(f"{where}: {variable} is read by nothing")

            for host, reason in RETIRED_HOSTS.items():
                if host in line:
                    findings.append(f"{where}: {host} — {reason}")

            for pattern, reason in PHANTOM_PATHS.items():
                if re.search(pattern, line):
                    findings.append(f"{where}: phantom endpoint — {reason}")

            for match in re.finditer(r"hub\.docker\.com/r/([\w.-]+/[\w.-]+)", line):
                if match.group(1) != "fabriziosalmi/certmate":
                    findings.append(
                        f"{where}: {match.group(1)} — we publish "
                        f"fabriziosalmi/certmate")

    return pages, findings


def main():
    wiki = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "wiki")
    pages, findings = check(wiki)
    print(f"checked {len(pages)} wiki pages against the repository")
    if not findings:
        print("no drift")
        return 0
    print(f"{len(findings)} finding(s):")
    for finding in findings:
        print(f"  {finding}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
