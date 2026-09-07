"""The docs must not promise a topology the product refuses to run (#673).

CertMate is single-instance by design: APScheduler runs inside the web process
and gunicorn runs one worker, so a second replica is a second scheduler issuing
against the same certificate store. The Helm chart enforces this — it calls
`fail` at template time when `replicaCount != 1`.

The documentation said otherwise in two places, and the second was worse than
the issue reported. The README led with "easy scaling" and "high availability
deployments" while the constraint sat in a docker-compose YAML comment ~73% of
the way down a 2,700-line file. And `docs/architecture.md` carried a **High
Availability** section giving operational steps for multi-instance deployments —
shared storage, a load balancer with sticky sessions, rate-limit counters across
instances — replicated verbatim into all four translations. Following it
produces duplicate ACME orders and the CA's duplicate-certificate rate limit,
not availability.

Prose drifts back, so this pins the outcome rather than the wording: the
constraint is stated where a reader forms a first impression, and no document in
any language instructs anyone to run more than one.
"""
import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

ROOT = Path(__file__).resolve().parent.parent
ARCHITECTURE_DOCS = [
    ROOT / 'docs' / 'architecture.md',
    ROOT / 'docs' / 'it' / 'architecture.md',
    ROOT / 'docs' / 'de' / 'architecture.md',
    ROOT / 'docs' / 'fr' / 'architecture.md',
    ROOT / 'docs' / 'es' / 'architecture.md',
]

# How far into the README still counts as "where a reader forms their first
# impression". The constraint used to be at line ~1997 of ~2700.
FIRST_IMPRESSION_LINES = 150


def test_every_architecture_translation_is_present():
    """The translations are this project's recurring blind spot: a fix lands in
    the English file and four copies keep the old claim. Fail loudly if one is
    renamed or added, rather than silently checking four files out of five.
    """
    missing = [str(p.relative_to(ROOT)) for p in ARCHITECTURE_DOCS if not p.exists()]
    assert not missing, f'architecture docs missing: {missing}'

    found = sorted(p.name for p in (ROOT / 'docs').glob('*/architecture.md'))
    expected = sorted(p.name for p in ARCHITECTURE_DOCS[1:])
    assert found == expected, (
        f'a translated architecture doc appeared or vanished: {found} != '
        f'{expected}; add it to ARCHITECTURE_DOCS so it is checked too'
    )


def test_the_single_instance_constraint_is_stated_up_front():
    """Not buried at 73% of the way down, under headline claims that
    contradict it."""
    head = '\n'.join(
        (ROOT / 'README.md').read_text().splitlines()[:FIRST_IMPRESSION_LINES]
    ).lower()

    assert 'single instance' in head or 'single-instance' in head, (
        f'the README does not say CertMate is single-instance within its '
        f'first {FIRST_IMPRESSION_LINES} lines'
    )
    assert 'replica' in head, (
        'the first impression does not mention replicas, so a reader planning '
        'a Kubernetes deployment has no reason to look further'
    )


@pytest.mark.parametrize('claim', [
    'easy scaling',
    'high availability deployments',
])
def test_the_contradicting_readme_claims_are_gone(claim):
    """Named individually so a reintroduction says which sentence came back."""
    text = re.sub(r'\s+', ' ', (ROOT / 'README.md').read_text().lower())
    assert claim not in text, (
        f'README claims "{claim}", which the Helm chart refuses to render'
    )


@pytest.mark.parametrize('doc', ARCHITECTURE_DOCS, ids=lambda p: p.parent.name)
def test_no_architecture_doc_instructs_a_multi_instance_deployment(doc):
    """The operational recipe, in every language it was copied into.

    Matching on "sticky sessions" and its translations rather than on the words
    "high availability": a document may legitimately explain how to *achieve*
    availability, and the replacement text does. What must not come back is
    telling someone to put a load balancer in front of several CertMates.
    """
    # Whitespace-normalised, because these files are hard-wrapped at ~80
    # columns and a two-word phrase lands across a line break about half the
    # time. Measured: the English file contained "sticky\nsessions" and a plain
    # substring check passed on it while the French file, wrapped differently,
    # failed. A guard that depends on where the wrapping fell is not a guard.
    text = re.sub(r'\s+', ' ', doc.read_text().lower())
    forbidden = [
        'sticky sessions',        # en
        'sessioni persistenti',   # it
        'sticky session',         # de (uses the English term)
        'sessions persistantes',  # fr
        'sesiones persistentes',  # es
    ]
    hit = [phrase for phrase in forbidden if phrase in text]
    assert not hit, (
        f'{doc.relative_to(ROOT)} still describes load balancing across '
        f'instances ({hit}); the chart fails at template time for '
        f'replicaCount != 1'
    )


@pytest.mark.parametrize('doc', ARCHITECTURE_DOCS, ids=lambda p: p.parent.name)
def test_each_architecture_doc_states_the_constraint(doc):
    """CONTROL for the test above: deleting the section would satisfy a
    forbidden-phrase check while leaving readers with nothing.
    """
    text = doc.read_text().lower()
    assert 'replicacount' in text, (
        f'{doc.relative_to(ROOT)} no longer names the replicaCount guard, so '
        f'a reader has no way to learn the constraint from this document'
    )


def _slugify(heading):
    """GitHub's anchor rules, near enough for our headings: lowercase, drop
    punctuation, spaces to hyphens."""
    slug = heading.strip().lower()
    slug = re.sub(r'[^\w\s-]', '', slug, flags=re.UNICODE)
    return re.sub(r'\s+', '-', slug)


@pytest.mark.parametrize('doc', ARCHITECTURE_DOCS, ids=lambda p: p.parent.name)
def test_the_in_document_anchors_resolve(doc):
    """The availability section links to the storage-backend section, and the
    heading is translated in every file — so the anchor is too. A dead anchor
    scrolls nowhere and is invisible in review.
    """
    text = doc.read_text()
    anchors = {_slugify(m) for m in re.findall(r'^#{1,6}\s+(.*)$', text, re.M)}
    used = set(re.findall(r'\]\(#([^)]+)\)', text))

    dead = sorted(a for a in used if a not in anchors)
    assert not dead, (
        f'{doc.relative_to(ROOT)} links to anchors that no heading produces: '
        f'{dead}'
    )
