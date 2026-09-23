"""`audit_prune` refuses before it deletes, not after.

`main()` had this, and it reads like a check:

    signer = audit_signing.AuditSigner(Path(args.key_dir))
    if not signer.available:
        print("FAIL: no audit signing key; the anchor could not be signed")
        return 2

It could never fail. `AuditSigner.__init__` mints and persists a key when it
finds none — correct for the application's first run, and wrong for a tool
pointed at an instance that already exists. Measured before the fix, on an
empty directory:

    available: True
    files now: ['.audit_signing_key']

So `--key-dir` pointing anywhere writable was accepted. Prune then deleted the
archived prefix and signed the replacement anchor with a key the instance had
never used. The instance's own `verify_chain` refuses that anchor — which is
the right answer, arriving after the records it was protecting are gone. A
stray private key is left behind as well.

Two changes, and the second is what makes the first worth having:

* `AuditSigner(..., create=False)` for tools. A missing key is then a missing
  key, and `available` is a question that can be answered no.
* The loaded key must be the instance that exported the bundle. Both answer
  "which instance is this", and this is the one operation where getting it
  wrong destroys the evidence that would have shown it.

The fingerprint is taken from `verify_bundle`, which derives it from the public
key it checked the signature against. The first version of this read
`manifest['fingerprint']`, which does not exist — the field is
`instance_fingerprint` — so the comparison would have been `None != <fp>` for
every bundle, and the guard would have refused everything while looking like it
worked. A dead guard replacing a dead guard.
"""
import json
import pathlib

import pytest

from modules.core import audit_chain, audit_prune
from modules.core.audit import AuditLogger
from modules.core.audit_prune import main
from modules.core.audit_signing import SIGNING_KEY_FILENAME, AuditSigner

pytestmark = [pytest.mark.unit]


@pytest.fixture
def instance(tmp_path):
    """An audit trail with 12 signed entries, key under tmp_path."""
    audit = AuditLogger(tmp_path / "logs", chain_dir=tmp_path / "chain",
                        signer=AuditSigner(tmp_path), checkpoint_interval=5)
    for i in range(12):
        audit.log_operation("renew", "certificate", f"d{i}.example.com", "success")
    yield audit
    if audit.file_handler is not None:
        audit.audit_logger.removeHandler(audit.file_handler)
        audit.file_handler.close()


def _archive(instance, tmp_path, to_seq=5):
    path = tmp_path / "prefix.json"
    path.write_text(json.dumps(instance.export_bundle(to_seq=to_seq)),
                    encoding="utf-8")
    return path


def _run(tmp_path, bundle_path, key_dir):
    return main(["--bundle", str(bundle_path),
                 "--data-dir", str(tmp_path / "chain"),
                 "--key-dir", str(key_dir), "--yes"])


def _chain_state(instance):
    """Everything a prune would change: the records and whether an anchor
    exists. Compared before and after a refusal.

    `anchor_path_for` returns a str, not a Path — the first version of this
    helper called `.exists()` on it and every refusal test failed with an
    AttributeError before it ever reached its assertion.
    """
    path = pathlib.Path(instance.audit_chain_file)
    anchor = pathlib.Path(audit_chain.anchor_path_for(str(path)))
    return path.read_text(encoding="utf-8"), anchor.exists()


# ── the signer, load-only ────────────────────────────────────────────

def test_the_application_still_mints_on_first_run(tmp_path):
    """Guard the guard. `create=True` is the default and is how a fresh
    instance gets an identity; a fix that broke it would disable audit
    signing everywhere."""
    signer = AuditSigner(tmp_path)
    assert signer.available
    assert (tmp_path / SIGNING_KEY_FILENAME).exists()


def test_load_only_reports_a_missing_key_as_missing(tmp_path):
    signer = AuditSigner(tmp_path, create=False)
    assert signer.available is False
    assert signer.fingerprint() is None


def test_load_only_leaves_no_key_behind(tmp_path):
    """Half the harm was the stray private key: a file that looks like an
    instance identity, in a directory that is not one."""
    AuditSigner(tmp_path, create=False)
    assert list(tmp_path.iterdir()) == []


def test_load_only_still_loads_a_key_that_is_there(tmp_path):
    made = AuditSigner(tmp_path)
    loaded = AuditSigner(tmp_path, create=False)
    assert loaded.available
    assert loaded.fingerprint() == made.fingerprint()


# ── the tool, refusing ───────────────────────────────────────────────

def test_prune_refuses_when_the_key_dir_holds_no_key(instance, tmp_path, capsys):
    """The case that reads as a typo in `--key-dir` and used to be accepted."""
    bundle = _archive(instance, tmp_path)
    empty = tmp_path / "not-the-data-dir"
    empty.mkdir()
    before = _chain_state(instance)

    rc = _run(tmp_path, bundle, empty)

    assert rc == 2
    assert "no audit signing key" in capsys.readouterr().err
    assert _chain_state(instance) == before, "records were removed anyway"


def test_a_refused_prune_does_not_leave_a_key_behind(instance, tmp_path):
    """Refusing is not enough if the tool has already written an identity
    into the directory it refused to use."""
    bundle = _archive(instance, tmp_path)
    empty = tmp_path / "not-the-data-dir"
    empty.mkdir()

    _run(tmp_path, bundle, empty)

    assert not (empty / SIGNING_KEY_FILENAME).exists()


def test_prune_refuses_a_bundle_from_another_instance(instance, tmp_path, capsys):
    """The key is real and the bundle is real; they are not the same
    instance. Nothing before this noticed, because `plan_prune` compares the
    bundle to the chain and the chain is not the key."""
    stranger_dir = tmp_path / "stranger"
    stranger_dir.mkdir()
    stranger = AuditLogger(tmp_path / "stranger-logs",
                           chain_dir=tmp_path / "chain",
                           signer=AuditSigner(stranger_dir))
    try:
        bundle = _archive(instance, tmp_path)
        before = _chain_state(instance)

        rc = _run(tmp_path, bundle, stranger_dir)

        assert rc == 2
        err = capsys.readouterr().err
        assert "exported by instance" in err
        assert _chain_state(instance) == before, "records were removed anyway"
    finally:
        if stranger.file_handler is not None:
            stranger.audit_logger.removeHandler(stranger.file_handler)
            stranger.file_handler.close()


def test_the_mismatch_message_names_both_instances(instance, tmp_path, capsys):
    """An operator who has more than one instance needs to know which key they
    used and which one they should have."""
    stranger_dir = tmp_path / "stranger"
    stranger_dir.mkdir()
    stranger_fp = AuditSigner(stranger_dir).fingerprint()
    ours_fp = AuditSigner(tmp_path, create=False).fingerprint()

    _run(tmp_path, _archive(instance, tmp_path), stranger_dir)

    err = capsys.readouterr().err
    assert ours_fp in err and stranger_fp in err
    assert ours_fp != stranger_fp


def test_an_unattributable_bundle_is_refused(instance, tmp_path, capsys, monkeypatch):
    """Fail-closed on a state no caller can reach today.

    `plan_prune` refuses an unsigned bundle, and a signed one always carries a
    public key to derive a fingerprint from — so this branch is unreachable
    through the front door. It is driven here rather than left untested,
    because an untested branch is how the check it replaced got to be wrong.
    """
    real = audit_prune.audit_verify.verify_bundle
    monkeypatch.setattr(
        audit_prune.audit_verify, 'verify_bundle',
        lambda b, *a, **k: {**real(b, *a, **k), 'fingerprint': None})
    before = _chain_state(instance)

    rc = _run(tmp_path, _archive(instance, tmp_path), tmp_path)

    assert rc == 2
    assert "names no exporting instance" in capsys.readouterr().err
    assert _chain_state(instance) == before


@pytest.mark.parametrize('page', ['compliance.md', 'it/compliance.md'])
def test_the_compliance_page_promises_what_the_tool_does(page):
    """`docs/compliance.md` used to say "Run it where the instance's key is",
    which was advice standing in for a check. It now states the refusals, and
    that the tool never creates a key — both of which have to stay true."""
    repo = pathlib.Path(__file__).resolve().parent.parent
    text = (repo / 'docs' / page).read_text(encoding='utf-8')
    promise = ('never creates a key' if page == 'compliance.md'
               else 'non crea mai una chiave')
    assert promise in text, f'docs/{page} no longer states it'
    # ...and the code does not.
    import tempfile
    with tempfile.TemporaryDirectory() as empty:
        assert AuditSigner(empty, create=False).available is False
        assert list(pathlib.Path(empty).iterdir()) == []


# ── and it still prunes ──────────────────────────────────────────────

def test_the_right_key_still_prunes(instance, tmp_path, capsys):
    """The refusals are worth nothing if they also refuse the real thing."""
    bundle = _archive(instance, tmp_path)

    rc = _run(tmp_path, bundle, tmp_path)

    assert rc == 0, capsys.readouterr().err
    assert pathlib.Path(
        audit_chain.anchor_path_for(str(instance.audit_chain_file))).exists()
    assert audit_chain.verify_chain(instance.audit_chain_file)["ok"]


def test_a_dry_run_needs_no_key_at_all(instance, tmp_path, capsys):
    """The key is only needed to sign the anchor, and a dry run writes
    nothing. Requiring one would make the safe mode the harder one."""
    bundle = _archive(instance, tmp_path)
    empty = tmp_path / "nowhere"
    empty.mkdir()

    rc = main(["--bundle", str(bundle), "--data-dir", str(tmp_path / "chain"),
               "--key-dir", str(empty)])

    assert rc == 0
    assert "Dry run" in capsys.readouterr().out
    assert not (empty / SIGNING_KEY_FILENAME).exists()
