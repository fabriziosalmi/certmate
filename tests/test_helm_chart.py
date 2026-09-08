"""The Helm chart must stay true to what CertMate actually is.

CertMate runs APScheduler inside the web process and gunicorn with one worker.
A chart that lets someone set replicas to 3 does not produce a scaled CertMate,
it produces three schedulers renewing the same certificates against one
ReadWriteOnce volume. These pin the invariants that keep the chart honest.

The static assertions run everywhere. The render assertions need the helm
binary and skip without it — stated plainly rather than pretending to cover
what they cannot.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

ROOT = Path(__file__).resolve().parent.parent
CHART = ROOT / "charts" / "certmate"


def _read(rel):
    return (CHART / rel).read_text(encoding="utf-8")


def test_chart_exists():
    assert (CHART / "Chart.yaml").exists(), "the Helm chart has moved or gone"


def test_replicas_are_hardcoded_not_templated():
    """A knob that can be turned to 3 is a knob that will be."""
    deployment = _read("templates/deployment.yaml")
    assert "replicas: 1" in deployment, (
        "the Deployment no longer hardcodes one replica — CertMate's scheduler "
        "runs in-process, so a second replica duplicates every renewal"
    )
    assert "{{ .Values.replicaCount }}" not in deployment


def test_the_chart_refuses_more_than_one_replica():
    helpers = _read("templates/_helpers.tpl")
    assert "fail" in helpers and "replicaCount must be 1" in helpers, (
        "the render-time guard is gone; a values override would now silently "
        "produce a multi-scheduler deployment"
    )


def test_rollout_strategy_is_recreate():
    """RollingUpdate deadlocks on a ReadWriteOnce volume: the new pod waits for
    a volume the old pod will not release until the new pod is Ready."""
    assert "type: Recreate" in _read("templates/deployment.yaml")


def test_the_certificate_volume_survives_uninstall():
    assert "helm.sh/resource-policy: keep" in _read("templates/pvc.yaml"), (
        "helm uninstall would now delete the volume holding issued "
        "certificates and the tamper-evident audit chain"
    )


@pytest.mark.parametrize("field", ["version", "appVersion"])
def test_chart_versions_track_the_application(field):
    """Both fields, not just appVersion.

    The chart versions with the application on purpose: a separate chart
    version is a second number to bump, and every independent copy of a
    version in this repository has drifted at least once. `version` also has
    to move for a publish to be a new artifact rather than a rejected
    duplicate — a chart whose contents changed under an unchanged version is
    how a stale chart gets served forever.
    """
    from modules import __version__
    lines = [ln for ln in _read("Chart.yaml").splitlines()
             if ln.startswith(f"{field}:")]
    assert lines, f"Chart.yaml has no {field}"
    found = lines[0].split(":", 1)[1].strip().strip('"')
    assert found == __version__, (
        f"Chart.yaml {field} is {found!r} but modules.__version__ is "
        f"{__version__!r}. scripts/release.sh bumps both."
    )


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")
class TestRender:
    def _template(self, *args):
        return subprocess.run(
            ["helm", "template", "t", str(CHART), *args],
            capture_output=True, text=True,
        )

    def test_default_values_render(self):
        res = self._template()
        assert res.returncode == 0, res.stderr
        assert "kind: Deployment" in res.stdout
        assert "kind: PersistentVolumeClaim" in res.stdout

    def test_more_than_one_replica_is_rejected_with_a_reason(self):
        res = self._template("--set", "replicaCount=2")
        assert res.returncode != 0
        assert "single-instance" in res.stderr

    def test_disabling_persistence_without_a_claim_is_rejected(self):
        res = self._template("--set", "persistence.enabled=false")
        assert res.returncode != 0
        assert "lost on restart" in res.stderr

    def test_an_external_claim_is_accepted(self):
        """The escape hatch for operators who manage storage themselves."""
        res = self._template("--set", "persistence.enabled=false",
                             "--set", "persistence.existingClaim=my-pvc")
        assert res.returncode == 0, res.stderr
        assert "claimName: my-pvc" in res.stdout
        assert "kind: PersistentVolumeClaim" not in res.stdout


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")
class TestSecretWiring:
    """Three paths, and each must render the honest thing for its case."""

    def _template(self, *args):
        return subprocess.run(
            ["helm", "template", "t", str(CHART), *args],
            capture_output=True, text=True, check=True,
        ).stdout

    def test_no_secret_values_produces_no_secret_and_no_envfrom(self):
        """An empty Secret is noise that looks like configuration."""
        out = self._template()
        assert "kind: Secret" not in out
        assert "envFrom" not in out

    def test_supplied_values_produce_a_secret_and_load_it(self):
        out = self._template("--set", "secrets.apiBearerToken=abc")
        assert "kind: Secret" in out
        assert "API_BEARER_TOKEN" in out
        assert "envFrom" in out

    def test_existing_secret_is_loaded_without_generating_one(self):
        out = self._template("--set", "secrets.existingSecret=my-sec")
        assert "kind: Secret" not in out
        assert "name: my-sec" in out

    def test_the_secret_reference_is_not_optional(self):
        """A typo in existingSecret must stop the pod, not start it blind."""
        out = self._template("--set", "secrets.existingSecret=my-sec")
        envfrom = out[out.index("envFrom"):out.index("envFrom") + 400]
        assert "optional: true" not in envfrom, (
            "the secretRef is optional again — a non-existent Secret would let "
            "the pod start without its credentials"
        )


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")
class TestBackupPlacement:
    """Backups must be able to live somewhere the primary volume's failure
    does not reach.

    The chart put `/app/backups` on the same claim as the certificates, the
    settings store and the audit chain — the things the backups exist to
    recover — so one volume loss destroyed the data and its restore points
    together. That stays the default, because a second claim is a real cost
    for a small install and because where backups belong is a fact about the
    operator's infrastructure, not about CertMate. What changed is that it is
    now a decision with an off switch rather than the only shape available.
    """

    def _template(self, *args):
        return subprocess.run(
            ["helm", "template", "t", str(CHART), *args],
            capture_output=True, text=True,
        )

    def test_the_default_is_unchanged(self):
        """Existing installs must render exactly as before: one claim, and
        backups on it under a subPath."""
        out = self._template().stdout
        assert out.count("kind: PersistentVolumeClaim") == 1
        assert "kind: CronJob" not in out
        backups = out.split("mountPath: /app/backups")[1][:80]
        assert "subPath: backups" in backups, (
            "the default no longer puts backups on the shared volume under a "
            "subPath, which silently relocates every existing install's "
            "restore points"
        )

    def test_a_separate_claim_moves_the_backups_off_the_data_volume(self):
        res = self._template("--set", "persistence.backups.separateClaim=true")
        assert res.returncode == 0, res.stderr
        assert res.stdout.count("kind: PersistentVolumeClaim") == 2
        mount = res.stdout.split("mountPath: /app/backups")[1][:80]
        assert "subPath" not in mount, (
            "backups are on their own claim but still mounted under a "
            "subPath, so they would land in a subdirectory of an empty volume"
        )
        assert "t-certmate-backups" in res.stdout

    def test_an_existing_backup_claim_is_used_without_creating_one(self):
        """The case that actually gets backups out of the failure domain:
        a claim the operator made on different storage."""
        res = self._template(
            "--set", "persistence.backups.separateClaim=true",
            "--set", "persistence.backups.existingClaim=nfs-backups")
        assert res.returncode == 0, res.stderr
        assert "claimName: nfs-backups" in res.stdout
        assert res.stdout.count("kind: PersistentVolumeClaim") == 1

    def test_the_backup_claim_survives_an_uninstall(self):
        """It is what is left when the other volume is gone, so deleting it
        with the release would defeat the whole point."""
        res = self._template("--set", "persistence.backups.separateClaim=true")
        pvcs = [doc for doc in res.stdout.split("---")
                if "kind: PersistentVolumeClaim" in doc]
        assert len(pvcs) == 2
        assert all("helm.sh/resource-policy: keep" in doc for doc in pvcs)

    def test_the_offsite_job_reads_the_backups_read_only(self):
        """A copy job must never be able to damage the archives it exists to
        preserve."""
        res = self._template(
            "--set", "persistence.backups.offsite.enabled=true",
            "--set", "persistence.backups.offsite.command={copy,/app/backups,r:x}")
        assert res.returncode == 0, res.stderr
        assert "kind: CronJob" in res.stdout
        job = res.stdout.split("kind: CronJob")[1]
        assert "readOnly: true" in job

    def test_the_offsite_job_follows_the_backup_claim(self):
        """With a separate claim it must mount that one, and without the
        subPath the shared layout needs."""
        res = self._template(
            "--set", "persistence.backups.separateClaim=true",
            "--set", "persistence.backups.offsite.enabled=true",
            "--set", "persistence.backups.offsite.command={copy,/app/backups,r:x}")
        job = res.stdout.split("kind: CronJob")[1]
        assert "t-certmate-backups" in job
        assert "subPath" not in job

    def test_no_offsite_job_without_being_asked_for(self):
        """CONTROL: a CronJob nobody configured would run an image nobody
        chose, on a schedule nobody set."""
        assert "kind: CronJob" not in self._template().stdout
