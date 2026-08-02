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


def test_appversion_matches_the_application():
    """Same rule as package.json, the docs pages and package-lock.json."""
    from modules import __version__
    chart = _read("Chart.yaml")
    line = [ln for ln in chart.splitlines() if ln.startswith("appVersion:")]
    assert line, "Chart.yaml has no appVersion"
    found = line[0].split(":", 1)[1].strip().strip('"')
    assert found == __version__, (
        f"Chart.yaml appVersion is {found!r} but modules.__version__ is "
        f"{__version__!r}. scripts/release.sh bumps this file."
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
