"""The chart carries what Artifact Hub reads (#1018).

Artifact Hub lists a Helm chart from its Chart.yaml annotations. The one that
can go stale is `artifacthub.io/images`: it names the image the chart deploys,
Artifact Hub security-scans that image, and a stale tag would scan (and
advertise) an old release. So it is pinned to the chart's appVersion, and
release.sh moves it with the other version numbers.

The repository metadata file stays outside the chart directory, or
`helm package` would ship it inside every chart archive.
"""
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest
import yaml

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
CHART = yaml.safe_load((REPO / 'charts' / 'certmate' / 'Chart.yaml').read_text())
ANN = CHART['annotations']


def test_it_is_filed_under_security_with_its_license():
    assert ANN['artifacthub.io/category'] == 'security'
    assert ANN['artifacthub.io/license'] == 'MIT'


def test_the_links_include_support():
    names = {link['name'] for link in yaml.safe_load(ANN['artifacthub.io/links'])}
    assert 'support' in names          # Artifact Hub gives this name a meaning


def test_the_scanned_image_is_the_one_this_chart_deploys():
    images = yaml.safe_load(ANN['artifacthub.io/images'])
    assert [i['image'] for i in images] == [
        f"docker.io/fabriziosalmi/certmate:{CHART['appVersion']}"]
    assert images[0]['platforms'] == ['linux/amd64', 'linux/arm64']


def test_the_release_moves_the_image_annotation():
    script = (REPO / 'scripts' / 'release.sh').read_text()
    line = next(l for l in script.splitlines() if 'image: docker' in l)
    pattern = re.search(r"r'(.+?)',", line).group(1)
    chart = (REPO / 'charts' / 'certmate' / 'Chart.yaml').read_text()
    bumped = re.sub(pattern, r'\g<1>9.9.9', chart)
    assert 'image: docker.io/fabriziosalmi/certmate:9.9.9' in bumped


def test_the_repository_metadata_is_not_inside_the_chart(tmp_path):
    assert (REPO / 'charts' / 'artifacthub-repo.yml').exists()
    assert not (REPO / 'charts' / 'certmate' / 'artifacthub-repo.yml').exists()
    if not shutil.which('helm'):
        pytest.skip('helm not installed')
    subprocess.run(['helm', 'package', str(REPO / 'charts' / 'certmate'),
                    '--destination', str(tmp_path)], check=True, capture_output=True)
    archive = next(tmp_path.glob('certmate-*.tgz'))
    with tarfile.open(archive) as tar:
        assert not [n for n in tar.getnames() if 'artifacthub' in n]
