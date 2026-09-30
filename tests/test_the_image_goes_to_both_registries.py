"""Every published image goes to Docker Hub AND GHCR, with one tag set (#1016).

The chart was on GHCR from the start; the image was on Docker Hub only, so
anyone pulling from a cluster or CI runner met Docker Hub's anonymous pull
limits, and `ghcr.io/fabriziosalmi/certmate` did not exist.

The trap this guards: a job-level `permissions:` block REPLACES the workflow's
`read-all` instead of adding to it. `packages: write` alone would have taken
`contents: read` away from the checkout, and forgetting `packages: write`
makes the GHCR login succeed and the push fail with a 403 on the first tag.
"""
from pathlib import Path

import pytest
import yaml

pytestmark = [pytest.mark.unit]

WORKFLOW = (Path(__file__).resolve().parent.parent
            / '.github' / 'workflows' / 'docker-multiplatform.yml')


@pytest.fixture(scope='module')
def build():
    return yaml.safe_load(WORKFLOW.read_text())['jobs']['build']


def _step(build, name):
    return next(s for s in build['steps'] if s.get('name') == name)


def test_one_tag_set_is_pushed_to_both_registries(build):
    images = _step(build, 'Extract metadata')['with']['images'].strip().splitlines()
    assert images == [
        '${{ env.REGISTRY }}/${{ steps.ns.outputs.namespace }}/${{ env.IMAGE_NAME }}',
        'ghcr.io/${{ github.repository_owner }}/${{ env.IMAGE_NAME }}',
    ]
    assert yaml.safe_load(WORKFLOW.read_text())['env']['REGISTRY'] == 'docker.io'


def test_ghcr_is_logged_in_with_the_workflow_token_and_never_on_a_pr(build):
    login = _step(build, 'Log in to GHCR')
    assert login['with']['registry'] == 'ghcr.io'
    assert login['with']['password'] == '${{ secrets.GITHUB_TOKEN }}'
    assert login['if'] == "github.event_name != 'pull_request'"


def test_the_build_job_can_push_packages_and_still_read_the_repo(build):
    assert build['permissions'] == {'contents': 'read', 'packages': 'write'}


def test_no_other_job_can_write_packages():
    jobs = yaml.safe_load(WORKFLOW.read_text())['jobs']
    writers = [name for name, job in jobs.items()
               if (job.get('permissions') or {}).get('packages') == 'write']
    assert writers == ['build']
