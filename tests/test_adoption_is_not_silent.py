"""Adopting a discovered certificate must not be silent (#640).

Adoption is a real issuance — `POST /api/inventory/<fp>/adopt` feeds the
derived plan into `CertificateService.create()`, which drives certbot and
writes new material to disk. Every other issuance path publishes on the event
bus afterwards; the adopt handler did not.

Three independent subscribers gate on the event NAME, and each one silently
ignores anything it does not recognise:

    factory._on_event            event_titles.get(event) -> None -> return
    DeployManager.on_certificate_event   event_map.get(event) -> None -> return
    CacheManager.on_certificate_event    `if event not in (...): return`

So an adopted certificate ran no deploy hook, and the dashboard kept serving a
cached "deployed & matching" verdict while the load balancer was still on the
OLD certificate — with no alert to say so. That is the operator-visible harm,
and it is what these tests assert: not "an event was published", but the three
consequences an operator actually loses.

The reporter offered two designs and asked for a steer. A distinct
`certificate_adopted` event would have to be taught to all three subscribers
plus two UI filters, and missing any one of them fixes the notification while
leaving the deploy hooks broken — the failure mode that produced this report.
So adoption publishes `certificate_created`, which every subscriber already
honours, and carries an `adopted` marker in the payload so the notification can
still tell the truth. `test_the_event_name_is_one_every_subscriber_honours`
exists to make a later rename fail loudly rather than silently.
"""
import time
from pathlib import Path

import pytest

from modules.factory import create_app

pytestmark = [pytest.mark.unit]


def _eventually(predicate, timeout=5.0):
    """EventBus invokes listeners in daemon threads, so the consequences of a
    publish are not visible the moment the request returns. Poll, as
    test_deploy_status_cache_invalidation does, rather than sleeping a fixed
    amount and hoping."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


@pytest.fixture
def app_container(tmp_path, monkeypatch):
    project_root = tmp_path / "certmate"
    module_dir = project_root / "modules" / "core"
    module_dir.mkdir(parents=True)
    (module_dir / "factory.py").write_text("# test path anchor\n")
    monkeypatch.setattr("modules.factory.__file__", str(module_dir / "factory.py"))
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("TESTING", "true")
    application, container = create_app()
    assert Path(container.cert_dir).resolve().is_relative_to(tmp_path)
    return application, container


@pytest.fixture
def client(app_container):
    return app_container[0].test_client()


@pytest.fixture
def container(app_container):
    return app_container[1]


def _record_discovered(container, fingerprint='fp', cn='example.com'):
    inv = container.managers['cert_inventory']
    inv.record_certificate(
        {'fingerprint_sha256': fingerprint, 'subject_cn': cn,
         'san_dns': [cn], 'key': {'type': 'RSA', 'size': 2048},
         'not_after': '2099-01-01T00:00:00Z'},
        source='ct-log',
    )
    return inv


def _make_adoptable(container):
    """Seed the state adoption needs: an inventory record, an account email,
    a DNS provider that can validate the domain, and an issuance that does not
    shell out to certbot.

    The issuance goes through the REAL CertificateService, with only the shell
    replaced. These tests used to stand a fake service in its place, and the
    fake announced nothing, so they could not see that the real service and
    the adopt handler each published `certificate_created`: every adoption ran
    the deploy hooks twice.
    """
    from modules.core.shell import MockShellExecutor

    inv = _record_discovered(container)

    def seed(settings):
        settings['email'] = 'a@b.com'
        settings['dns_provider'] = 'cloudflare'
        settings['dns_providers'] = {
            'cloudflare': {'accounts': {'default': {'api_token': 'test-token'}}}}
    container.managers['settings'].update(seed, 'seed')

    class _FakeDNS:
        settings_manager = container.managers['settings']

        def suggest_dns_provider_for_domain(self, domain, settings=None):
            return 'cloudflare', 90

        def get_available_providers(self):
            return [{'name': 'cloudflare', 'configured': True}]

    container.managers['dns'] = _FakeDNS()
    container.managers['certificates'].shell_executor = MockShellExecutor()
    return inv


def _adopt(client):
    resp = client.post('/api/inventory/fp/adopt')
    assert resp.status_code == 201, resp.get_json()
    return resp


# ---------------------------------------------------------------------------
# The three consequences
# ---------------------------------------------------------------------------

def test_adoption_publishes_an_issuance_event(app_container, client, container):
    """The root of all three. Asserted on the real bus, not a mock."""
    app, _ = app_container
    _make_adoptable(container)

    seen = []
    app.config['EVENT_BUS'].add_listener(lambda event, data: seen.append((event, data)))

    _adopt(client)
    _eventually(lambda: bool(seen))

    assert seen, (
        'adoption issued a certificate and published nothing: no deploy hook '
        'ran, no cache was invalidated, no operator was told'
    )
    names = [event for event, _ in seen]
    assert 'certificate_created' in names, (
        f'expected certificate_created on the bus, got {names}'
    )


def test_adoption_is_announced_once(app_container, client, container):
    """One adoption, one issuance, one announcement.

    The service publishes `certificate_created` for every create, and the adopt
    handler published it again afterwards, so the deploy hooks and targets ran
    twice for one certificate. The record is taken synchronously, at publish
    time, so a second announcement cannot hide behind listener threads that
    have not run yet.
    """
    app, _ = app_container
    _make_adoptable(container)

    bus = app.config['EVENT_BUS']
    published = []
    original = bus.publish

    def recording_publish(event, data=None, *args, **kwargs):
        published.append((event, dict(data or {})))
        return original(event, data, *args, **kwargs)

    bus.publish = recording_publish
    try:
        _adopt(client)
    finally:
        bus.publish = original

    created = [data for event, data in published if event == 'certificate_created']
    assert len(created) == 1, (
        f'adoption announced the certificate {len(created)} times: {created}')
    assert created[0]['domain'] == 'example.com'
    assert created[0].get('adopted') is True
    assert created[0].get('fingerprint') == 'fp'


def test_adoption_invalidates_the_cached_deployment_verdict(
        app_container, client, container):
    """The dangerous one: without this the dashboard keeps saying "deployed &
    matching" for up to cache_ttl while the load balancer serves the OLD
    certificate."""
    _make_adoptable(container)
    cache = container.managers['cache']
    cache.set_deployment_status('example.com', {'deployed': True, 'matches': True})
    assert cache.get_deployment_status('example.com') is not None, (
        'this test is only meaningful with something cached to evict'
    )

    _adopt(client)
    _eventually(lambda: cache.get_deployment_status('example.com') is None)

    assert cache.get_deployment_status('example.com') is None, (
        'the stale "deployed & matching" verdict survived adoption'
    )


def test_adoption_runs_the_deploy_hooks(app_container, client, container,
                                        monkeypatch):
    """An adopted certificate is new material on disk; the hooks that push it
    to the load balancer must fire exactly as they do for create and renew."""
    _make_adoptable(container)

    fired = []
    deploy_manager = container.managers.get('deployer')
    assert deploy_manager is not None, 'no deploy manager to assert against'
    monkeypatch.setattr(
        deploy_manager, '_execute_hooks',
        lambda domain, event_type: fired.append((domain, event_type)) or [],
    )

    _adopt(client)
    _eventually(lambda: bool(fired))

    assert fired == [('example.com', 'created')], (
        f'deploy hooks did not run for the adopted certificate: {fired}'
    )


# ---------------------------------------------------------------------------
# Truthfulness, and the guard on the design decision
# ---------------------------------------------------------------------------

def test_the_notification_says_adopted_rather_than_created(
        app_container, client, container):
    """Reusing certificate_created must not make the alert lie. The payload
    carries the distinction so operators keep one toggle and still read what
    actually happened."""
    app, _ = app_container
    _make_adoptable(container)

    seen = []
    app.config['EVENT_BUS'].add_listener(lambda event, data: seen.append((event, data)))

    _adopt(client)
    _eventually(lambda: bool(seen))

    payloads = [data for event, data in seen if event == 'certificate_created']
    assert payloads, 'no certificate_created payload to inspect'
    assert payloads[0].get('adopted') is True, (
        'the payload does not record that this issuance was an adoption, so '
        'the notification cannot distinguish it from a plain create'
    )
    assert payloads[0].get('fingerprint') == 'fp', (
        'the adopted inventory record is not identified in the payload'
    )


def test_the_notification_title_reflects_adoption(app_container):
    """The bridge renders the message; a marker nothing reads is not a fix."""
    from modules import factory

    src = factory.build_notification_message
    assert src('certificate_created', {'domain': 'example.com'}) == (
        'Certificate Created', 'Certificate Created: example.com')
    assert src('certificate_created',
               {'domain': 'example.com', 'adopted': True}) == (
        'Certificate Adopted', 'Certificate Adopted: example.com')


def test_the_event_name_is_one_every_subscriber_honours():
    """A guard on the design choice, not on the code path.

    The obvious "improvement" is a dedicated `certificate_adopted` event. Three
    subscribers filter on the name and each ignores what it does not know, so
    that change would restore silent deploy hooks unless all three are updated
    together.

    So this reads the name the adoption path actually publishes and requires
    every subscriber to know it. Written the other way round — asserting that
    the three subscribers mention `certificate_created` — it would have passed
    unchanged while adoption published something none of them handles, which is
    the whole failure being guarded against.

    Adoption announces through the service's create, the one place every
    create publishes; the handler adds only the `adopted` marker. A publish of
    its own in the handler is what announced every adoption twice.
    """
    import inspect
    import re

    from modules.api import resources_inventory
    from modules import factory
    from modules.core.cache import CacheManager
    from modules.core.cert_service import CertificateService
    from modules.core.deployer import DeployManager

    assert not re.search(r"\.publish\(", inspect.getsource(resources_inventory)), (
        'the inventory resources publish an event of their own; adoption is '
        'announced by the service, and a second publish runs every hook twice')

    published = re.findall(
        r"_publish\(\s*'([a-z_]+)'",
        inspect.getsource(CertificateService._issue_create),
    )
    assert published, 'the create path the adoption goes through publishes nothing'

    # The notifier bridge is checked against its title table rather than its
    # source: the session-scoped fixture from #702 repoints
    # modules.factory.__file__ at a stub, so inspect.getsource() on the
    # MODULE reads "# test path anchor" and every containment check passes
    # vacuously. Function objects carry their own co_filename and are safe.
    for event in published:
        for owner, recognises in (
            ('CacheManager',
             event in inspect.getsource(CacheManager.on_certificate_event)),
            ('DeployManager',
             event in inspect.getsource(DeployManager.on_certificate_event)),
            ('notifier bridge', event in factory._EVENT_TITLES),
        ):
            assert recognises, (
                f"adoption publishes '{event}', which {owner} does not "
                f"recognise — it will drop the event silently"
            )
