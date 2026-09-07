"""An extracted resource group must build without the whole manager graph.

That is the entire point of the decomposition. While all 41 classes lived
inside `create_api_resources`, reaching one route meant constructing every
manager, which is why the HTTP layer ended up both the largest module and the
least covered (#662, #669).

This asserts the property directly for each group as it moves out, so a later
change that quietly reintroduces a dependency on the full graph fails here
rather than showing up as coverage that cannot be written.
"""
from unittest.mock import MagicMock

import pytest
from flask import Flask
from flask_restx import Api, Resource

from modules.api.resource_context import ApiContext
from modules.api.resources_cache import create_cache_resources

pytestmark = [pytest.mark.unit]


def _minimal_context(**overrides):
    """A context with only the managers a group genuinely needs."""
    fields = dict(
        auth=MagicMock(), settings=None, certificates=None, file_ops=None,
        cache=None, dns=None, deployer=None, audit=None,
        cert_service=None, cert_executor=None,
    )
    fields.update(overrides)
    fields['auth'].require_role = lambda role: (lambda fn: fn)
    return ApiContext(**fields)


@pytest.fixture
def api():
    app = Flask(__name__)
    app.config['TESTING'] = True
    return Api(app, prefix='/api')


def test_the_cache_group_builds_from_a_minimal_context(api):
    models = {
        'cache_stats_model': MagicMock(),
        'cache_clear_response_model': MagicMock(),
    }
    resources = create_cache_resources(api, models,
                                       _minimal_context(cache=MagicMock()))

    assert set(resources) == {'CacheStats', 'CacheClear'}
    for name, cls in resources.items():
        assert issubclass(cls, Resource), f'{name} is not a Resource'


def test_the_cache_group_needs_no_certificate_manager(api):
    """CONTROL: names the dependency that used to be unavoidable.

    Every class in the old closure could reach the certificate manager whether
    it needed one or not. If cache endpoints start requiring it, that coupling
    has come back.
    """
    models = {
        'cache_stats_model': MagicMock(),
        'cache_clear_response_model': MagicMock(),
    }
    ctx = _minimal_context(cache=MagicMock(), certificates=None)
    resources = create_cache_resources(api, models, ctx)
    assert resources, 'the group must build with no certificate manager at all'
