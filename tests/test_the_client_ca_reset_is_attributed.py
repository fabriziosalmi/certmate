"""The client CA reset is attributed like every other audit record.

`_audit_ca_reset` passed the username as `actor`, so the one record of a destructive operation
was the one whose `actor` was a string where every other record has `{kind, label}`; the route
walk saw `actor` recorded as `dict` or `str` (#1105). It now takes the attribution from the
request it runs in.
"""
from unittest.mock import MagicMock

import pytest
from flask import Flask, request

from modules.core.client_certificates import ClientCertificateManager

pytestmark = [pytest.mark.unit]


def test_the_reset_record_carries_a_structured_actor():
    manager = ClientCertificateManager.__new__(ClientCertificateManager)
    manager._audit_logger = MagicMock()
    app = Flask(__name__)
    with app.test_request_context('/api/client-certs/ca/reset', method='POST',
                                  environ_base={'REMOTE_ADDR': '10.0.0.7'}):
        request.current_user = {'username': 'alice', 'role': 'admin', 'auth_method': 'session'}
        manager._audit_ca_reset(3, 'alice')

    kwargs = manager._audit_logger.log_operation.call_args.kwargs
    assert kwargs['operation'] == 'ca_reset'
    assert isinstance(kwargs['actor'], dict), kwargs['actor']
    assert kwargs['actor']['label'] == 'alice' and kwargs['actor']['kind']
    assert kwargs['user'] == 'alice' and kwargs['ip_address'] == '10.0.0.7'
    assert kwargs['details'] == {'certificates_removed': 3}
