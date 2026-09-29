"""AWS storage authentication: explicit keys, credential chain, refreshing STS roles."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask
from flask_restx import Api

from modules.api.resource_context import ApiContext
from modules.api.resources_storage import create_storage_resources
from modules.core.storage_backends import AWSSecretsManagerBackend, S3CompatibleBackend, StorageManager


pytestmark = pytest.mark.unit

ROLE = 'arn:aws:iam::123456789012:role/CertMateS3'


def test_aws_role_uses_sdk_credential_chain_without_explicit_keys():
    backend = S3CompatibleBackend({'bucket': 'certs', 'region': 'eu-west-1',
                                   'auth_mode': 'iam_role'})
    with patch('boto3.client') as client:
        backend._get_client()
    client.assert_called_once_with('s3', endpoint_url=None, region_name='eu-west-1')


def test_secrets_manager_uses_sdk_credential_chain_without_explicit_keys():
    backend = AWSSecretsManagerBackend({'region': 'eu-west-1', 'auth_mode': 'iam_role'})
    with patch('boto3.client') as client:
        backend._get_client()
    client.assert_called_once_with('secretsmanager', region_name='eu-west-1')


def test_existing_s3_compatible_access_keys_are_unchanged():
    backend = S3CompatibleBackend({
        'bucket': 'certs', 'endpoint_url': 'https://s3.example.com',
        'access_key_id': 'key', 'secret_access_key': 'secret',
    })
    with patch('boto3.client') as client:
        backend._get_client()
    client.assert_called_once_with('s3', endpoint_url='https://s3.example.com',
                                   region_name='us-east-1', aws_access_key_id='key',
                                   aws_secret_access_key='secret')


def test_existing_secrets_manager_access_keys_are_unchanged():
    backend = AWSSecretsManagerBackend({'access_key_id': 'key', 'secret_access_key': 'secret'})
    with patch('boto3.client') as client:
        backend._get_client()
    client.assert_called_once_with('secretsmanager', region_name='us-east-1',
                                   aws_access_key_id='key', aws_secret_access_key='secret')


@pytest.mark.parametrize('backend_class,config', [
    (S3CompatibleBackend, {'bucket': 'certs'}),
    (AWSSecretsManagerBackend, {'region': 'eu-west-1'}),
])
def test_missing_keys_without_explicit_auth_mode_fail_closed(backend_class, config):
    with pytest.raises(ValueError, match='access_key_id and secret_access_key'):
        backend_class(config)


def test_selecting_iam_ignores_any_old_stored_access_keys():
    backend = S3CompatibleBackend({
        'bucket': 'certs', 'auth_mode': 'iam_role',
        'access_key_id': 'old-key', 'secret_access_key': 'old-secret',
    })
    with patch('boto3.client') as client:
        backend._get_client()
    assert 'aws_access_key_id' not in client.call_args.kwargs
    assert 'aws_secret_access_key' not in client.call_args.kwargs


def test_secrets_manager_iam_ignores_any_old_stored_access_keys():
    backend = AWSSecretsManagerBackend({'auth_mode': 'iam_role',
                                        'access_key_id': 'old-key', 'secret_access_key': 'old-secret'})
    with patch('boto3.client') as client:
        backend._get_client()
    client.assert_called_once_with('secretsmanager', region_name='us-east-1')


@pytest.mark.parametrize('service,backend_class', [
    ('s3', S3CompatibleBackend), ('secretsmanager', AWSSecretsManagerBackend),
])
def test_assume_role_refreshes_temporary_credentials(service, backend_class):
    config = {'region': 'eu-west-1', 'auth_mode': 'iam_role', 'assume_role_arn': ROLE}
    if service == 's3':
        config['bucket'] = 'certs'
    backend = backend_class(config)
    sts = MagicMock()
    sessions = MagicMock()
    counter = [0]

    def assume_role(**kwargs):
        assert kwargs == {'RoleArn': ROLE, 'RoleSessionName': f'certmate-{service}-storage'}
        counter[0] += 1
        return {'Credentials': {
            'AccessKeyId': f'TEMP{counter[0]}',
            'SecretAccessKey': f'SECRET{counter[0]}',
            'SessionToken': f'TOKEN{counter[0]}',
            'Expiration': datetime.now(timezone.utc) + timedelta(hours=1),
        }}

    sts.assume_role.side_effect = assume_role
    with patch('boto3.client', return_value=sts) as client, \
         patch('boto3.Session', return_value=sessions) as session:
        assert backend._get_client() is sessions.client.return_value

    client.assert_called_once_with('sts', region_name='eu-west-1')
    client_options = {'endpoint_url': None} if service == 's3' else {}
    sessions.client.assert_called_once_with(service, region_name='eu-west-1', **client_options)
    credentials = session.call_args.kwargs['botocore_session'].get_credentials()
    assert credentials.get_frozen_credentials().token == 'TOKEN1'
    credentials._expiry_time = datetime.now(timezone.utc) + timedelta(seconds=1)
    assert credentials.get_frozen_credentials().token == 'TOKEN2'
    assert sts.assume_role.call_count == 2


@pytest.mark.parametrize('backend_class', [S3CompatibleBackend, AWSSecretsManagerBackend])
def test_explicit_keys_can_be_the_source_for_assume_role(backend_class):
    config = {'auth_mode': 'access_keys', 'access_key_id': 'key',
              'secret_access_key': 'secret', 'assume_role_arn': ROLE}
    if backend_class is S3CompatibleBackend:
        config['bucket'] = 'certs'
    backend = backend_class(config)
    sts = MagicMock()
    sts.assume_role.return_value = {'Credentials': {
        'AccessKeyId': 'TEMP', 'SecretAccessKey': 'TEMPSECRET', 'SessionToken': 'TOKEN',
        'Expiration': datetime.now(timezone.utc) + timedelta(hours=1),
    }}
    with patch('boto3.client', return_value=sts) as client, patch('boto3.Session'):
        backend._get_client()
    client.assert_called_once_with('sts', region_name='us-east-1',
                                   aws_access_key_id='key', aws_secret_access_key='secret')


@pytest.mark.parametrize('config, error', [
    ({'auth_mode': 'unknown'}, 'auth_mode'),
    ({'auth_mode': 'access_keys'}, 'secret_access_key'),
    ({'auth_mode': 'iam_role', 'endpoint_url': 'https://minio.example'}, 'endpoint_url'),
    ({'auth_mode': 'iam_role', 'assume_role_arn': ROLE,
      'endpoint_url': 'https://minio.example'}, 'endpoint_url'),
    ({'auth_mode': 'iam_role', 'assume_role_arn': 'not-an-arn'}, 'assume_role_arn'),
])
def test_invalid_auth_combinations_fail_before_connecting(config, error):
    with pytest.raises(ValueError, match=error):
        S3CompatibleBackend({'bucket': 'certs', **config})


@pytest.mark.parametrize('config, error', [
    ({'auth_mode': 'unknown'}, 'auth_mode'),
    ({'auth_mode': 'access_keys'}, 'secret_access_key'),
    ({'auth_mode': 'iam_role', 'assume_role_arn': 'not-an-arn'}, 'assume_role_arn'),
])
def test_secrets_manager_rejects_bad_auth_config(config, error):
    with pytest.raises(ValueError, match=error):
        AWSSecretsManagerBackend(config)


@pytest.mark.parametrize('backend_type,backend_class', [
    ('s3_compatible', S3CompatibleBackend),
    ('aws_secrets_manager', AWSSecretsManagerBackend),
])
def test_storage_connection_test_reports_iam_permission_errors(backend_type, backend_class):
    auth = MagicMock()
    auth.require_role = lambda role: (lambda fn: fn)
    ctx = ApiContext(auth=auth, settings=MagicMock(), certificates=None,
                     file_ops=None, cache=None, dns=None, deployer=None,
                     audit=None, cert_service=None, cert_executor=None,
                     managers={})
    app = Flask(__name__)
    api = Api(app, prefix='/api')
    models = {key: MagicMock() for key in ('storage_config_model',
                                          'storage_test_config_model',
                                          'storage_migration_config_model')}
    resource = create_storage_resources(api, models, ctx)['StorageBackendTest']
    with app.test_request_context('/', json={
        'backend': backend_type,
        'config': {'bucket': 'certs', 'auth_mode': 'iam_role'} if backend_type == 's3_compatible'
                  else {'auth_mode': 'iam_role'},
    }), patch.object(backend_class, '_list_certificates_attempt',
                     side_effect=PermissionError('AccessDenied')):
        result = resource().post()
    assert result['success'] is False
    assert result['backend'] == backend_type


@pytest.mark.parametrize('backend_class', [S3CompatibleBackend, AWSSecretsManagerBackend])
def test_migration_does_not_report_an_unreadable_iam_source_as_empty(backend_class):
    config = {'auth_mode': 'iam_role'}
    if backend_class is S3CompatibleBackend:
        config['bucket'] = 'certs'
    source = backend_class(config)
    source._client = MagicMock()
    source._client.get_paginator.side_effect = PermissionError('AccessDenied')
    with pytest.raises(PermissionError, match='AccessDenied'):
        StorageManager.__new__(StorageManager).migrate_certificates(source, MagicMock())
