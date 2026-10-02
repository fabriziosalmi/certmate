"""The calls of the route walk for the routes the OpenAPI document DOES describe.

`tests/contract_routes.py` walks the plain Flask routes (users, keys, deploy, auth, audit).
These are the other 69: certificates, client certificates, DNS accounts, backups, storage,
inventory, settings, health. The document declares a 200 for nearly all of them and a response
schema for 7 (#1105); what they answer, in which fields and under which status codes, is what
callers depend on, and nothing compared it with the version.

Each function is one area, and each calls its routes in the order that makes the next call
meaningful: create before read, read before change, change before delete. The plan runs inside
`contract_world.sealed()` with `contract_world.Certbot` standing in for the one program the
application launches, on an instance seeded with a certificate (`contract_world.seed`), so the
SUCCESS answer of create, renew and reissue is reached and recorded, next to the failures.
"""
import io

from tests import contract_world as world

DOMAIN = world.DOMAIN
NEW = 'new.example.test'
BROKEN = 'broken.example.test'
ASYNC = 'queued.example.test'
UNKNOWN = 'unknown.example.test'


def walk(plan):
    """All of it, in an order where each area leaves the state the next needs."""
    health(plan)
    dns_accounts(plan)
    certificates(plan)
    client_certificates(plan)
    inventory(plan)
    backups(plan)
    storage(plan)
    settings(plan)


# --------------------------------------------------------------------------

def health(plan):
    call = plan.call
    call('get', '/api/health')
    call('get', '/api/metrics')
    call('post', '/api/cache/clear', body={})
    call('post', '/api/probe', body={})                                                     # 400
    call('post', '/api/probe', body={'host': DOMAIN, 'port': 443})                           # unreachable: sealed
    call('post', '/api/probe', body={'host': '127.0.0.1', 'port': plan.world.port})          # a certificate
    call('post', '/api/probe', body={'host': '127.0.0.1', 'port': 1})                        # a refused connection


def dns_accounts(plan):
    call = plan.call
    call('get', '/api/dns/accounts')
    call('get', '/api/dns/<provider>/accounts', path='/api/dns/cloudflare/accounts')
    call('post', '/api/dns/<provider>/accounts', path='/api/dns/cloudflare/accounts',
         body={'name': 'walk', 'config': {'api_token': 'x' * 24}})
    call('post', '/api/dns/<provider>/accounts', path='/api/dns/cloudflare/accounts', body={})  # 400
    call('post', '/api/dns/accounts',
         body={'name': 'walk2', 'provider': 'cloudflare', 'config': {'api_token': 'y' * 24},
               'set_as_default': False})
    call('post', '/api/dns/accounts', body={})                                              # 400
    call('put', '/api/dns/<provider>/accounts/<account_id>', path='/api/dns/cloudflare/accounts/walk',
         body={'api_token': 'z' * 24})
    call('delete', '/api/dns/<provider>/accounts/<account_id>', path='/api/dns/cloudflare/accounts/walk')
    call('delete', '/api/dns/<provider>/accounts/<account_id>', path='/api/dns/cloudflare/accounts/walk2')
    call('delete', '/api/dns/<provider>/accounts/<account_id>', path='/api/dns/cloudflare/accounts/never-existed')


def certificates(plan):
    call = plan.call
    detail = f'/api/certificates/{DOMAIN}'

    # --- reads. The deployment probe is pointed at the TLS server of the world, and a browser
    # has reported on the certificate, before it is read: the answer carries both.
    call('patch', '/api/certificates/<domain>', path=detail,
         body={'deployment_host': '127.0.0.1', 'deployment_port': plan.world.port, 'deployment_protocol': 'https-tls'})
    call('get', '/api/certificates/<domain>/deployment-status', path=f'{detail}/deployment-status')   # a probe
    call('post', '/api/certificates/deployment-status/browser',
         body={'reports': [{'domain': DOMAIN, 'reachable': True, 'method': 'browser',
                            'source': 'dashboard', 'checked_at': '2026-10-01T00:00:00Z'}]})
    call('get', '/api/certificates')
    call('get', '/api/certificates/<domain>', path=detail)
    call('get', '/api/certificates/<domain>', path=f'/api/certificates/{UNKNOWN}')           # 404
    call('get', '/api/certificates/<domain>', path='/api/certificates/not-a-domain')         # 400
    call('get', '/api/certificates/<domain>/deployment-status', path=f'{detail}/deployment-status')
    call('get', '/api/certificates/<domain>/dns-alias-check', path=f'{detail}/dns-alias-check')    # 400: not an alias
    call('get', '/api/certificates/<domain>/dns-alias-check',
         path=f'/api/certificates/{plan.world.alias_domain}/dns-alias-check')                   # sealed: unresolved
    call('get', '/api/certificates/<domain>/dns-alias-check', path=f'/api/certificates/{UNKNOWN}/dns-alias-check')
    call('get', '/api/certificates/<domain>/download', path=f'{detail}/download', stream=True)
    for kind in ('cert', 'chain', 'fullchain', 'privkey'):
        call('get', '/api/certificates/<domain>/download/<file_type>', path=f'{detail}/download/{kind}',
             stream=True)
    call('get', '/api/certificates/<domain>/download/<file_type>', path=f'{detail}/download/nope')   # 400
    call('get', '/api/certificates/<domain>/download', path=f'/api/certificates/{UNKNOWN}/download')   # 404

    # --- issue: bad requests, then the real thing, then a failure at the CA
    call('post', '/api/certificates/create', body={})                                       # 400: validation
    call('post', '/api/certificates/create', body={'domain': 'not-a-domain', 'dns_provider': 'cloudflare'})
    call('post', '/api/certificates/create', body={'domain': NEW, 'dns_provider': 'no-such-provider'})
    call('post', '/api/certificates/create', body={'domain': NEW, 'dns_provider': 'cloudflare'})   # issued
    call('post', '/api/certificates/create', body={'domain': NEW, 'dns_provider': 'cloudflare'})   # again
    plan.certbot.fail_with()
    call('post', '/api/certificates/create', body={'domain': BROKEN, 'dns_provider': 'cloudflare'})  # CA refuses
    _, accepted = call('post', '/api/certificates/create',
                       body={'domain': ASYNC, 'dns_provider': 'cloudflare', 'async': True})        # 202
    job = (accepted or {}).get('job_id')
    if job:
        plan.wait_job(job)
        call('get', '/api/certificates/jobs/<job_id>', path=f'/api/certificates/jobs/{job}')
    gate = plan.certbot.hold_next()                  # a job caught in flight: the only time the list has one
    _, held = call('post', '/api/certificates/create',
                   body={'domain': 'held.example.test', 'dns_provider': 'cloudflare', 'async': True})
    running = (held or {}).get('job_id')
    if running:
        plan.wait_job(running, until=('running',))
        call('get', '/api/certificates/jobs')
        call('get', '/api/certificates/jobs/<job_id>', path=f'/api/certificates/jobs/{running}')   # running
    gate.set()
    if running:
        plan.wait_job(running)
    plan.certbot.fail_with()
    _, refused = call('post', '/api/certificates/create',
                      body={'domain': 'refused.example.test', 'dns_provider': 'cloudflare', 'async': True})
    job = (refused or {}).get('job_id')
    if job:
        plan.wait_job(job)
        call('get', '/api/certificates/jobs/<job_id>', path=f'/api/certificates/jobs/{job}')   # failed
    call('get', '/api/certificates/jobs')
    call('get', '/api/certificates/jobs/<job_id>', path='/api/certificates/jobs/no-such-job')    # 404

    # --- change
    call('patch', '/api/certificates/<domain>', path=detail, body={'notes': 'walk', 'tags': ['walk']})
    call('patch', '/api/certificates/<domain>', path=detail, body={'deployment_port': 99999})             # 400
    call('patch', '/api/certificates/<domain>', path=detail, body={'deployment_protocol': 'ftp'})         # 400
    call('patch', '/api/certificates/<domain>', path=detail, body={})                           # 400
    call('patch', '/api/certificates/<domain>', path=f'/api/certificates/{UNKNOWN}', body={'notes': 'x'})
    call('put', '/api/certificates/<domain>/auto-renew', path=f'{detail}/auto-renew', body={'enabled': False})
    call('put', '/api/certificates/<domain>/auto-renew', path=f'{detail}/auto-renew', body={})   # 400
    call('put', '/api/certificates/<domain>/auto-renew', path=f'/api/certificates/{UNKNOWN}/auto-renew',
         body={'enabled': True})

    # --- renew, reissue, deploy
    call('post', '/api/certificates/<domain>/renew', path=f'{detail}/renew', body={})           # renewed
    call('get', '/api/certificates/<domain>', path=detail)                                      # renewed_at, notes
    call('get', '/api/certificates')
    plan.certbot.fail_with()
    call('post', '/api/certificates/<domain>/renew', path=f'{detail}/renew', body={})           # CA refuses
    call('post', '/api/certificates/<domain>/renew', path=f'/api/certificates/{UNKNOWN}/renew', body={})
    call('post', '/api/certificates/<domain>/reissue', path=f'{detail}/reissue',
         body={'san_domains': ['www.shop.example.test']})
    plan.certbot.fail_with()
    call('post', '/api/certificates/<domain>/reissue', path=f'{detail}/reissue', body={})
    call('post', '/api/certificates/<domain>/reissue', path=f'/api/certificates/{UNKNOWN}/reissue', body={})
    call('post', '/api/certificates/<domain>/deploy', path=f'{detail}/deploy', body={})         # nothing configured
    call('post', '/api/deploy/config',
         body={'enabled': True, 'domain_hooks': {},
               'global_hooks': [{'id': 'walk-hook', 'name': 'walk-hook', 'command': 'echo deployed',
                                 'enabled': True, 'on_events': ['manual']}]})
    call('post', '/api/certificates/<domain>/deploy', path=f'{detail}/deploy', body={})         # a hook runs
    call('post', '/api/deploy/config', body={'enabled': False, 'domain_hooks': {}, 'global_hooks': []})
    call('post', '/api/certificates/<domain>/deploy', path=f'/api/certificates/{UNKNOWN}/deploy', body={})

    # --- checks that look at the world: sealed, so they answer for a world that does not answer
    call('post', '/api/certificates/check-caa', body={'domain': DOMAIN})
    call('post', '/api/certificates/check-caa', body={})                                    # 400
    call('post', '/api/certificates/check-dns-alias',
         body={'domain': DOMAIN, 'domain_alias': 'alias.example.test'})
    call('post', '/api/certificates/check-dns-alias', body={})                              # 400
    call('post', '/api/certificates/deployment-status/browser', body={})                   # 400
    call('post', '/api/certificates/reissue-keyless', body={})                              # one queued
    call('post', '/api/certificates/zombies/scan', body={})

    call('get', '/api/cache/stats')                                  # what the reads above left in it
    call('post', '/api/cache/clear', body={})

    # --- remove
    call('delete', '/api/certificates/<domain>', path=f'/api/certificates/{NEW}')
    call('delete', '/api/certificates/<domain>', path=f'/api/certificates/{NEW}')           # 404
    call('delete', '/api/certificates/<domain>', path='/api/certificates/not-a-domain')     # 400


def client_certificates(plan):
    call = plan.call
    call('get', '/api/client-certs/ca', stream=True)
    call('get', '/api/client-certs/stats')
    call('get', '/api/client-certs')
    call('post', '/api/client-certs/create', body={})                                       # 400
    _, made = call('post', '/api/client-certs/create',
                   body={'common_name': 'alice@example.test', 'email': 'alice@example.test',
                         'cert_usage': 'api-mtls'})
    ident = _identifier(made)
    call('post', '/api/client-certs/batch', body={})                                        # 400
    call('post', '/api/client-certs/batch',
         body={'headers': ['common_name', 'email'], 'rows': [['bob@example.test', 'bob@example.test'], ['', '']]})
    call('get', '/api/client-certs')
    call('get', '/api/client-certs/stats')
    if ident:
        call('get', '/api/client-certs/<identifier>', path=f'/api/client-certs/{ident}')
        for kind in ('crt', 'key', 'csr', 'pfx'):
            call('get', '/api/client-certs/<identifier>/download/<file_type>',
                 path=f'/api/client-certs/{ident}/download/{kind}', stream=True)
        call('post', '/api/client-certs/<identifier>/renew', path=f'/api/client-certs/{ident}/renew', body={})
        call('post', '/api/client-certs/<identifier>/revoke', path=f'/api/client-certs/{ident}/revoke',
             body={'reason': 'unspecified'})
        call('post', '/api/client-certs/<identifier>/revoke', path=f'/api/client-certs/{ident}/revoke', body={})
        call('get', '/api/client-certs')                    # a revoked one listed: `revoked_at` is a string
        call('get', '/api/client-certs/<identifier>', path=f'/api/client-certs/{ident}')
    call('get', '/api/client-certs/<identifier>', path='/api/client-certs/no-such-certificate')       # 404
    call('get', '/api/client-certs/<identifier>/download/<file_type>',
         path='/api/client-certs/no-such-certificate/download/crt')
    call('get', '/api/client-certs/<identifier>/download/<file_type>',
         path='/api/client-certs/no-such-certificate/download/nope')                        # 400
    call('post', '/api/client-certs/<identifier>/renew', path='/api/client-certs/no-such-certificate/renew', body={})
    call('post', '/api/client-certs/<identifier>/revoke', path='/api/client-certs/no-such-certificate/revoke', body={})
    for fmt in ('pem', 'der', 'info', 'nope'):
        call('get', '/api/crl/download/<format>', path=f'/api/crl/download/{fmt}', stream=fmt in ('pem', 'der'))
    call('get', '/api/ocsp/status/<serial>', path='/api/ocsp/status/1234')
    call('get', '/api/ocsp/status/<serial>', path='/api/ocsp/status/not-a-serial')
    call('post', '/api/client-certs/ca/reset', body={})                                     # 400: not confirmed
    call('post', '/api/client-certs/ca/reset', body={'confirm': 'reset-client-ca', 'subject': 'nope'})  # 400
    call('post', '/api/client-certs/ca/reset', body={'confirm': 'reset-client-ca'})


def _identifier(made):
    if not isinstance(made, dict):
        return None
    for holder in (made, made.get('certificate'), made.get('data')):
        if isinstance(holder, dict):
            for key in ('identifier', 'serial_number', 'id'):
                if holder.get(key):
                    return str(holder[key])
    return None


def inventory(plan):
    call = plan.call
    call('get', '/api/inventory')
    call('get', '/api/inventory/domains')
    call('get', '/api/inventory/health')
    call('get', '/api/inventory/crypto-report')
    call('get', '/api/inventory/config')
    call('post', '/api/inventory/config', body={})
    # 400, and nothing saved: the valid section before the refused one is not applied (#1109)
    call('post', '/api/inventory/config',
         body={'ct_monitoring': {'domains': ['unsaved.example.test']},
               'domain_registration': {'extra_domains': ['example.test']}})
    call('post', '/api/inventory/config',
         body={'ct_monitoring': {'domains': ['ct.example.test']}, 'dns_resolver': {'nameservers': ['192.0.2.53']},
               'domain_registration': {'extra_domains': ['example.com']},
               'domain_health': {'extra_domains': ['example.com']}})
    call('get', '/api/inventory/config')
    call('post', '/api/inventory/config',
         body={'discovery': {'enabled': True, 'allow_private': True,
                             'endpoints': [f'127.0.0.1:{plan.world.port}', f'{DOMAIN}:443']}})
    call('post', '/api/inventory/scan', body={})                                            # one found, one sealed
    call('get', '/api/inventory')
    call('post', '/api/inventory/config', body={'discovery': {'enabled': False}})
    adopt, forget = plan.world.discovered
    call('get', '/api/inventory/<fingerprint>/adopt', path=f'/api/inventory/{adopt}/adopt')
    call('post', '/api/inventory/<fingerprint>/adopt', path=f'/api/inventory/{adopt}/adopt', body={})
    call('delete', '/api/inventory/<fingerprint>', path=f'/api/inventory/{forget}')
    call('delete', '/api/inventory/<fingerprint>', path=f'/api/inventory/{forget}')            # 404
    call('get', '/api/inventory/<fingerprint>/adopt', path='/api/inventory/0000/adopt')       # 404
    call('post', '/api/inventory/<fingerprint>/adopt', path='/api/inventory/0000/adopt', body={})


def backups(plan):
    call = plan.call
    call('get', '/api/backups')
    call('post', '/api/backups/create', body={})                                            # 400
    call('post', '/api/backups/create', body={'type': 'unified', 'reason': 'walk'})             # masked: share-safe
    _, made = call('post', '/api/backups/create',
                   body={'type': 'unified', 'reason': 'walk', 'include_secrets': True})
    name = _backup_name(plan, made)
    call('get', '/api/backups')
    if name:
        call('get', '/api/backups/download/<kind>/<filename>', path=f'/api/backups/download/unified/{name}',
             stream=True, keep=True)
        archive = plan.last_body
        call('post', '/api/backups/upload', data={'file': (io.BytesIO(archive or b''), 'uploaded-walk.zip')})
        call('post', '/api/backups/restore/<kind>', path='/api/backups/restore/unified',
             body={'filename': name, 'create_backup_before_restore': False})
        call('delete', '/api/backups/delete/<kind>/<filename>', path=f'/api/backups/delete/unified/{name}')
    call('post', '/api/backups/upload', data={})                                            # 400
    call('post', '/api/backups/upload', data={'file': (io.BytesIO(b'not a zip'), 'bad.zip')})
    call('post', '/api/backups/restore/<kind>', path='/api/backups/restore/unified', body={})   # 400
    call('post', '/api/backups/restore/<kind>', path='/api/backups/restore/unified',
         body={'filename': 'nope.zip'})
    call('get', '/api/backups/download/<kind>/<filename>', path='/api/backups/download/unified/nope.zip')
    call('delete', '/api/backups/delete/<kind>/<filename>', path='/api/backups/delete/unified/nope.zip')


def _backup_name(plan, made):
    created = (made or {}).get('backups') or []
    return created[0].get('filename') if created else None


def storage(plan):
    call = plan.call
    call('get', '/api/storage/info')
    call('post', '/api/storage/config', body={})                                            # 400
    call('post', '/api/storage/config', body={'backend': 'local_filesystem'})
    call('post', '/api/storage/test', body={})                                              # 400
    call('post', '/api/storage/test', body={'backend': 'local_filesystem', 'config': {}})
    call('post', '/api/storage/test',
         body={'backend': 's3_compatible',
               'config': {'endpoint_url': 'https://s3.example.test', 'bucket': 'walk',
                          'access_key_id': 'a' * 20, 'secret_access_key': 'b' * 40}})       # sealed
    call('post', '/api/storage/migrate', body={})                                           # 400
    call('post', '/api/storage/migrate',
         body={'source_backend': 'local_filesystem', 'target_backend': 'local_filesystem', 'target_config': {}})
    call('post', '/api/storage/azure-keyvault/backfill-certificates', body={})              # 400: not that backend


def settings(plan):
    call = plan.call
    call('get', '/api/diagnostics/snapshot')                          # last: the audit trail has entries by now
    call('get', '/api/settings')
    call('get', '/api/settings/dns-providers')
    call('post', '/api/settings', body={'auto_renew': True})
    call('post', '/api/settings/test-ca-provider', body={})                                 # 400
    call('post', '/api/settings/test-ca-provider',
         body={'ca_provider': 'letsencrypt', 'config': {}})                                  # sealed
    call('post', '/api/settings/test-ca-provider',
         body={'ca_provider': 'no-such-ca', 'config': {}})

