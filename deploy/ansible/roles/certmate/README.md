# Ansible role: certmate

Deploys [CertMate](https://github.com/fabriziosalmi/certmate) with its production Docker Compose bundle. It installs Docker when missing, writes `/srv/certmate/.env` from your variables (mode 600), starts CertMate and waits until it answers.

It uses only `ansible.builtin` modules, so it depends on no other collection.

## Install

It ships in the `fabriziosalmi.certmate` collection on Ansible Galaxy:

```bash
ansible-galaxy collection install fabriziosalmi.certmate
```

and is used as `fabriziosalmi.certmate.certmate`.

## Variables

| Variable | Default | |
| --- | --- | --- |
| `certmate_api_token` | *(required)* | at least 32 characters; keep it in Ansible Vault |
| `certmate_secret_key` | *(required)* | at least 32 characters; keep it in Ansible Vault |
| `certmate_backup_passphrase` | `""` | without it, automatic backups cannot restore the instance |
| `certmate_cloudflare_token` | `""` | bootstraps a Cloudflare DNS account on first start |
| `certmate_bind` / `certmate_port` | `127.0.0.1` / `8000` | where CertMate listens on the host |
| `certmate_behind_proxy` | `false` | `true` behind a trusted reverse proxy |
| `certmate_version` | `""` | an image version; empty keeps the one the bundle pins |
| `certmate_bundle_ref` | `main` | Git ref of `deploy/docker-compose.yml` |
| `certmate_dir` | `/srv/certmate` | |
| `certmate_install_docker` | `true` | install Docker Engine when `docker compose` is missing |

Generate each secret with `openssl rand -hex 32`.

## Example

```yaml
- hosts: certmate
  become: true
  roles:
    - role: fabriziosalmi.certmate.certmate
      vars:
        certmate_api_token: "{{ vault_certmate_api_token }}"
        certmate_secret_key: "{{ vault_certmate_secret_key }}"
        certmate_backup_passphrase: "{{ vault_certmate_backup_passphrase }}"
```

Changing a secret or the bundle recreates the container once. A run that changes nothing reports `changed=0`.

Verified against a fresh Debian 13 host: Docker installed by the role, CertMate healthy, token 200 and anonymous 401, loopback only, `.env` 600, `changed=0` on the second run, a token rotation applied with a single recreate, missing secrets refused, and healthy after a reboot.
