# fabriziosalmi.certmate

Ansible collection for [CertMate](https://github.com/fabriziosalmi/certmate), the self-hosted TLS certificate lifecycle manager.

## Roles

- `fabriziosalmi.certmate.certmate`: deploys CertMate with its production Docker Compose bundle. It installs Docker when missing, writes the secrets to a mode-600 `.env`, starts CertMate and waits until it answers. Variables and an example: [roles/certmate/README.md](https://github.com/fabriziosalmi/certmate/blob/main/deploy/ansible/roles/certmate/README.md).

## Install

```bash
ansible-galaxy collection install fabriziosalmi.certmate
```

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
