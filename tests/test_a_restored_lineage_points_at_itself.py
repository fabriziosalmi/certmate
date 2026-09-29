"""A lineage restored into another directory must point at itself.

certbot writes absolute paths into renewal/<domain>.conf: archive_dir, the four
live/ files, and config_dir / work_dir / logs_dir. A backup restored into a
different directory (CERTMATE_CERT_DIR changed, bare metal moved into the
container, a second install on the same host) keeps the ORIGINAL install's
paths. Measured on 2026-09-29 (#966): certbot on the restored instance then
evaluated the other install's lineage, answered for THAT certificate, and
would have renewed THOSE files; where the old path no longer exists it is a
parse failure every night instead.
"""
import pytest

from modules.core.utils import repair_certbot_renewal_paths

pytestmark = [pytest.mark.unit]

DOMAIN = 'app.example.com'


def _conf(old_domain_dir, domain=DOMAIN):
    return (
        "# renew_before_expiry = 30 days\n"
        "version = 2.10.0\n"
        f"archive_dir = {old_domain_dir}/archive/{domain}\n"
        f"cert = {old_domain_dir}/live/{domain}/cert.pem\n"
        f"privkey = {old_domain_dir}/live/{domain}/privkey.pem\n"
        f"chain = {old_domain_dir}/live/{domain}/chain.pem\n"
        f"fullchain = {old_domain_dir}/live/{domain}/fullchain.pem\n"
        "\n"
        "[renewalparams]\n"
        "account = bb1fe145531485a717be791f407ad123\n"
        f"config_dir = {old_domain_dir}\n"
        f"work_dir = {old_domain_dir}/work\n"
        f"logs_dir = {old_domain_dir}/logs\n"
        "server = https://acme-staging-v02.api.letsencrypt.org/directory\n"
        "authenticator = dns-cloudflare\n"
        "dns_cloudflare_credentials = letsencrypt/config/cloudflare-60f0c45e2bc0b57a.ini\n"
    )


def _lineage(tmp_path, conf_text, domain=DOMAIN):
    domain_dir = tmp_path / 'new' / 'certificates' / domain
    (domain_dir / 'renewal').mkdir(parents=True)
    (domain_dir / 'archive' / domain).mkdir(parents=True)
    conf = domain_dir / 'renewal' / f'{domain}.conf'
    conf.write_text(conf_text)
    return domain_dir, conf


def test_a_lineage_from_another_directory_is_rewritten_to_this_one(tmp_path):
    """THE regression."""
    old = '/srv/old-install/certificates/' + DOMAIN
    domain_dir, conf = _lineage(tmp_path, _conf(old))

    assert repair_certbot_renewal_paths(domain_dir, DOMAIN) is True

    text = conf.read_text()
    assert old not in text, 'a path of the other install survived'
    new = str(domain_dir)
    for line in (f"archive_dir = {new}/archive/{DOMAIN}",
                 f"cert = {new}/live/{DOMAIN}/cert.pem",
                 f"privkey = {new}/live/{DOMAIN}/privkey.pem",
                 f"config_dir = {new}",
                 f"work_dir = {new}/work",
                 f"logs_dir = {new}/logs"):
        assert line in text.splitlines(), line


def test_everything_else_is_left_exactly_as_it_was(tmp_path):
    """Only the lines that name the old directory change. The comment, the
    account, the server, the relative credentials path: byte for byte."""
    old = '/srv/old-install/certificates/' + DOMAIN
    domain_dir, conf = _lineage(tmp_path, _conf(old))

    repair_certbot_renewal_paths(domain_dir, DOMAIN)

    before = [ln for ln in _conf(old).splitlines() if old not in ln]
    after = [ln for ln in conf.read_text().splitlines() if str(domain_dir) not in ln]
    assert after == before


def test_a_lineage_that_already_points_here_is_not_touched(tmp_path):
    """CONTROL. The everyday case: no rewrite, no write at all."""
    domain_dir, conf = _lineage(tmp_path, '')
    conf.write_text(_conf(str(domain_dir)))
    mtime = conf.stat().st_mtime_ns

    assert repair_certbot_renewal_paths(domain_dir, DOMAIN) is False
    assert conf.stat().st_mtime_ns == mtime


def test_a_conf_of_an_unexpected_shape_is_not_guessed_at(tmp_path):
    """CONTROL on safety. When archive_dir is not <dir>/<domain>/archive/<domain>
    there is no old directory that can be named with confidence, so nothing
    is rewritten; certbot's own error is better than a guessed repair."""
    domain_dir, conf = _lineage(tmp_path, '')
    odd = _conf('/srv/x/' + DOMAIN).replace(
        f'archive_dir = /srv/x/{DOMAIN}/archive/{DOMAIN}',
        'archive_dir = /somewhere/else/entirely')
    conf.write_text(odd)

    assert repair_certbot_renewal_paths(domain_dir, DOMAIN) is False
    assert conf.read_text() == odd


def test_a_hostile_domain_name_is_refused(tmp_path):
    """The domain reaches restore callers from ZIP entry names."""
    assert repair_certbot_renewal_paths(tmp_path, '../../etc') is False


# --- wired where it has to run -------------------------------------------

def test_a_backup_restored_elsewhere_points_at_its_new_home(tmp_path):
    """Through the real backup and restore, into a different directory. This
    is the path the migration took in #966's measurement."""
    import os

    from modules.core.file_operations import FileOperations

    src = [tmp_path / 'src' / n for n in ('certificates', 'data', 'backups', 'logs')]
    for d in src:
        d.mkdir(parents=True)
    ops = FileOperations(*src)
    dom = src[0] / DOMAIN
    live, archive = dom / 'live' / DOMAIN, dom / 'archive' / DOMAIN
    for d in (live, archive, dom / 'renewal'):
        d.mkdir(parents=True)
    (dom / 'renewal' / f'{DOMAIN}.conf').write_text(_conf(str(dom)))
    for stem in ('cert', 'chain', 'fullchain', 'privkey'):
        (archive / f'{stem}1.pem').write_text(stem)
        (live / f'{stem}.pem').symlink_to(os.path.relpath(archive / f'{stem}1.pem', live))
        (dom / f'{stem}.pem').write_text(stem)

    name = ops.create_unified_backup({'domains': [DOMAIN]}, 'test', include_secrets=True)

    dst = [tmp_path / 'dst' / n for n in ('certificates', 'data', 'backups', 'logs')]
    for d in dst:
        d.mkdir(parents=True)
    assert FileOperations(*dst).restore_unified_backup(
        str(src[2] / 'unified' / name)) is True

    conf = (dst[0] / DOMAIN / 'renewal' / f'{DOMAIN}.conf').read_text()
    assert str(dom) not in conf, 'the restored conf still names the source install'
    assert f'archive_dir = {dst[0] / DOMAIN}/archive/{DOMAIN}' in conf.splitlines()


def test_the_renewal_path_repairs_the_conf_before_certbot_reads_it():
    """Instances already restored by an older version carry the old paths on
    disk and heal at their next renewal (measured end to end in #966). Read
    off the source because the ordering is the property: after certbot has
    parsed the conf, a repair is too late."""
    import inspect

    from modules.core.certificates import CertificateManager

    source = inspect.getsource(CertificateManager.renew_certificate)
    repair = source.index('repair_certbot_renewal_paths(')
    symlinks = source.index('repair_certbot_lineage_symlinks(')
    certbot = source.index("'certbot', 'renew'")
    assert repair < symlinks < certbot


def test_a_look_alike_archive_dir_is_not_mistaken_for_one(tmp_path):
    """The suffix check is not redundant with the directory-name check. An
    archive_dir whose tail is the right LENGTH but not `/archive/<domain>`
    slices down to a prefix that does end in the domain, so only the suffix
    check stops a rewrite built on a misread directory."""
    suffix_len = len(f'/archive/{DOMAIN}')
    look_alike = f'/srv/x/{DOMAIN}/' + 'Z' * (suffix_len - 1)
    domain_dir, conf = _lineage(tmp_path, '')
    text = _conf(f'/srv/x/{DOMAIN}').replace(
        f'archive_dir = /srv/x/{DOMAIN}/archive/{DOMAIN}', f'archive_dir = {look_alike}')
    conf.write_text(text)

    assert repair_certbot_renewal_paths(domain_dir, DOMAIN) is False
    assert conf.read_text() == text
