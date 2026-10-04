"""A certificate's paths are built in one place (#854, step 1: #1146).

Every path to a server certificate's files was built from its domain where it
was needed: `self.cert_dir / domain`, `domain_dir / 'live' / domain`,
`f'{domain}.conf'`, about sixty times in eleven files. That is fine while a
certificate's identity is its domain. The day it is not (a public and a
private certificate for one hostname, #854), every one of those places has to
agree on the answer, and the only way to know they do is for there to be one.

So the layout lives in `modules/core/domain_paths.py` (`certificate_dir`,
`certificate_file`, `lineage_live_dir`, `lineage_archive_dir`,
`renewal_conf`), and this refuses a path built from the identity anywhere else
in `modules/`. "Built from the identity" means: a `/` join or an
`os.path.join` / `Path(...)` call whose operand is a variable or attribute
named like one (`domain`, `primary_domain`, `cert_name`, `lineage`), or an
f-string that interpolates one.
"""
import ast
import pathlib

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
HOME = 'modules/core/domain_paths.py'
IDENTITY = frozenset({'domain', 'primary_domain', 'cert_name', 'lineage'})


def _is_identity(node):
    return ((isinstance(node, ast.Name) and node.id in IDENTITY)
            or (isinstance(node, ast.Attribute) and node.attr in IDENTITY))


def _interpolates_identity(node):
    return isinstance(node, ast.JoinedStr) and any(_is_identity(n) for n in ast.walk(node))


def paths_built_from_the_identity(source, filename='<source>'):
    """`(line, code)` for every path built from the identity in `source`."""
    found = []
    for node in ast.walk(ast.parse(source, filename)):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            if _is_identity(node.right) or _interpolates_identity(node.right):
                found.append((node.lineno, ast.unparse(node)))
        elif isinstance(node, ast.Call) and ast.unparse(node.func) in ('os.path.join', 'Path', 'pathlib.Path'):
            if any(_is_identity(arg) or _interpolates_identity(arg) for arg in node.args[1:]):
                found.append((node.lineno, ast.unparse(node)))
    return found


def test_no_certificate_path_is_built_outside_its_home():
    offenders = []
    for path in sorted((REPO / 'modules').rglob('*.py')):
        relative = str(path.relative_to(REPO))
        if relative == HOME:
            continue
        for line, code in paths_built_from_the_identity(path.read_text(encoding='utf-8'), relative):
            offenders.append(f'{relative}:{line}  {code}')
    assert not offenders, (
        'a certificate path built from its identity outside domain_paths.py; '
        'use certificate_dir / certificate_file / lineage_live_dir / '
        'lineage_archive_dir / renewal_conf:\n  ' + '\n  '.join(offenders))


@pytest.mark.parametrize('code', [
    "p = self.cert_dir / domain / 'cert.pem'",
    "p = domain_dir / 'live' / domain",
    "p = base / 'renewal' / f'{domain}.conf'",
    "p = os.path.join(cert_dir, domain, 'metadata.json')",
    "p = Path(cert_dir, primary_domain)",
    "p = Path('archive') / cert_name",
])
def test_the_shapes_it_exists_for_are_found(code):
    """NEGATIVE CONTROL: without these, the test above passes as well against a
    scanner that finds nothing."""
    assert paths_built_from_the_identity(code)


@pytest.mark.parametrize('code', [
    "p = certificate_dir(self.cert_dir, domain) / 'cert.pem'",
    "p = domain_dir / name",           # `name` here is a file name
    "p = self.cert_dir / 'ca' / 'ca.key'",
])
def test_what_is_not_built_from_the_identity_is_left_alone(code):
    assert paths_built_from_the_identity(code) == []


def test_the_home_builds_them():
    """CONTROL: the home itself joins the name, so the scanner sees it there."""
    home = (REPO / HOME).read_text(encoding='utf-8')
    assert 'def certificate_dir(' in home and 'def renewal_conf(' in home
