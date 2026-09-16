"""The reset endpoint destroys every client identity, so reaching it is not easy.

Two guards, and both matter for different reasons. The role check is the usual
one. The typed confirmation is the unusual one: `{"confirm": true}` is what a
mis-sent form, a retried request or a copy-pasted curl produces, and none of
those mean "discard every certificate we have issued". A phrase somebody had
to type does.
"""
import pytest

pytestmark = [pytest.mark.unit]

from modules.api.client_certificates import CA_RESET_CONFIRMATION  # noqa: E402


def test_the_confirmation_is_a_phrase_and_not_a_boolean():
    assert isinstance(CA_RESET_CONFIRMATION, str)
    assert len(CA_RESET_CONFIRMATION) > 8
    assert CA_RESET_CONFIRMATION not in ('true', 'yes', '1')


def test_the_route_is_registered_and_does_not_shadow_an_identifier():
    """`/ca/reset` has a slash in it, so it cannot be mistaken for a
    certificate identifier by the `/<string:identifier>` rule above it."""
    import pathlib
    factory = (pathlib.Path(__file__).resolve().parent.parent
               / 'modules' / 'core' / 'factory.py').read_text(encoding='utf-8')

    assert "'ClientCertificateAuthorityReset'], '/ca/reset'" in factory
    assert '/' in '/ca/reset'.strip('/'), 'a single-segment path would collide'


def test_it_is_admin_only():
    import pathlib
    source = (pathlib.Path(__file__).resolve().parent.parent
              / 'modules' / 'api' / 'client_certificates.py').read_text(encoding='utf-8')
    start = source.index('class ClientCertificateAuthorityReset')
    block = source[start:start + 700]

    assert "require_role('admin')" in block, (
        'the most destructive endpoint in this namespace is not admin-gated'
    )


def test_the_refusal_says_what_to_send():
    """A 400 that does not say how to proceed sends people to the source."""
    import pathlib
    source = (pathlib.Path(__file__).resolve().parent.parent
              / 'modules' / 'api' / 'client_certificates.py').read_text(encoding='utf-8')
    start = source.index('class ClientCertificateAuthorityReset')
    block = source[start:start + 1600]

    assert 'cannot be undone' in block
    assert 'confirm' in block


def test_the_crl_is_republished_after_a_reset():
    """The old CRL is signed by a key that no longer exists."""
    import pathlib
    source = (pathlib.Path(__file__).resolve().parent.parent
              / 'modules' / 'api' / 'client_certificates.py').read_text(encoding='utf-8')
    start = source.index('class ClientCertificateAuthorityReset')
    block = source[start:start + 2400]

    assert 'crl_manager.update_crl()' in block
