"""The source of the renewal path, however many methods it is spread over.

Two tests asserted a contract by grepping `inspect.getsource(
CertificateManager.renew_certificate)` — that create and renew share one
storage implementation, and that both return the keys the route reads. Both
assertions are still true, and both tests broke the moment #666 split that
390-line method into the four it delegates to.

That is the failure mode worth avoiding, not the broken test: a structural
assertion pinned to one function name stops covering anything as soon as the
code moves, and it does so by *passing* if the grep happens to still match
something. So this follows the delegation instead of naming the destination.

One level deep, deliberately. It answers "is this on the renewal path", and
the renewal path is `renew_certificate` plus what it calls on itself; going
further would pull in `_load_metadata`, `_write_pfx` and eventually most of
the class, and an assertion that matches most of the class is not an
assertion.
"""
import ast
import inspect
import textwrap

from modules.core.certificates import CertificateManager


def _self_calls(source):
    """The `self._x(...)` method names a piece of source calls."""
    names = set()
    # `textwrap.dedent`, not `inspect.cleandoc`: a method's source comes back
    # indented by four and cleandoc only normalises a docstring's shape, so
    # ast.parse got "expected an indented block after function definition".
    for node in ast.walk(ast.parse(textwrap.dedent(source))):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == 'self'):
            names.add(func.attr)
    return names


def renewal_path_source(entry='renew_certificate'):
    """`entry`'s source plus the source of every method it calls on self.

    Returns one string. Methods that do not exist on the class (a call on an
    injected collaborator, say) are skipped rather than raising, so this does
    not need a list of exceptions kept in step by hand.
    """
    root = inspect.getsource(getattr(CertificateManager, entry))
    parts = [root]
    for name in sorted(_self_calls(root)):
        attribute = getattr(CertificateManager, name, None)
        if attribute is None or not callable(attribute):
            continue
        try:
            parts.append(inspect.getsource(attribute))
        except (OSError, TypeError):      # pragma: no cover - builtins
            continue
    return '\n'.join(parts)
