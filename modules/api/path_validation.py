"""Domain-to-path validation for the API layer.

The rules moved to ``modules/core/domain_paths`` (#672), where ``web`` and the
storage backends can reach them too — they had their own copies, and one of
those copies still carried a defect this one had already fixed.

Re-exported rather than rewritten at thirteen call sites: the names here are
what the endpoints import.
"""
from ..core.domain_paths import (
    DOMAIN_RE,
    is_path_safe_segment,
    validate_domain_path,
)

# What the endpoints import from here. Explicit, so a re-export is a statement and not an accident:
# mypy (no_implicit_reexport, which mypy.ini holds this module to) and ruff both read it from here.
__all__ = ['DOMAIN_RE', 'is_path_safe_segment', 'validate_domain_path']
