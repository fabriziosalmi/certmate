"""Domain-to-path validation for the API layer.

The rules moved to ``modules/core/domain_paths`` (#672), where ``web`` and the
storage backends can reach them too — they had their own copies, and one of
those copies still carried a defect this one had already fixed.

Re-exported rather than rewritten at thirteen call sites: the names here are
what the endpoints import.
"""
from ..core.domain_paths import (  # noqa: F401
    DOMAIN_RE,
    is_path_safe_segment,
    validate_domain_path,
)
