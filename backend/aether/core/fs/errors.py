"""Fail-closed error vocabulary for filesystem capabilities.

Every rejection carries a stable machine-readable ``reason_code``. Reason codes
are part of the security contract: callers and tests assert on them, and the
audit trail records them verbatim. Adding a code is safe; changing the meaning
of an existing one is not.
"""

from __future__ import annotations

from typing import Final

# --- Path / identity -------------------------------------------------------
PATH_UNSAFE: Final = "fs_path_unsafe"
RESOURCE_NOT_REGISTERED: Final = "fs_resource_not_registered"
RESOURCE_NOT_FOUND: Final = "fs_resource_not_found"
RESOURCE_VERSION_CHANGED: Final = "fs_resource_version_changed"
RESOURCE_IDENTITY_CHANGED: Final = "fs_resource_identity_changed"
UNSUPPORTED_RESOURCE_TYPE: Final = "fs_unsupported_resource_type"
UNSUPPORTED_FILESYSTEM: Final = "fs_unsupported_filesystem"
HARD_LINK_DENIED: Final = "fs_hard_link_denied"
REPARSE_ESCAPE_DENIED: Final = "fs_reparse_escape_denied"

# --- Scope / policy -------------------------------------------------------
OUTSIDE_ALLOWED_ROOT: Final = "fs_outside_allowed_root"
CAPABILITY_OUTSIDE_ROOT_SCOPE: Final = "fs_capability_outside_root_scope"
PROTECTED_PATH_DENIED: Final = "fs_protected_path_denied"
SENSITIVE_CONTENT_DENIED: Final = "fs_sensitive_content_denied"
SECRET_CLASS_DENIED: Final = "fs_secret_class_denied"
NETWORK_VOLUME_DENIED: Final = "fs_network_volume_denied"
REMOVABLE_VOLUME_DENIED: Final = "fs_removable_volume_denied"
POLICY_DENIED: Final = "fs_policy_denied"

# --- Content --------------------------------------------------------------
BINARY_CONTENT_DENIED: Final = "fs_binary_content_denied"
INVALID_ENCODING: Final = "fs_invalid_encoding"
CONTENT_TOO_LARGE: Final = "fs_content_too_large"
READ_TRUNCATED: Final = "fs_read_truncated"

# --- Search ---------------------------------------------------------------
SEARCH_QUERY_INVALID: Final = "fs_search_query_invalid"
SEARCH_LIMIT_EXCEEDED: Final = "fs_search_limit_exceeded"
SEARCH_DEPTH_EXCEEDED: Final = "fs_search_depth_exceeded"
SEARCH_OUTPUT_EXCEEDED: Final = "fs_search_output_exceeded"
SEARCH_CANCELLED: Final = "fs_search_cancelled"
SEARCH_TIMEOUT: Final = "fs_search_timeout"

# --- Open -----------------------------------------------------------------
OPEN_UNSUPPORTED_TARGET: Final = "fs_open_unsupported_target"
OPEN_FAILED: Final = "fs_open_failed"

# --- Integrity -----------------------------------------------------------
INTEGRITY_CHECK_FAILED: Final = "fs_integrity_check_failed"
NOT_AUTHORIZED: Final = "fs_not_authorized"

__all__ = [name for name in dir() if name.isupper()]
