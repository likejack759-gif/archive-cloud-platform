"""Hard platform-wide object-storage quota helpers."""

# Binary GiB: 5 * 1024**3 bytes.
MAX_STORAGE_BYTES = 5 * 1024**3


def would_exceed_quota(current_bytes: int, incoming_bytes: int, quota_bytes: int = MAX_STORAGE_BYTES) -> bool:
    """Return True if a proposed upload would exceed the configured quota.

    The exact limit is allowed; only a total greater than the limit is rejected.
    """
    if current_bytes < 0 or incoming_bytes < 0 or quota_bytes < 0:
        raise ValueError("Storage byte counts must not be negative")
    return current_bytes + incoming_bytes > quota_bytes
