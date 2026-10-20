import pytest

from app.storage_quota import MAX_STORAGE_BYTES, would_exceed_quota


def test_quota_allows_upload_that_fills_remaining_capacity_exactly():
    assert not would_exceed_quota(MAX_STORAGE_BYTES - 100, 100)


def test_quota_rejects_one_byte_over_capacity():
    assert would_exceed_quota(MAX_STORAGE_BYTES - 100, 101)


def test_quota_rejects_when_already_at_capacity():
    assert would_exceed_quota(MAX_STORAGE_BYTES, 1)


def test_quota_counts_archive_and_cover_together():
    current = MAX_STORAGE_BYTES - 1024
    assert not would_exceed_quota(current, 900 + 124)
    assert would_exceed_quota(current, 900 + 125)


@pytest.mark.parametrize(
    "current,incoming,quota",
    [(-1, 0, 10), (0, -1, 10), (0, 0, -1)],
)
def test_quota_rejects_invalid_negative_sizes(current, incoming, quota):
    with pytest.raises(ValueError):
        would_exceed_quota(current, incoming, quota)
