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


def test_s3_total_bytes_sums_all_pages(monkeypatch):
    from app import main

    class PagedStorage:
        def __init__(self):
            self.requests = []

        def list_objects_v2(self, **kwargs):
            self.requests.append(kwargs.copy())
            if "ContinuationToken" not in kwargs:
                return {
                    "Contents": [{"Size": 12}, {"Size": 30}],
                    "IsTruncated": True,
                    "NextContinuationToken": "page-2",
                }
            return {"Contents": [{"Size": 8}], "IsTruncated": False}

    client = PagedStorage()
    monkeypatch.setattr(main, "s3_client", lambda: client)

    assert main.s3_total_bytes() == 50
    assert len(client.requests) == 2
    assert client.requests[1]["ContinuationToken"] == "page-2"


def test_s3_total_bytes_fails_closed_if_truncated_listing_has_no_token(monkeypatch):
    from app import main

    class BrokenPagination:
        def list_objects_v2(self, **_kwargs):
            return {"Contents": [{"Size": 12}], "IsTruncated": True}

    monkeypatch.setattr(main, "s3_client", lambda: BrokenPagination())

    with pytest.raises(RuntimeError, match="without a continuation token"):
        main.s3_total_bytes()
