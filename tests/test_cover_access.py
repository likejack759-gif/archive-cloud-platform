import unittest
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

from app import main


class FakeConnection:
    def __init__(self, resource):
        self.resource = resource

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, query, params):
        return self

    def fetchone(self):
        return self.resource


def make_request():
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/covers/covers/test.png",
        "headers": [],
        "session": {},
    }
    return Request(scope)


class CoverAccessTests(unittest.TestCase):
    def setUp(self):
        self.filename = "covers/test.png"
        self.resource = {"user_id": 7, "status": "pending"}
        self.connection = FakeConnection(self.resource)
        self.db_patch = patch.object(main, "db_connect", return_value=self.connection)
        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        self.stream_patch = patch.object(main, "stream_s3_object", return_value="streamed")
        self.stream = self.stream_patch.start()
        self.addCleanup(self.stream_patch.stop)

    def call_cover(self, user):
        with patch.object(main, "current_user", return_value=user):
            return main.cover_file(make_request(), self.filename)

    def test_anonymous_user_is_denied(self):
        with self.assertRaises(HTTPException) as raised:
            self.call_cover(None)
        self.assertEqual(raised.exception.status_code, 401)
        self.stream.assert_not_called()

    def test_owner_can_view_own_pending_cover(self):
        response = self.call_cover({"id": 7, "role": "user"})
        self.assertEqual(response, "streamed")
        self.stream.assert_called_once()

    def test_other_user_cannot_view_pending_cover(self):
        with self.assertRaises(HTTPException) as raised:
            self.call_cover({"id": 8, "role": "user"})
        self.assertEqual(raised.exception.status_code, 404)
        self.stream.assert_not_called()

    def test_admin_can_view_pending_cover(self):
        response = self.call_cover({"id": 99, "role": "admin"})
        self.assertEqual(response, "streamed")
        self.stream.assert_called_once()

    def test_logged_in_user_can_view_approved_cover(self):
        self.resource["status"] = "approved"
        response = self.call_cover({"id": 8, "role": "user"})
        self.assertEqual(response, "streamed")
        self.stream.assert_called_once()

    def test_other_user_cannot_view_rejected_cover(self):
        self.resource["status"] = "rejected"
        with self.assertRaises(HTTPException) as raised:
            self.call_cover({"id": 8, "role": "user"})
        self.assertEqual(raised.exception.status_code, 404)
        self.stream.assert_not_called()


if __name__ == "__main__":
    unittest.main()
