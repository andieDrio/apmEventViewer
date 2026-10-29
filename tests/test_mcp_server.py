import unittest

from mcp_server import _event_ref, _job_id


class MCPReferenceValidationTests(unittest.TestCase):
    def test_accepts_uuid_hex_investigation_id(self):
        self.assertEqual(_job_id("a" * 32), "a" * 32)

    def test_rejects_path_traversal_as_investigation_id(self):
        with self.assertRaises(ValueError):
            _job_id("../../README.md")

    def test_accepts_event_reference(self):
        self.assertEqual(_event_ref("ev-000042"), "EV-000042")

    def test_rejects_invalid_event_reference(self):
        with self.assertRaises(ValueError):
            _event_ref("EV-../../README.md")


if __name__ == "__main__":
    unittest.main()
