import unittest

from server import parse_upload


class ServerParserTests(unittest.TestCase):
    def test_csv_upload_normalizes_rows(self):
        events = parse_upload(
            "events.csv",
            b"TimeCreated,EventID,Computer,Message\n2026-10-28T04:00:00Z,4625,host01,logon failure\n",
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].source_type, "CSV")
        self.assertEqual(events[0].event_id, "4625")
        self.assertEqual(events[0].host, "host01")
        self.assertIn("logon failure", events[0].message)

    def test_text_upload_preserves_line_location(self):
        events = parse_upload("server.log", b"2026-10-28 12:30:00 ERROR php-cgi.exe spawned cmd.exe\n\n")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].location, "line[1]")
        self.assertIn("php-cgi.exe", events[0].message)

    def test_json_upload_normalizes_event_array(self):
        events = parse_upload(
            "events.json",
            b'[{"EventID":4688,"TimeCreated":"2026-10-28T04:00:00Z","Computer":"host01","Message":"powershell.exe spawned"}]',
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].source_type, "JSON")
        self.assertEqual(events[0].event_id, "4688")
        self.assertEqual(events[0].host, "host01")
        self.assertIn("powershell.exe", events[0].message)

    def test_json_upload_flattens_nested_windows_event(self):
        events = parse_upload(
            "nested.json",
            b'{"events":[{"System":{"EventID":4625,"Computer":"host02","TimeCreated":{"SystemTime":"2026-10-28T04:00:00Z"}},"EventData":{"TargetUserName":"alice","Message":"logon failure"}}]}',
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_id, "4625")
        self.assertEqual(events[0].host, "host02")
        self.assertEqual(events[0].user, "alice")

    def test_json_upload_rejects_non_object_array_items(self):
        with self.assertRaises(ValueError):
            parse_upload("events.json", b'[{"EventID":4625}, 7]')

    def test_rejects_unsupported_file_type(self):
        with self.assertRaises(ValueError):
            parse_upload("sample.exe", b"not a log")


if __name__ == "__main__":
    unittest.main()
