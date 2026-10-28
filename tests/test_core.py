import unittest

from app import Event, assess, normalize_time, sha256


class CoreTests(unittest.TestCase):
    def test_normalize_naive_timestamp_assumes_utc8(self):
        self.assertEqual(normalize_time("2026-10-26 12:34:56"), "2026-10-26T12:34:56+08:00")

    def test_normalize_utc_timestamp_converts_to_utc8(self):
        self.assertEqual(normalize_time("2026-10-26T04:34:56Z"), "2026-10-26T12:34:56+08:00")

    def test_sha256_is_stable(self):
        self.assertEqual(sha256(b"evidence"), sha256(b"evidence"))
        self.assertNotEqual(sha256(b"evidence"), sha256(b"different"))

    def test_powershell_encoded_command_generates_finding(self):
        event = Event(
            timestamp="2026-10-26T12:34:56+08:00",
            source_file="security.log",
            source_type="LOG",
            location="line[10]",
            message="powershell.exe -EncodedCommand " + "A" * 32,
            raw="powershell.exe -EncodedCommand " + "A" * 32,
        )
        findings = assess([event])
        self.assertTrue(any(f.rule_id == "WIN-POWERSHELL-ENC" for f in findings))

    def test_web_server_child_shell_generates_critical_finding(self):
        event = Event(
            timestamp="2026-10-26T12:34:56+08:00",
            source_file="process.csv",
            source_type="CSV",
            location="row[2]",
            message="php-cgi.exe spawned cmd.exe /c powershell",
            raw="php-cgi.exe spawned cmd.exe /c powershell",
        )
        findings = assess([event])
        self.assertTrue(any(f.rule_id == "WEB-SHELL-CHILDPROC" and f.severity == "CRITICAL" for f in findings))

    def test_no_finding_for_unmatched_benign_event(self):
        event = Event(timestamp="", source_file="app.log", source_type="LOG", location="line[1]", message="Application started normally", raw="Application started normally")
        self.assertEqual(assess([event]), [])


if __name__ == "__main__":
    unittest.main()
