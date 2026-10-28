import unittest

from core import Event, assess, normalize_time, sha256, sniff_timestamp


class CoreTests(unittest.TestCase):
    def test_normalize_naive_timestamp_assumes_utc8(self):
        self.assertEqual(normalize_time("2026-10-26 12:34:56"), "2026-10-26T12:34:56+08:00")

    def test_normalize_utc_timestamp_converts_to_utc8(self):
        self.assertEqual(normalize_time("2026-10-26T04:34:56Z"), "2026-10-26T12:34:56+08:00")

    def test_sniff_syslog_timestamp(self):
        self.assertEqual(sniff_timestamp("Oct 26 12:34:56 2026 php-cgi.exe cmd.exe"), "2026-10-26T12:34:56+08:00")

    def test_sha256_is_stable(self):
        self.assertEqual(sha256(b"evidence"), sha256(b"evidence"))
        self.assertNotEqual(sha256(b"evidence"), sha256(b"different"))

    def test_encoded_powershell_generates_finding(self):
        payload = "powershell.exe -EncodedCommand " + "A" * 32
        events = [Event("", "security.log", "LOG", "line[10]", message=payload, raw=payload)]
        self.assertTrue(any(f.rule_id == "WIN-POWERSHELL-ENC" for f in assess(events)))

    def test_web_shell_child_shell_generates_critical_finding(self):
        payload = "php-cgi.exe spawned cmd.exe /c powershell"
        events = [Event("", "process.csv", "CSV", "row[2]", message=payload, raw=payload)]
        self.assertTrue(any(f.rule_id == "WEB-SHELL-CHILDPROC" and f.severity == "CRITICAL" for f in assess(events)))

    def test_no_finding_for_unmatched_benign_event(self):
        events = [Event("", "app.log", "LOG", "line[1]", message="Application started normally", raw="Application started normally")]
        self.assertEqual(assess(events), [])


if __name__ == "__main__":
    unittest.main()
