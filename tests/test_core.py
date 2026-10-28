import unittest
import xml.etree.ElementTree as ET

from core import Event, assess, build_case_assessment, normalize_time, sha256, sniff_timestamp, xml_event_to_event


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

    def test_sysmon_xml_named_eventdata_fields_are_parsed(self):
        xml = ET.fromstring("""<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><TimeCreated SystemTime="2026-10-26T04:34:56.000Z"/><Computer>host01</Computer></System><EventData><Data Name="Image">C:\\Windows\\System32\\powershell.exe</Data><Data Name="CommandLine">powershell.exe -EncodedCommand ABCDEFGHIJKLMNOPQRSTUVWXYZ123456</Data><Data Name="ParentImage">C:\\Windows\\System32\\cmd.exe</Data></EventData></Event>""")
        event = xml_event_to_event(xml, "Microsoft-Windows-Sysmon%4Operational.evtx", "digest", 1)
        self.assertEqual(event.source_type, "SYSMON")
        self.assertEqual(event.event_id, "1")
        self.assertEqual(event.timestamp, "2026-10-26T12:34:56+08:00")
        self.assertIn("CommandLine=powershell.exe", event.message)
        self.assertIn("Image=C:\\Windows\\System32\\powershell.exe", event.message)

    def test_sysmon_event_8_creates_dedicated_finding(self):
        event = Event("2026-10-26T12:34:56+08:00", "sysmon.evtx", "SYSMON", "record[8]", event_id="8", provider="Microsoft-Windows-Sysmon", message="SourceImage=source.exe | TargetImage=target.exe", raw="Sysmon EventID 8")
        self.assertTrue(any(f.rule_id == "SYSMON-EID-8" and f.severity == "HIGH" for f in assess([event])))

    def test_sysmon_event_25_creates_dedicated_finding(self):
        event = Event("", "sysmon.evtx", "SYSMON", "record[25]", event_id="25", provider="Microsoft-Windows-Sysmon", message="Image=unknown.exe", raw="ProcessTampering")
        self.assertTrue(any(f.rule_id == "SYSMON-EID-25" for f in assess([event])))

    def test_no_finding_for_unmatched_benign_event(self):
        events = [Event("", "app.log", "LOG", "line[1]", message="Application started normally", raw="Application started normally")]
        self.assertEqual(assess(events), [])

    def test_case_assessment_reports_rule_matches_and_limits_conclusion(self):
        events = [
            Event("2026-10-26T12:34:56+08:00", "web.log", "LOG", "line[1]", message="php-cgi.exe spawned cmd.exe /c powershell", raw="php-cgi.exe spawned cmd.exe /c powershell"),
            Event("2026-10-26T12:35:00+08:00", "sysmon.evtx", "SYSMON", "record[2]", event_id="8", provider="Microsoft-Windows-Sysmon", message="CreateRemoteThread", raw="CreateRemoteThread"),
        ]
        findings = assess(events)
        summary = build_case_assessment(events, findings)
        self.assertIn("indicators present", summary["activity_level"])
        self.assertIn("do not independently establish", summary["assessment"])
        self.assertEqual(len(summary["facts"]), 4)
        self.assertTrue(summary["analyst_attention"])

    def test_case_assessment_without_matches_does_not_claim_benign_activity(self):
        events = [Event("", "app.log", "LOG", "line[1]", message="Application started normally", raw="Application started normally")]
        summary = build_case_assessment(events, assess(events))
        self.assertEqual(summary["activity_level"], "No enabled-rule matches")
        self.assertIn("not evidence that all activity was benign", summary["assessment"])
        self.assertEqual(summary["confidence"], "Limited")


if __name__ == "__main__":
    unittest.main()
