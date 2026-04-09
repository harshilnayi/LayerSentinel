from __future__ import annotations

import unittest
import uuid
import shutil
from pathlib import Path
from unittest.mock import patch

from rogue_device_detector.analyzer import analyze_devices
from rogue_device_detector.baseline import add_device, load_baseline, save_baseline
from rogue_device_detector.nmap_runner import build_nmap_command, parse_nmap_xml, run_nmap_scan
from rogue_device_detector.reporter import list_reports, write_reports


FIXTURE = Path(__file__).parent / "fixtures" / "sample_nmap.xml"


class RogueDeviceDetectorTests(unittest.TestCase):
    def test_xml_parser_extracts_hosts(self) -> None:
        devices = parse_nmap_xml(FIXTURE)
        self.assertEqual(len(devices), 2)
        self.assertEqual(devices[0].ip, "192.168.1.10")
        self.assertEqual(devices[1].hostname, "rogue-hotspot")

    def test_analysis_flags_unknown_and_suspicious_devices(self) -> None:
        temp_dir = Path(__file__).parent / "_tmp" / uuid.uuid4().hex
        temp_dir.mkdir(parents=True, exist_ok=True)
        try:
            baseline_path = temp_dir / "baseline.json"
            save_baseline([], baseline_path)
            add_device(
                name="Office Laptop",
                mac="A8:BB:CC:DD:EE:FF",
                ip="192.168.1.10",
                owner="Security",
                allowed_ports=[443],
                path=baseline_path,
            )

            devices = parse_nmap_xml(FIXTURE)
            baseline = load_baseline(baseline_path)
            analysis = analyze_devices(devices, baseline)

            self.assertEqual(analysis["summary"]["known"], 1)
            self.assertEqual(analysis["summary"]["suspicious"], 1)
            suspicious = next(
                item for item in analysis["findings"] if item["classification"] == "suspicious"
            )
            self.assertIn("Device not found in approved baseline.", suspicious["reasons"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_reporter_writes_csv_and_dashboard(self) -> None:
        temp_dir = Path(__file__).parent / "_tmp" / uuid.uuid4().hex
        temp_dir.mkdir(parents=True, exist_ok=True)
        try:
            devices = parse_nmap_xml(FIXTURE)
            analysis = analyze_devices(devices, [])
            json_path, markdown_path, csv_path, html_path = write_reports(analysis, temp_dir)

            self.assertTrue(json_path.exists())
            self.assertTrue(markdown_path.exists())
            self.assertTrue(csv_path.exists())
            self.assertTrue(html_path.exists())
            self.assertIn("classification,score,ip,mac", csv_path.read_text(encoding="utf-8"))
            self.assertIn("Network Findings Dashboard", html_path.read_text(encoding="utf-8"))
            self.assertEqual(list_reports(temp_dir)[0].name, json_path.name)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_build_nmap_command_keeps_xml_stdout_and_extra_args(self) -> None:
        command = build_nmap_command("192.168.1.0/24", extra_args=["-O", "-Pn"])

        self.assertEqual(command[0], "nmap")
        self.assertIn("-sV", command)
        self.assertIn("-O", command)
        self.assertIn("-Pn", command)
        self.assertEqual(command[-3:], ["-oX", "-", "192.168.1.0/24"])

    def test_run_nmap_scan_uses_built_command(self) -> None:
        xml_text = FIXTURE.read_text(encoding="utf-8")

        with patch("rogue_device_detector.nmap_runner.shutil.which", return_value="nmap"), patch(
            "rogue_device_detector.nmap_runner.subprocess.run"
        ) as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = xml_text
            mock_run.return_value.stderr = ""

            devices = run_nmap_scan("10.0.0.0/24", extra_args=["-Pn"])

        self.assertEqual(len(devices), 2)
        self.assertEqual(mock_run.call_args.args[0], ["nmap", "-sV", "-Pn", "-oX", "-", "10.0.0.0/24"])


if __name__ == "__main__":
    unittest.main()
