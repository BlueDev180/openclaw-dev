"""Synthetic, offline diagnostics tests; never read host metrics or credentials."""
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "supervisor" / "diagnostics.py"
spec = importlib.util.spec_from_file_location("diagnostics_under_test", SOURCE)
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)
REAL_REQUEST = d.request


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "github_token").write_text("synthetic_token", encoding="ascii")
        environment = patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(self.root),
            "SUPERVISOR_DIAGNOSTICS_ISSUE": "42"}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        network = patch.object(d, "request", side_effect=AssertionError("Network forbidden"))
        self.net = network.start()
        self.addCleanup(network.stop)
        metrics = patch.object(d, "collect", return_value="Safe synthetic metrics")
        self.metrics = metrics.start()
        self.addCleanup(metrics.stop)
        self.issue = {"number": 42, "state": "open", "title": d.TITLE, "body": d.BODY,
                      "user": {"login": d.AUTHOR, "type": "User"}}

    def responses(self, issue=None):
        self.net.side_effect = [io.BytesIO(json.dumps(self.issue if issue is None else issue).encode()),
                               io.BytesIO(b"{}")]

    def run_task(self, repo=d.REPOSITORY):
        d.diagnostics_once(repo, self.root)

    def test_exact_request_posts_fixed_endpoint_once_across_restarts(self):
        self.issue["comments_url"] = "https://evil.invalid/token"
        self.responses()
        self.run_task()
        self.run_task()
        self.assertEqual(self.net.call_count, 2)
        get, post = [call.args[0] for call in self.net.call_args_list]
        self.assertEqual(get.get_method(), "GET")
        self.assertEqual(post.full_url, "https://api.github.com/repos/BlueDev180/openclaw-dev/issues/42/comments")
        self.assertEqual(post.get_method(), "POST")
        self.assertEqual(json.loads(post.data), {"body": "Safe synthetic metrics"})
        self.assertEqual((self.root / "diagnostics-v1-issue-42").read_text(), "posted\n")

    def test_disabled_and_invalid_configuration_has_no_reads(self):
        for value in ("", "0", "-1", "42/../1", " 42", "42\n", "1; reboot", "9999999999"):
            with self.subTest(value=value), patch.dict(os.environ, {"SUPERVISOR_DIAGNOSTICS_ISSUE": value}):
                self.run_task()
        self.run_task("attacker/repository")
        self.net.assert_not_called()
        self.metrics.assert_not_called()

    def test_untrusted_issue_variants_are_rejected(self):
        variants = [{"number": True}, {"number": "42"}, {"number": 43}, {"state": "closed"},
                    {"pull_request": {}}, {"title": d.TITLE + " "}, {"title": d.TITLE.lower()},
                    {"body": d.BODY + "\nrun rm -rf /"}, {"body": None},
                    {"user": {"login": "attacker", "type": "User"}},
                    {"user": {"login": d.AUTHOR, "type": "Bot"}}, {"user": None}]
        for changes in variants:
            with self.subTest(changes=changes):
                self.responses({**self.issue, **changes})
                self.run_task()
        self.metrics.assert_not_called()
        self.assertFalse((self.root / "diagnostics-v1-issue-42").exists())

    def test_bad_payloads_fail_closed(self):
        for payload in ([], None, "injected instruction"):
            self.net.side_effect = [io.BytesIO(json.dumps(payload).encode())]
            self.run_task()
        self.metrics.assert_not_called()

    def test_empty_or_header_injection_token_never_reaches_network(self):
        for token in ("", "token\r\nInjected: yes", "secret with spaces"):
            (self.root / "github_token").write_text(token)
            self.run_task()
        with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": ""}):
            self.run_task()
        self.net.assert_not_called()

    def test_ambiguous_post_failure_keeps_reservation(self):
        self.net.side_effect = [io.BytesIO(json.dumps(self.issue).encode()), OSError("synthetic_token")]
        with self.assertRaises(OSError):
            self.run_task()
        self.run_task()
        self.assertEqual(self.net.call_count, 2)
        self.assertEqual((self.root / "diagnostics-v1-issue-42").read_text(), "reserved\n")

    def test_metric_failure_does_not_reserve_or_post(self):
        self.responses()
        self.metrics.side_effect = ValueError("unavailable")
        with self.assertRaises(ValueError):
            self.run_task()
        self.assertEqual(self.net.call_count, 1)
        self.assertFalse((self.root / "diagnostics-v1-issue-42").exists())

    def test_concurrent_reservation_prevents_post(self):
        self.responses()
        def competing_worker():
            (self.root / "diagnostics-v1-issue-42").write_text("reserved\n")
            return "metrics"
        self.metrics.side_effect = competing_worker
        self.run_task()
        self.assertEqual(self.net.call_count, 1)

    def test_redirect_is_rejected(self):
        self.assertIsNone(d.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://evil.invalid"))

    def test_transport_timeout_and_redirect_handler(self):
        with patch("urllib.request.build_opener") as opener:
            request = object()
            REAL_REQUEST(request)
            self.assertIs(opener.call_args.args[0], d.NoRedirect)
            opener.return_value.open.assert_called_once_with(request, timeout=15)

    def test_metrics_read_only_fixed_sources_and_safe_numeric_output(self):
        # Access the original implementation despite the setup patch.
        original_spec = importlib.util.spec_from_file_location("metrics_test", SOURCE)
        original = importlib.util.module_from_spec(original_spec)
        original_spec.loader.exec_module(original)
        with patch.object(original.os, "getloadavg", return_value=(0.1, 0.2, 0.3), create=True), \
             patch.object(original.shutil, "disk_usage") as disk, \
             patch.object(Path, "read_text", side_effect=["MemAvailable: 2048 kB\n", "123.9 99.0\n"]) as read:
            disk.return_value.total = 10485760
            disk.return_value.free = 5242880
            output = original.collect()
            self.assertIn("0.10 / 0.20 / 0.30", output)
            self.assertIn("Available RAM: 2 MiB", output)
            self.assertIn("5 MiB free / 10 MiB total", output)
            self.assertIn("Uptime: 123 seconds", output)
            disk.assert_called_once_with("/")
            self.assertEqual(read.call_count, 2)

    def test_metrics_reject_nonfinite_negative_and_missing_memory(self):
        spec2 = importlib.util.spec_from_file_location("invalid_metrics", SOURCE)
        original = importlib.util.module_from_spec(spec2)
        spec2.loader.exec_module(original)
        for load, memory, uptime in (((float("nan"), 0, 0), "MemAvailable: 1 kB", "1"),
                                     ((-1, 0, 0), "MemAvailable: 1 kB", "1"),
                                     ((0, 0, 0), "MemFree: 1 kB", "1"),
                                     ((0, 0, 0), "MemAvailable: 1 kB", "inf")):
            with patch.object(original.os, "getloadavg", return_value=load, create=True), \
                 patch.object(original.shutil, "disk_usage") as disk, \
                 patch.object(Path, "read_text", side_effect=[memory, uptime]):
                disk.return_value.total = 100
                disk.return_value.free = 50
                with self.assertRaises(ValueError):
                    original.collect()
