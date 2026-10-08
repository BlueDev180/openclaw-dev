"""Offline security regressions using synthetic API payloads and local state."""
import ast
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[1] / "supervisor" / "diagnostics.py"
spec = importlib.util.spec_from_file_location("diagnostics_under_test", SOURCE)
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)

UUID1 = "12345678-1234-4123-8123-123456789abc"
UUID2 = "22345678-1234-4123-8123-123456789abc"
NOW = 1700000000
STAMP = datetime.fromtimestamp(NOW, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class PrivateDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "operations_token").write_text("synthetic_ops_token", encoding="ascii")
        env = {"SUPERVISOR_DIAGNOSTICS_ENABLED": "1", "SUPERVISOR_OPERATIONS_REPO_ID": "9001",
               "SUPERVISOR_OPERATIONS_ISSUE": "42", "SUPERVISOR_OPERATIONS_REPORTER_ID": "202",
               "CREDENTIALS_DIRECTORY": str(self.root)}
        for context in (patch.dict(os.environ, env, clear=True), patch.object(d, "AUTHOR_ID", 101),
                        patch.object(d.time, "time", return_value=NOW),
                        patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Network forbidden"))):
            context.start()
            self.addCleanup(context.stop)
        self.author = {"login": d.AUTHOR, "id": 101, "type": "User"}
        self.reporter = {"login": "synthetic-reporter", "id": 202, "type": "User"}
        self.repo = {"id": 9001, "private": True, "archived": False, "full_name": d.REPOSITORY}
        self.issue = {"number": 42, "state": "open", "title": d.TITLE,
                      "body": d.CHANNEL_BODY, "user": self.author}
        self.requests = [self.new_request(UUID1, 301)]
        self.reports = []
        self.calls = []
        self.lock = threading.Lock()
        api_mock = patch.object(d, "api", side_effect=self.fake_api)
        self.api = api_mock.start()
        self.addCleanup(api_mock.stop)
        metric_mock = patch.object(d, "collect", return_value="Synthetic numeric metrics")
        self.metrics = metric_mock.start()
        self.addCleanup(metric_mock.stop)

    def new_request(self, identifier, number):
        return {"id": number, "body": "supervisor:diagnostics:v2 request=" + identifier,
                "user": self.author, "created_at": STAMP, "updated_at": STAMP}

    def fake_api(self, path, token, body=None):
        self.assertEqual(token, "synthetic_ops_token")
        with self.lock:
            self.calls.append((path, body))
            if path == "":
                return deepcopy(self.repo)
            if path == "user":
                return deepcopy(self.reporter)
            if path == "/issues/42":
                return deepcopy(self.issue)
            if path.startswith("/issues/42/comments?"):
                return deepcopy(self.requests + self.reports)
            if path.startswith("/issues/comments/"):
                number = int(path.rsplit("/", 1)[1])
                return deepcopy(next(c for c in self.requests if c["id"] == number))
            if path == "/issues/42/comments" and body is not None:
                report = {"id": 401 + len(self.reports), "user": self.reporter, "body": body}
                self.reports.append(deepcopy(report))
                return deepcopy(report)
        raise AssertionError("Unexpected endpoint")

    def poll(self):
        d.diagnostics_once(self.root)

    def rows(self):
        with sqlite3.connect(self.root / "operations-diagnostics.sqlite3") as db:
            return db.execute("SELECT request, source, state FROM deliveries ORDER BY request").fetchall()

    def test_repeated_requests_and_restart_deduplication(self):
        self.poll()
        self.requests.append(self.new_request(UUID2, 302))
        self.poll()
        self.poll()
        self.assertEqual(len(self.reports), 2)
        self.assertEqual(self.rows(), [(UUID1, 301, "posted"), (UUID2, 302, "posted")])
        self.assertIn(UUID1, self.reports[0]["body"])
        self.assertIn(UUID2, self.reports[1]["body"])
        self.assertEqual(self.metrics.call_count, 2)

    def test_duplicate_uuid_in_new_comment_does_not_repeat(self):
        self.requests.append(self.new_request(UUID1, 302))
        self.poll()
        self.assertEqual(len(self.reports), 1)

    def test_disabled_default_and_legacy_settings_never_enable(self):
        with patch.dict(os.environ, {"SUPERVISOR_DIAGNOSTICS_ENABLED": "", "SUPERVISOR_DIAGNOSTICS_ISSUE": "42"}):
            self.poll()
        with patch.dict(os.environ, {}, clear=True):
            self.poll()
        self.api.assert_not_called()
        self.metrics.assert_not_called()

    def test_invalid_configuration_has_no_side_effects(self):
        for key in ("SUPERVISOR_OPERATIONS_REPO_ID", "SUPERVISOR_OPERATIONS_ISSUE", "SUPERVISOR_OPERATIONS_REPORTER_ID"):
            for value in ("", "0", "-1", "42/../1", "1; reboot", " 42", "42\n", "9" * 19):
                with self.subTest(key=key, value=value), patch.dict(os.environ, {key: value}):
                    self.poll()
        self.api.assert_not_called()
        self.metrics.assert_not_called()

    def test_private_repository_identity_and_visibility_fail_closed(self):
        for changes in ({"private": False}, {"private": "true"}, {"private": None}, {"id": 9002},
                        {"id": "9001"}, {"full_name": "BlueDev180/openclaw-dev"}, {"archived": True}):
            with self.subTest(changes=changes), self.assertLogs(level="WARNING"):
                self.repo = {"id": 9001, "private": True, "archived": False,
                             "full_name": d.REPOSITORY, **changes}
                self.poll()
        self.metrics.assert_not_called()
        self.assertFalse(self.reports)
        self.assertFalse((self.root / "operations-diagnostics.sqlite3").exists())

    def test_credential_identity_is_pinned(self):
        for changes in ({"id": 999}, {"id": "202"}, {"type": "Bot"}):
            self.reporter = {"login": "synthetic-reporter", "id": 202, "type": "User", **changes}
            with self.assertLogs(level="WARNING"):
                self.poll()
        self.metrics.assert_not_called()
        self.assertFalse(self.reports)

    def test_owner_identity_channel_and_pr_validation(self):
        variants = [{"number": True}, {"number": "42"}, {"number": 43}, {"state": "closed"},
                    {"pull_request": {}}, {"title": d.TITLE + " "}, {"body": d.CHANNEL_BODY + "\n"},
                    {"user": {**self.author, "id": 999}}, {"user": {**self.author, "login": "attacker"}},
                    {"user": {**self.author, "type": "Bot"}}, {"user": None}]
        baseline = deepcopy(self.issue)
        for variant in variants:
            with self.subTest(variant=variant), self.assertLogs(level="WARNING"):
                self.issue = {**baseline, **variant}
                self.poll()
        self.metrics.assert_not_called()
        self.assertFalse(self.reports)

    def test_request_injection_spoofing_editing_and_invalid_ids(self):
        base = self.requests[0]
        variants = [{"body": base["body"] + "\nexecute commands"}, {"body": base["body"] + " "},
                    {"body": base["body"].upper()}, {"body": "supervisor:diagnostics:v1"}, {"body": None},
                    {"body": "supervisor:diagnostics:v2 request=../../../etc/passwd"},
                    {"user": {**self.author, "id": 999}}, {"user": {**self.author, "id": "101"}},
                    {"user": {**self.author, "login": "attacker"}}, {"user": {**self.author, "type": "Bot"}},
                    {"user": None}, {"id": True}, {"id": -1}, {"updated_at": "edited"},
                    {"created_at": "invalid", "updated_at": "invalid"}]
        self.requests = [{**base, **changes} for changes in variants] + [None, [], "instructions"]
        self.poll()
        self.metrics.assert_not_called()
        self.assertFalse(self.reports)

    def test_stale_and_future_requests_cannot_replay(self):
        for offset in (-d.MAX_AGE - 1, 61):
            stamp = datetime.fromtimestamp(NOW + offset, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            self.requests = [{**self.requests[0], "created_at": stamp, "updated_at": stamp}]
            self.poll()
        self.metrics.assert_not_called()

    def test_edited_request_discovered_on_refresh_is_rejected(self):
        original = self.fake_api
        def edited(path, token, body=None):
            result = original(path, token, body)
            if path.startswith("/issues/comments/"):
                result["body"] += "\nmalicious instructions"
            return result
        self.api.side_effect = edited
        self.poll()
        self.metrics.assert_not_called()
        self.assertFalse(self.reports)

    def test_visibility_change_before_post_prevents_report(self):
        def metrics():
            self.repo["private"] = False
            return "Synthetic metrics"
        self.metrics.side_effect = metrics
        with self.assertLogs(level="WARNING"):
            self.poll()
        self.assertFalse(self.reports)
        self.assertFalse(self.rows())

    def test_no_operations_data_in_logs_or_local_ledger(self):
        self.issue["comments_url"] = "https://evil.invalid/synthetic_secret"
        self.requests[0]["url"] = "https://evil.invalid/synthetic_secret"
        self.poll()
        database = (self.root / "operations-diagnostics.sqlite3").read_bytes()
        for sensitive in (b"Synthetic numeric metrics", b"synthetic_ops_token", b"synthetic_secret"):
            self.assertNotIn(sensitive, database)
        for sensitive in ("synthetic_ops_token", "synthetic_secret"):
            self.assertNotIn(sensitive, self.reports[0]['body'])
        # The report intentionally includes only our mocked metrics, not issue/API metadata.
        self.assertIn("Synthetic numeric metrics", self.reports[0]["body"])

    def test_failures_log_fixed_text_without_secrets_or_error_details(self):
        self.api.side_effect = OSError("synthetic_ops_token private-host.example account-secret")
        with self.assertLogs(level="WARNING") as logs:
            self.poll()
        self.assertEqual(logs.output, ["WARNING:root:Private diagnostics poll deferred; check configuration and delivery state"])
        self.metrics.assert_not_called()

    def test_missing_bad_and_legacy_credentials_never_fall_back(self):
        for value in ("", "token\r\nInjected: yes", "secret with spaces", "x" * 514):
            (self.root / "operations_token").write_text(value)
            self.poll()
        (self.root / "operations_token").unlink()
        (self.root / "github_token").write_text("synthetic_ops_token")
        with self.assertLogs(level="WARNING"):
            self.poll()
        with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": ""}):
            self.poll()
        self.api.assert_not_called()

    def test_concurrent_workers_send_one_report(self):
        with ThreadPoolExecutor(max_workers=2) as workers:
            list(workers.map(lambda _: self.poll(), range(2)))
        self.assertEqual(len(self.reports), 1)
        self.assertEqual(self.rows(), [(UUID1, 301, "posted")])

    def test_concurrent_ledger_claim_is_atomic_and_repo_wide(self):
        def reserve(issue):
            db = d.ledger(self.root)
            try:
                return d.claim(db, 9001, issue, UUID1, 301)
            finally:
                db.close()
        with ThreadPoolExecutor(max_workers=8) as workers:
            results = list(workers.map(reserve, range(42, 58)))
        self.assertEqual(sum(results), 1)

    def test_accepted_post_lost_response_reconciles_without_resend(self):
        original = self.fake_api
        def lost_response(path, token, body=None):
            result = original(path, token, body)
            if body is not None:
                raise OSError("lost response with synthetic_ops_token")
            return result
        self.api.side_effect = lost_response
        with self.assertLogs(level="WARNING"):
            self.poll()
        self.assertEqual(self.rows(), [(UUID1, 301, "reserved")])
        self.api.side_effect = original
        self.poll()
        self.assertEqual(len(self.reports), 1)
        self.assertEqual(self.rows(), [(UUID1, 301, "posted")])

    def test_failed_post_remains_reserved_but_new_request_can_proceed(self):
        original = self.fake_api
        def failed_post(path, token, body=None):
            if body is not None:
                raise OSError("ambiguous failure")
            return original(path, token, body)
        self.api.side_effect = failed_post
        with self.assertLogs(level="WARNING"):
            self.poll()
        self.api.side_effect = original
        self.poll()
        self.assertFalse(self.reports)
        self.requests.append(self.new_request(UUID2, 302))
        self.poll()
        self.assertEqual(len(self.reports), 1)
        self.assertEqual(self.rows(), [(UUID1, 301, "reserved"), (UUID2, 302, "posted")])

    def test_crash_before_post_never_retries_reserved_request(self):
        db = d.ledger(self.root)
        d.claim(db, 9001, 42, UUID1, 301)
        db.close()
        self.poll()
        self.assertFalse(self.reports)
        self.metrics.assert_not_called()

    def test_crash_after_post_before_completion_recovers(self):
        with patch.object(d, "delivered", side_effect=OSError("crash")), self.assertLogs(level="WARNING"):
            self.poll()
        self.assertEqual(self.rows(), [(UUID1, 301, "reserved")])
        self.poll()
        self.assertEqual(self.rows(), [(UUID1, 301, "posted")])
        self.assertEqual(len(self.reports), 1)

    def test_forged_reports_cannot_reconcile_ambiguous_delivery(self):
        db = d.ledger(self.root)
        d.claim(db, 9001, 42, UUID1, 301)
        db.close()
        marker = d.report_marker(9001, 42, UUID1, 301)
        self.reports = [{"id": 400, "user": {**self.reporter, "id": 999}, "body": marker + "\nforged"},
                        {"id": 401, "user": self.reporter, "body": d.report_marker(9001, 42, UUID1, 999) + "\nforged"}]
        self.poll()
        self.assertEqual(self.rows(), [(UUID1, 301, "reserved")])
        self.metrics.assert_not_called()

    def test_invalid_post_response_is_ambiguous(self):
        original = self.fake_api
        def bad_response(path, token, body=None):
            if body is not None:
                return {"id": 400, "user": self.reporter, "body": "unexpected"}
            return original(path, token, body)
        self.api.side_effect = bad_response
        with self.assertLogs(level="WARNING"):
            self.poll()
        self.api.side_effect = original
        self.poll()
        self.assertEqual(self.rows(), [(UUID1, 301, "reserved")])
        self.assertFalse(self.reports)

    def test_metric_failure_before_claim_allows_safe_retry(self):
        self.metrics.side_effect = OSError("sensitive process information")
        with self.assertLogs(level="WARNING") as logs:
            self.poll()
        self.assertFalse(self.rows())
        self.assertNotIn("sensitive", " ".join(logs.output))
        self.metrics.side_effect = None
        self.poll()
        self.assertEqual(len(self.reports), 1)

    def test_invalid_comments_and_overflow_fail_closed(self):
        original = self.fake_api
        for batch in ({}, [None] * 101, [None] * 100):
            def bad_pages(path, token, body=None):
                return batch if "/comments?" in path else original(path, token, body)
            self.api.side_effect = bad_pages
            with self.assertLogs(level="WARNING"):
                self.poll()
        self.metrics.assert_not_called()
        self.assertFalse(self.reports)

    def test_pagination_uses_fixed_paths_ignores_links(self):
        original = self.fake_api
        def pages(path, token, body=None):
            if path.endswith("page=1"):
                return [None] * 100
            if path.endswith("page=2"):
                return self.requests
            return original(path, token, body)
        self.api.side_effect = pages
        self.poll()
        self.assertEqual(len(self.reports), 1)
        self.assertIn("/issues/42/comments?per_page=100&page=2", [call.args[0] for call in self.api.call_args_list])

    def test_per_poll_work_is_bounded(self):
        self.requests = [self.new_request(f"{index:08x}-1234-4123-8123-123456789abc", 300 + index)
                         for index in range(1, 8)]
        self.poll()
        self.assertEqual(len(self.reports), 5)
        self.poll()
        self.assertEqual(len(self.reports), 7)


class TransportTests(unittest.TestCase):
    def test_fixed_private_endpoint_credentials_timeout_and_redirect_policy(self):
        with patch("urllib.request.build_opener") as opener:
            response = opener.return_value.open.return_value.__enter__.return_value
            response.status = 201
            response.read.return_value = b'{"id":400}'
            self.assertEqual(d.api("/issues/42/comments", "synthetic_token", "synthetic body"), {"id": 400})
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url, "https://api.github.com/repos/BlueDev180/vps-operations/issues/42/comments")
            self.assertEqual(request.get_method(), "POST")
            self.assertEqual(request.get_header("Authorization"), "Bearer synthetic_token")
            self.assertEqual(opener.return_value.open.call_args.kwargs, {"timeout": 15})
            self.assertIs(opener.call_args.args[1], d.NoRedirect)
            self.assertEqual(opener.call_args.args[0].proxies, {})
            response.read.assert_called_once_with(d.MAX_BYTES + 1)
        self.assertIsNone(d.NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.invalid"))

    def test_errors_malformed_json_and_oversize_are_rejected(self):
        for status, body in ((401, b'{}'), (200, b'not json'), (200, b'x' * (d.MAX_BYTES + 1))):
            with patch("urllib.request.build_opener") as opener:
                response = opener.return_value.open.return_value.__enter__.return_value
                response.status, response.read.return_value = status, body
                with self.assertRaises(ValueError):
                    d.api("", "synthetic_token")

    def test_no_unsafe_execution_or_model_client_in_supervisor_sources(self):
        for path in SOURCE.parent.glob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    self.assertFalse(any(alias.name.split(".")[0] in {"subprocess", "openai", "anthropic"} for alias in node.names))
                if isinstance(node, ast.ImportFrom):
                    self.assertNotIn(node.module, {"subprocess", "openai", "anthropic"})
                if isinstance(node, ast.Call):
                    name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
                    self.assertNotIn(name, {"eval", "exec", "system", "popen", "spawn", "execv", "execve"})


class MetricTests(unittest.TestCase):
    def setUp(self):
        for context in (patch.object(d.os, "getloadavg", return_value=(0.1, 0.2, 0.3), create=True),
                        patch.object(d.shutil, "disk_usage", return_value=Mock(total=10485760, free=5242880)),
                        patch.object(d.time, "sleep")):
            context.start()
            self.addCleanup(context.stop)
        self.files = {"/proc/meminfo": "MemAvailable: 2048 kB\nMemTotal: 4096 kB\n",
                      "/proc/uptime": "123.9 99.0\n", "/proc/stat": "cpu 10 0 0 90 0 0 0 0 999 999\n"}
        files = patch.object(Path, "read_text", autospec=True, side_effect=lambda path, **kw: self.files[path.as_posix()])
        self.read = files.start()
        self.addCleanup(files.stop)

    def test_safe_metrics_include_total_ram_and_cpu_utilization(self):
        with patch.object(d, "cpu_counters", side_effect=[[10, 0, 0, 90, 0, 0, 0, 0], [30, 0, 0, 170, 0, 0, 0, 0]]):
            output = d.collect()
        self.assertIn("0.10 / 0.20 / 0.30", output)
        self.assertIn("20.0%", output)
        self.assertIn("2 MiB available / 4 MiB total", output)
        self.assertIn("5 MiB free / 10 MiB total", output)
        self.assertIn("123 seconds", output)
        self.assertNotIn("999", output)
        d.shutil.disk_usage.assert_called_once_with("/")
        self.assertEqual({call.args[0].as_posix() for call in self.read.call_args_list}, {"/proc/meminfo", "/proc/uptime"})

    def test_guest_cpu_counters_are_not_double_counted(self):
        self.assertEqual(d.cpu_counters(), [10, 0, 0, 90, 0, 0, 0, 0])

    def test_optional_cpu_is_unavailable_for_missing_reset_or_zero_sample(self):
        for effect in (OSError("sensitive host detail"), [[1] * 8, [0] * 8], [[1] * 8, [1] * 8]):
            with patch.object(d, "cpu_counters", side_effect=effect):
                self.assertEqual(d.utilization(), "unavailable")
        self.assertIn("CPU utilization (0.2-second sample): unavailable", d.collect())

    def test_invalid_memory_load_disk_and_uptime_fail_closed(self):
        for text in ("MemFree: 1 kB", "MemAvailable: 5000 kB\nMemTotal: 4096 kB",
                     "MemAvailable: 1 kB\nMemTotal: 0 kB", "MemAvailable: -1 kB\nMemTotal: 4096 kB"):
            self.files["/proc/meminfo"] = text
            with self.assertRaises(ValueError):
                d.collect()
        self.files["/proc/meminfo"] = "MemAvailable: 2048 kB\nMemTotal: 4096 kB\n"
        for uptime in ("nan", "inf", "-1", "1e100"):
            self.files["/proc/uptime"] = uptime
            with self.assertRaises(ValueError):
                d.collect()
        self.files["/proc/uptime"] = "1"
        for load in ((float("nan"), 0, 0), (-1, 0, 0), (0, 0)):
            with patch.object(d.os, "getloadavg", return_value=load):
                with self.assertRaises(ValueError):
                    d.collect()
        with patch.object(d.shutil, "disk_usage", return_value=Mock(total=10, free=20)):
            with self.assertRaises(ValueError):
                d.collect()


if __name__ == "__main__":
    unittest.main()
