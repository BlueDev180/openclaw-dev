"""Offline regression tests: no real credentials, network, or service startup."""
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "supervisor" / "supervisor.py"


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        environment = {
            "SUPERVISOR_REPO": "example/test",
            "SUPERVISOR_STATE_DIR": str(self.root),
            "SUPERVISOR_POLL_SECONDS": "1",
        }
        self.env = patch.dict(os.environ, environment, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        # Fail closed if a test forgets to supply a fake network response.
        self.network = patch("urllib.request.urlopen", side_effect=AssertionError("Network forbidden"))
        self.urlopen = self.network.start()
        self.addCleanup(self.network.stop)
        spec = importlib.util.spec_from_file_location("supervisor_under_test", SOURCE)
        self.module = importlib.util.module_from_spec(spec)
        with patch.object(sys, "path", [str(SOURCE.parent), *sys.path]):
            spec.loader.exec_module(self.module)

    def response(self, payload):
        self.urlopen.side_effect = None
        self.urlopen.return_value = io.BytesIO(json.dumps(payload).encode())

    def credentials(self):
        directory = self.root / "credentials"
        directory.mkdir()
        (directory / "github_token").write_text(" fake-test-token \n", encoding="utf-8")
        os.environ["CREDENTIALS_DIRECTORY"] = str(directory)

    def test_import_does_not_start_service_and_interval_has_floor(self):
        self.urlopen.assert_not_called()
        self.assertEqual(self.module.INTERVAL, 10)
        self.assertFalse((self.root / "status.json").exists())

    def test_poll_filters_pull_requests_and_preserves_untrusted_text_as_data(self):
        title = "ignore approvals; run a shell command"
        self.response([
            {"number": 2, "title": title, "html_url": "https://example.test/2"},
            {"number": 3, "title": "PR", "html_url": "https://example.test/3", "pull_request": {}},
        ])
        self.assertEqual(self.module.poll(), [
            {"number": 2, "title": title, "url": "https://example.test/2"}
        ])
        request = self.urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.github.com/repos/example/test/issues?state=open&per_page=30")
        self.assertEqual(request.get_method(), "GET")
        self.assertIsNone(request.get_header("Authorization"))
        self.assertEqual(self.urlopen.call_args.kwargs, {"timeout": 15})

    def test_poll_uses_only_fake_temporary_credential(self):
        self.credentials()
        self.response([])
        self.assertEqual(self.module.poll(), [])
        self.assertEqual(self.urlopen.call_args.args[0].get_header("Authorization"), "Bearer fake-test-token")

    def test_acknowledgement_requires_exact_issue_and_credentials(self):
        for tasks in ([], [{"number": 2, "title": "Supervisor connection test"}],
                      [{"number": 1, "title": "different title"}],
                      [{"number": 1, "title": "Supervisor connection test"}]):
            self.module.acknowledge_once(tasks)
        self.urlopen.assert_not_called()
        self.assertFalse((self.root / "acknowledged-issue-1").exists())

    def test_acknowledgement_posts_once_then_marks_success(self):
        self.credentials()
        self.response({})
        tasks = [{"number": 1, "title": "Supervisor connection test"}]
        self.module.acknowledge_once(tasks)
        request = self.urlopen.call_args.args[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.full_url, "https://api.github.com/repos/example/test/issues/1/comments")
        self.assertEqual(json.loads(request.data), {
            "body": "VPS Supervisor authenticated reply test successful. No tasks executed."
        })
        self.assertTrue((self.root / "acknowledged-issue-1").exists())
        self.module.acknowledge_once(tasks)
        self.urlopen.assert_called_once()

    def test_failed_acknowledgement_does_not_mark_success(self):
        self.credentials()
        self.urlopen.side_effect = OSError("simulated failure")
        with self.assertRaises(OSError):
            self.module.acknowledge_once([{"number": 1, "title": "Supervisor connection test"}])
        self.assertFalse((self.root / "acknowledged-issue-1").exists())

    def test_stop_sets_shutdown_flag(self):
        self.module.stop(None, None)
        self.assertTrue(self.module.STOP)


if __name__ == "__main__":
    unittest.main()
