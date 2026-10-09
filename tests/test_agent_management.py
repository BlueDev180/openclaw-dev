"""Offline Linux capability and private transport regressions; synthetic fixtures only."""
import base64
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "supervisor"))
import agent_management as am
import agent_management_worker as worker
import agent_approval as signer

ID1 = "12345678-1234-4234-8234-123456789abc"
ID2 = "22345678-1234-4234-8234-123456789abc"
NOW = 1700000000
KEY = b"synthetic-offline-approval-key-00000000"


class Fixture:
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.workspace = self.root / "workspace"
        self.state.mkdir(mode=0o700)
        self.workspace.mkdir(mode=0o700)
        (self.workspace / "knowledge").mkdir(mode=0o700)
        self.target = self.workspace / "AGENTS.md"
        self.old = b"Approved instructions.\n"
        self.target.write_bytes(self.old)
        self.target.chmod(0o640)
        (self.workspace / "knowledge/reference.md").write_text("Approved knowledge.\n")
        self.registry = self.root / "registry.json"
        self.projection = {"version": 1, "source_version": "synthetic-1", "agents": [
            {"id": "main", "workspace": "main-root", "config_ref": "main-config", "whatsapp": {"configured": True, "binding_count": 1}},
            {"id": "sous-chef", "workspace": "chef-root", "config_ref": "chef-config", "whatsapp": {"configured": False, "binding_count": 0}},
            {"id": "future-agent", "workspace": "future-root", "config_ref": "future-config", "whatsapp": {"configured": False, "binding_count": 0}}]}
        self.registry.write_bytes(am.canonical(self.projection))
        self.policy = {"version": 1, "registry": str(self.registry), "roots": {"main-root": {
            "path": str(self.workspace), "files": {
                "AGENTS.md": {"write": True, "publish": [am.digest(self.old)]},
                "knowledge/reference.md": {"write": False, "publish": [am.digest(b"Approved knowledge.\n")]}}}}}
        real_read = am.read_at
        def synthetic_root_owner(parent, name):
            raw, metadata = real_read(parent, name)
            # Only simulate root ownership of the synthetic trust anchor.
            if name == "registry.json":
                metadata = SimpleNamespace(st_uid=0)
            return raw, metadata
        fixture_patch = patch.object(am, "read_at", side_effect=synthetic_root_owner)
        fixture_patch.start()
        self.addCleanup(fixture_patch.stop)
        clock_patch = patch.object(am.time, "time", return_value=NOW)
        clock_patch.start()
        self.addCleanup(clock_patch.stop)
        network_patch = patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Offline test attempted network"))
        network_patch.start()
        self.addCleanup(network_patch.stop)
        self.manager = am.Manager(self.policy, self.state, KEY, 9001, 101)
        self.addCleanup(self.manager.close)

    def manifest(self, operation="write", request=ID1, **values):
        result = {"version": 1, "request": request, "operation": operation}
        if operation == "write":
            result.update(agent="main", path="AGENTS.md", expected=am.digest(self.old), content="New approved instructions.\n")
        result.update(values)
        return result

    def approval(self, manifest):
        claim = {"repo": 9001, "owner": 101, "request": manifest["request"], "commit": "a" * 40,
                 "manifest": am.digest(am.canonical(manifest)), "policy": self.manager.policy_hash, "expires": NOW + 300}
        return {"claim": claim, "signature": am.signature(claim, KEY)}

    def execute(self, manifest):
        return self.manager.execute(manifest, self.approval(manifest), now=NOW)


@unittest.skipUnless(os.name == "posix", "Linux directory capabilities required")
class AgentManagementTests(Fixture, unittest.TestCase):
    def test_inventory_covers_future_agents_without_exposing_paths(self):
        result = self.execute(self.manifest("list"))["result"]
        self.assertEqual([a["id"] for a in result["agents"]], ["main", "sous-chef", "future-agent"])
        self.assertFalse(result["agents"][2]["managed"])
        self.assertNotIn(str(self.workspace), json.dumps(result))

    def test_projection_rejects_raw_configs_and_duplicate_agents(self):
        for mutation in (lambda p: p.update(auth={"secret": "synthetic"}),
                         lambda p: p["agents"].append(p["agents"][0]),
                         lambda p: p.update(version=True),
                         lambda p: p["agents"][0]["whatsapp"].update(phone="synthetic")):
            value = copy.deepcopy(self.projection)
            mutation(value)
            self.registry.write_bytes(am.canonical(value))
            with self.assertRaises(ValueError):
                am.discover(self.policy)

    def test_changed_inventory_invalidates_approval(self):
        self.projection["agents"][0]["workspace"] = "future-root"
        self.registry.write_bytes(am.canonical(self.projection))
        with self.assertRaises(ValueError):
            self.execute(self.manifest())
        self.assertEqual(self.target.read_bytes(), self.old)

    def test_path_allowlist_rejects_traversal_credentials_and_scripts(self):
        for path in ("../AGENTS.md", "/AGENTS.md", "knowledge/../AGENTS.md", "knowledge\\evil.md", ".env", "USER.md", "MEMORY.md", "TOOLS.md", "auth.json", "run.sh", "prompts/.hidden.md"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                am.approved_path(path)
        for path in ("AGENTS.md", "SOUL.md", "IDENTITY.md", "knowledge/reference.md", "prompts/test.md"):
            self.assertEqual(am.approved_path(path), path)

    def test_only_explicitly_configured_writable_files(self):
        for values in ({"path": "SOUL.md"}, {"path": "knowledge/reference.md"}, {"agent": "future-agent"}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.manager.location(values.get("agent", "main"), values.get("path", "AGENTS.md"), write=True)

    def test_symlink_and_hardlink_files_are_rejected(self):
        outside = self.root / "outside.md"
        outside.write_bytes(self.old)
        self.target.unlink()
        self.target.symlink_to(outside)
        with self.assertRaises((OSError, ValueError)):
            am.read_file(self.workspace, "AGENTS.md")
        self.target.unlink()
        os.link(outside, self.target)
        with self.assertRaises(ValueError):
            am.read_file(self.workspace, "AGENTS.md")
        self.assertEqual(outside.read_bytes(), self.old)

    def test_symlink_root_and_parent_are_rejected(self):
        link = self.root / "link"
        link.symlink_to(self.workspace, target_is_directory=True)
        with self.assertRaises(OSError):
            am.read_file(link, "AGENTS.md")
        knowledge = self.workspace / "knowledge"
        (knowledge / "reference.md").unlink()
        knowledge.rmdir()
        knowledge.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            am.read_file(self.workspace, "knowledge/reference.md")

    def test_special_executable_and_writable_files_are_rejected(self):
        for mode in (0o666, 0o755):
            self.target.chmod(mode)
            with self.assertRaises(ValueError):
                am.read_file(self.workspace, "AGENTS.md")
        self.target.unlink()
        os.mkfifo(self.target, 0o600)
        with self.assertRaises(ValueError):
            am.read_file(self.workspace, "AGENTS.md")

    def test_content_limits_and_control_bytes(self):
        for value in ("x" * 65537, "bad\x00text", "bad\x01text", 123):
            with self.assertRaises(ValueError):
                am.safe_text(value)
        self.target.write_bytes(b"x" * 65537)
        with self.assertRaises(ValueError):
            am.read_file(self.workspace, "AGENTS.md")

    def test_publication_requires_exact_reviewed_hash(self):
        self.target.write_text("Unreviewed harmless-looking text.\n")
        with self.assertRaises(ValueError):
            self.execute(self.manifest("snapshot", agent="main", paths=["AGENTS.md"]))

    def test_secret_detection_is_additional_release_gate(self):
        for value in ("api_key=synthetic", "password: synthetic", "-----BEGIN RSA PRIVATE KEY-----", "github_pat_synthetic00000", "trading-data", "session-cookie"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                am.safe_text(value)

    def test_snapshot_contains_only_allowed_files_and_is_repeatable(self):
        manifest = self.manifest("snapshot", agent="main", paths=["AGENTS.md", "knowledge/reference.md"])
        result = self.execute(manifest)
        self.assertEqual(result, self.execute(manifest))
        self.assertEqual(result["result"]["timestamp"], NOW)
        self.assertEqual(result["result"]["source_version"], "synthetic-1")
        self.assertEqual(len(result["result"]["files"]), 2)
        self.assertNotIn(str(self.workspace), json.dumps(result))

    def test_forged_expired_wrong_repository_and_wrong_policy_approvals(self):
        manifest = self.manifest()
        for field, value in (("repo", 9002), ("owner", 102), ("repo", True), ("request", ID2), ("commit", "main"), ("manifest", "b" * 64), ("policy", "c" * 64), ("expires", NOW), ("expires", NOW + 3601), ("expires", True)):
            proof = self.approval(manifest)
            proof["claim"][field] = value
            proof["signature"] = am.signature(proof["claim"], KEY)
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.manager.execute(manifest, proof, now=NOW)
        for proof in ({}, {"claim": self.approval(manifest)["claim"], "signature": "0" * 64}):
            with self.assertRaises(ValueError):
                self.manager.execute(manifest, proof, now=NOW)
        self.assertEqual(self.target.read_bytes(), self.old)

    def test_content_change_after_approval_fails(self):
        manifest = self.manifest()
        proof = self.approval(manifest)
        manifest["content"] = "Different instructions.\n"
        with self.assertRaises(ValueError):
            self.manager.execute(manifest, proof, now=NOW)

    def test_atomic_backup_audit_and_duplicate_does_not_write_again(self):
        manifest = self.manifest()
        real_replace = os.replace
        with patch.object(am.os, "replace", wraps=real_replace) as replacement:
            first = self.execute(manifest)
            self.assertEqual(first, self.execute(manifest))
            self.assertEqual(replacement.call_count, 1)
        row = self.manager.db.execute("SELECT backup,state FROM jobs WHERE request=?", (ID1,)).fetchone()
        self.assertEqual(row, (self.old, "applied"))
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o640)
        self.assertEqual([r[0] for r in self.manager.db.execute("SELECT event FROM audit ORDER BY sequence")], ["claimed", "prepared", "applied"])
        self.assertFalse(list(self.workspace.glob(".agent-manager-*")))

    def test_restore_requires_new_approval_and_expected_current_hash(self):
        self.execute(self.manifest())
        changed = self.target.read_bytes()
        result = self.execute(self.manifest("restore", ID2, agent="main", path="AGENTS.md", expected=am.digest(changed), backup=ID1))
        self.assertEqual(result["state"], "applied")
        self.assertEqual(self.target.read_bytes(), self.old)
        self.assertEqual(self.manager.db.execute("SELECT backup FROM jobs WHERE request=?", (ID2,)).fetchone()[0], changed)

    def test_corrupt_backup_cannot_be_restored(self):
        self.execute(self.manifest())
        with self.manager.db:
            self.manager.db.execute("UPDATE jobs SET backup=? WHERE request=?", (b"corrupt", ID1))
        with self.assertRaises(ValueError):
            self.execute(self.manifest("restore", ID2, agent="main", path="AGENTS.md", expected=am.digest(self.target.read_bytes()), backup=ID1))

    def test_stale_expected_hash_leaves_external_change_intact(self):
        self.target.write_bytes(b"External approved change.\n")
        with self.assertRaises(ValueError):
            self.execute(self.manifest())
        self.assertEqual(self.target.read_bytes(), b"External approved change.\n")

    def test_external_change_during_staging_is_detected(self):
        original = am.read_at
        count = 0
        def race(parent, name):
            nonlocal count
            if name == "AGENTS.md":
                count += 1
                if count == 2:
                    self.target.write_bytes(b"Concurrent change.\n")
            return original(parent, name)
        with patch.object(am, "read_at", side_effect=race), self.assertRaises(ValueError):
            self.execute(self.manifest())
        self.assertEqual(self.target.read_bytes(), b"Concurrent change.\n")
        self.assertEqual(self.execute(self.manifest())["state"], "held")

    def test_failed_rename_is_held_without_automatic_retry(self):
        manifest = self.manifest()
        with patch.object(am.os, "replace", side_effect=OSError("synthetic failure")), self.assertRaises(OSError):
            self.execute(manifest)
        self.assertEqual(self.target.read_bytes(), self.old)
        with patch.object(am.os, "replace", side_effect=AssertionError("must not retry")):
            self.assertEqual(self.execute(manifest)["state"], "held")
        self.assertFalse(list(self.workspace.glob(".agent-manager-*")))

    def test_crash_after_rename_recovers_without_reapplying(self):
        manifest = self.manifest()
        real_replace = os.replace
        def crash(*args, **kwargs):
            real_replace(*args, **kwargs)
            raise KeyboardInterrupt("synthetic crash")
        with patch.object(am.os, "replace", side_effect=crash), self.assertRaises(KeyboardInterrupt):
            self.execute(manifest)
        with patch.object(am.os, "replace", side_effect=AssertionError("must not retry")):
            self.assertEqual(self.execute(manifest)["state"], "applied")

    def test_request_identifier_conflict(self):
        self.execute(self.manifest())
        with self.assertRaises(ValueError):
            self.execute(self.manifest(content="Different content.\n"))

    def test_request_cannot_move_to_another_commit(self):
        manifest = self.manifest()
        self.execute(manifest)
        proof = self.approval(manifest)
        proof["claim"]["commit"] = "b" * 40
        proof["signature"] = am.signature(proof["claim"], KEY)
        with self.assertRaises(ValueError):
            self.manager.execute(manifest, proof, now=NOW)

    def test_owner_signing_helper_binds_exact_manifest(self):
        manifest = self.manifest()
        proof = self.approval(manifest)
        line = signer.approval_line(proof["claim"], manifest, KEY, now=NOW)
        self.assertTrue(worker.LINE.fullmatch(line))
        manifest["content"] = "Changed after review.\n"
        with self.assertRaises(ValueError):
            signer.approval_line(proof["claim"], manifest, KEY, now=NOW)

    def test_signing_key_requires_owner_private_regular_file(self):
        path = self.root / "synthetic-signing-key"
        path.write_text("ab" * 32)
        path.chmod(0o600)
        self.assertEqual(signer.read_key(path), bytes.fromhex("ab" * 32))
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            signer.read_key(path)
        path.chmod(0o600)
        link = self.root / "key-link"
        link.symlink_to(path)
        with self.assertRaises(OSError):
            signer.read_key(link)

    def test_root_owned_policy_required(self):
        policy = self.root / "policy.json"
        policy.write_bytes(am.canonical(self.policy))
        # The ownership proof is synthetic regardless of CI runner privileges.
        with patch.object(am, "read_at", return_value=(policy.read_bytes(), SimpleNamespace(st_uid=999, st_mode=0o600))):
            with self.assertRaises(ValueError):
                am.load_policy(policy)

    def test_duplicate_and_empty_backup_lists_rejected(self):
        for paths in ([], ["AGENTS.md", "AGENTS.md"]):
            with self.assertRaises(ValueError):
                self.manager.perform(self.manifest("snapshot", agent="main", paths=paths))

    def test_restore_does_not_cross_agent_or_file_identity(self):
        self.execute(self.manifest())
        with self.assertRaises(ValueError):
            self.execute(self.manifest("restore", ID2, agent="main", path="AGENTS.md", expected=am.digest(self.target.read_bytes()), backup=ID2))

    def test_independent_requests_have_independent_versions(self):
        self.execute(self.manifest())
        with self.assertRaises(ValueError):
            self.execute(self.manifest(request=ID2))
        self.assertEqual(self.manager.db.execute("SELECT count(*) FROM jobs").fetchone()[0], 2)

    def test_concurrent_managers_apply_one_transaction(self):
        manifest = self.manifest()
        proof = self.approval(manifest)
        def invoke(_):
            manager = am.Manager(self.policy, self.state, KEY, 9001, 101)
            try:
                return manager.execute(manifest, proof, now=NOW)
            finally:
                manager.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(invoke, range(2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(self.manager.db.execute("SELECT count(*) FROM jobs").fetchone()[0], 1)
        self.assertEqual(self.manager.db.execute("SELECT count(*) FROM audit WHERE event='prepared'").fetchone()[0], 1)

    def test_registration_and_routing_only_prepare_proposals(self):
        for operation, request in (("prepare_agent", ID1), ("prepare_routing", ID2)):
            result = self.execute(self.manifest(operation, request, agent="new-agent", workspace="main-root"))
            self.assertTrue(result["result"]["proposal_only"])
        self.assertEqual(self.target.read_bytes(), self.old)
        self.assertEqual(json.loads(self.registry.read_bytes()), self.projection)

    def test_insecure_state_and_state_symlink_rejected(self):
        self.state.chmod(0o755)
        with self.assertRaises(ValueError):
            am.Manager(self.policy, self.state, KEY, 9001, 101)
        self.state.chmod(0o700)
        alias = self.root / "state-alias"
        alias.symlink_to(self.state, target_is_directory=True)
        with self.assertRaises(ValueError):
            am.Manager(self.policy, alias, KEY, 9001, 101)


class WorkerFixture(Fixture):
    def setUp(self):
        super().setUp()
        self.owner = {"id": 101, "login": "BlueDev180", "type": "User"}
        self.reporter = {"id": 202, "login": "synthetic-reporter", "type": "User"}
        owner_patch = patch.object(worker, "AUTHOR_ID", 101)
        owner_patch.start()
        self.addCleanup(owner_patch.stop)
        trusted_patch = patch.object(worker, "trusted", side_effect=lambda u: u == self.owner)
        trusted_patch.start()
        self.addCleanup(trusted_patch.stop)
        self.request = self.manifest()
        proof = self.approval(self.request)
        claim = proof["claim"]
        body = f"supervisor:agent-management:v1 request={ID1} commit={claim['commit']} manifest={claim['manifest']} policy={claim['policy']} expires={claim['expires']} signature={proof['signature']}"
        self.comment = {"id": 301, "user": self.owner, "created_at": "2023-11-14T22:13:20Z", "updated_at": "2023-11-14T22:13:20Z", "body": body}
        self.artifact = None
        self.report = None
        self.calls = []

    @staticmethod
    def content(raw):
        return {"type": "file", "encoding": "base64", "content": base64.b64encode(raw).decode(), "sha": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}

    def fake(self, method, path, token, payload=None):
        self.calls.append((method, path))
        if path == "":
            return {"id": 9001, "private": True, "full_name": worker.REPOSITORY, "archived": False}
        if path == "user":
            return self.reporter
        if path == "/issues/42":
            return {"number": 42, "state": "open", "title": worker.TITLE, "body": worker.BODY, "user": self.owner}
        if path == "/issues/42/comments?per_page=100&page=1":
            return [self.comment] + ([self.report] if self.report else [])
        if path == "/issues/comments/301":
            return self.comment
        if path == "/issues/comments/401":
            return self.report
        if path.startswith("/git/commits/"):
            return {"sha": "a" * 40}
        if path.startswith("/contents/agent-requests/"):
            return self.content(am.canonical(self.request))
        if path.startswith("/contents/agent-snapshots/"):
            if method == "PUT":
                self.assertNotIn("sha", payload)
                self.artifact = base64.b64decode(payload["content"])
                return {"content": {"sha": self.content(self.artifact)["sha"]}}
            if self.artifact is None:
                raise OSError("synthetic absent artifact")
            return self.content(self.artifact)
        if method == "POST" and path == "/issues/42/comments":
            self.report = {"id": 401, "user": self.reporter, "body": payload["body"]}
            return self.report
        raise AssertionError("Unexpected mocked endpoint")

    def run_worker(self, fake=None):
        with patch.object(worker, "github", side_effect=fake or self.fake):
            worker.run_once(self.manager, "synthetic_token", 42, 202)


@unittest.skipUnless(os.name == "posix", "Linux directory capabilities required")
class WorkerTests(WorkerFixture, unittest.TestCase):
    def test_private_request_applied_and_published_exactly_once(self):
        self.run_worker()
        self.run_worker()
        self.assertEqual(sum(method == "PUT" for method, _ in self.calls), 1)
        self.assertEqual(sum(method == "POST" for method, _ in self.calls), 1)
        self.assertNotIn(b"synthetic_token", self.artifact)
        self.assertNotIn(str(self.workspace), self.report["body"])

    def test_forged_comment_and_edited_approval_rejected(self):
        original = copy.deepcopy(self.comment)
        for field, value in (("user", {"id": 999, "login": "BlueDev180", "type": "User"}), ("updated_at", "2023-11-14T22:13:21Z"), ("created_at", None), ("body", original["body"][:-64] + "0" * 64)):
            self.comment = {**original, field: value}
            with self.assertLogs(level="WARNING"):
                self.run_worker()
            self.assertEqual(self.target.read_bytes(), self.old)
            self.assertIsNone(self.artifact)

    def test_public_repository_and_wrong_reporter_prevent_local_effects(self):
        def public(method, path, token, payload=None):
            value = self.fake(method, path, token, payload)
            if path == "":
                value["private"] = False
            return value
        with self.assertRaises(ValueError):
            self.run_worker(public)
        self.reporter = {"id": 303, "type": "User"}
        with self.assertRaises(ValueError):
            self.run_worker()
        self.assertEqual(self.target.read_bytes(), self.old)

    def test_manifest_substitution_is_rejected(self):
        self.request["content"] = "Substituted instructions.\n"
        with self.assertLogs(level="WARNING"):
            self.run_worker()
        self.assertEqual(self.target.read_bytes(), self.old)

    def test_lost_post_response_reconciles_without_duplicate(self):
        def ambiguous(method, path, token, payload=None):
            result = self.fake(method, path, token, payload)
            if method == "POST":
                raise OSError("synthetic_token private infrastructure error")
            return result
        with self.assertLogs(level="WARNING") as logs:
            self.run_worker(ambiguous)
        self.assertNotIn("synthetic_token", " ".join(logs.output))
        self.run_worker()
        self.assertEqual(sum(method == "POST" for method, _ in self.calls), 1)
        self.assertEqual(self.manager.db.execute("SELECT state FROM outbox").fetchone()[0], "posted")

    def test_ambiguous_artifact_failure_is_never_retried(self):
        def ambiguous(method, path, token, payload=None):
            if method == "PUT":
                self.calls.append((method, path))
                raise OSError("synthetic ambiguous failure")
            return self.fake(method, path, token, payload)
        with self.assertLogs(level="WARNING"):
            self.run_worker(ambiguous)
        with self.assertLogs(level="WARNING"):
            self.run_worker()
        self.assertEqual(sum(method == "PUT" for method, _ in self.calls), 1)
        self.assertIsNone(self.artifact)
        self.assertEqual(self.manager.db.execute("SELECT state FROM outbox").fetchone()[0], "reserved")

    def test_invalid_configuration_logs_no_private_exception_data(self):
        with patch.dict(os.environ, {"SUPERVISOR_AGENT_MANAGEMENT_ENABLED": "1", "SUPERVISOR_OPERATIONS_REPO_ID": "private-sensitive-address"}, clear=True), self.assertLogs(level="WARNING") as logs:
            worker.poll_once()
        self.assertNotIn("private-sensitive-address", " ".join(logs.output))

    def test_wrong_channel_never_changes_files(self):
        def wrong_channel(method, path, token, payload=None):
            result = self.fake(method, path, token, payload)
            if path == "/issues/42":
                result["title"] = "ordinary issue"
            return result
        with self.assertRaises(ValueError):
            self.run_worker(wrong_channel)
        self.assertEqual(self.target.read_bytes(), self.old)

    def test_repository_visibility_rechecked_before_local_write(self):
        calls = 0
        def changed(method, path, token, payload=None):
            nonlocal calls
            result = self.fake(method, path, token, payload)
            if path == "":
                calls += 1
                if calls > 1:
                    result["private"] = False
            return result
        with self.assertLogs(level="WARNING"):
            self.run_worker(changed)
        self.assertEqual(self.target.read_bytes(), self.old)

    def test_forged_report_marker_does_not_reconcile(self):
        def lost(method, path, token, payload=None):
            result = self.fake(method, path, token, payload)
            if method == "POST":
                raise OSError("synthetic lost response")
            return result
        with self.assertLogs(level="WARNING"):
            self.run_worker(lost)
        self.report["user"] = {"id": 999, "type": "User"}
        self.run_worker()
        self.assertEqual(self.manager.db.execute("SELECT state FROM outbox").fetchone()[0], "reserved")

    def test_multiple_requests_in_one_issue_apply_individually(self):
        self.run_worker()
        self.request = self.manifest(request=ID2, expected=am.digest(self.target.read_bytes()), content="Second approved edit.\n")
        proof = self.approval(self.request)
        claim = proof["claim"]
        self.comment["body"] = f"supervisor:agent-management:v1 request={ID2} commit={claim['commit']} manifest={claim['manifest']} policy={claim['policy']} expires={claim['expires']} signature={proof['signature']}"
        self.run_worker()
        self.assertEqual(self.target.read_bytes(), b"Second approved edit.\n")
        self.assertEqual(self.manager.db.execute("SELECT count(*) FROM outbox WHERE state='posted'").fetchone()[0], 2)


class TransportTests(unittest.TestCase):
    def test_fixed_https_transport_is_bounded_and_disables_proxies(self):
        from unittest.mock import MagicMock
        response = MagicMock()
        response.status = 200
        response.read.return_value = b"{}"
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch.object(worker.urllib.request, "build_opener", return_value=opener) as build:
            self.assertEqual(worker.github("GET", "", "synthetic_token"), {})
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, worker.API)
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 15)
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIs(build.call_args.args[1], worker.NoRedirect)
        response.read.assert_called_once_with(worker.MAX_RESPONSE + 1)

    def test_disabled_worker_does_not_read_or_call_network(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(worker, "github", side_effect=AssertionError("network")), patch.object(worker, "load_policy", side_effect=AssertionError("files")):
            worker.poll_once()

    def test_transport_rejects_arbitrary_hosts_paths_methods_and_header_injection(self):
        for method, path, token in (("GET", "https://evil.invalid/", "synthetic"), ("GET", "/contents/auth.json", "synthetic"), ("DELETE", "", "synthetic"), ("PUT", "/issues/1", "synthetic"), ("POST", "/contents/agent-snapshots/" + ID1 + ".json", "synthetic"), ("GET", "", "bad\ncredential")):
            with self.assertRaises(ValueError):
                worker.github(method, path, token)

    def test_blob_type_and_integrity_are_verified(self):
        value = WorkerFixture.content(b"synthetic")
        self.assertEqual(worker.decode_content(value, 100), b"synthetic")
        for mutation in ({"type": "symlink"}, {"sha": "0" * 40}, {"encoding": "utf8"}, {"content": "!!!"}):
            with self.assertRaises(ValueError):
                worker.decode_content({**value, **mutation}, 100)
        with self.assertRaises(ValueError):
            worker.decode_content(value, 1)

    def test_approval_requires_strong_dedicated_key(self):
        with self.assertRaises(ValueError):
            am.signature({}, b"short")

    def test_report_markers_require_authenticated_reporting_identity(self):
        marker = "<!-- synthetic -->"
        good = {"body": marker + "\nresult", "user": {"id": 202, "type": "User"}}
        self.assertTrue(worker.report_matches(good, 202, marker))
        self.assertFalse(worker.report_matches({**good, "user": {"id": 999, "type": "User"}}, 202, marker))
        self.assertFalse(worker.report_matches({**good, "body": "ordinary discussion"}, 202, marker))


if __name__ == "__main__":
    unittest.main()
