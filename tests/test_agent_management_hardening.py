"""Failure injection for the hardened manager; no live data or network."""
from contextlib import contextmanager
import copy
import hashlib
import json
import os
import sqlite3
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_agent_management import Fixture, WorkerFixture, ID1, ID2, NOW, KEY, am, worker, signer


@unittest.skipUnless(os.name == "posix", "Linux capability filesystem required")
class HardenedFilesystemTests(Fixture, unittest.TestCase):
    def test_root_worker_refused_before_any_file_read(self):
        with patch.object(am.os, "getuid", return_value=0), patch.object(am, "discover", side_effect=AssertionError("root must not read")), self.assertRaises(ValueError):
            am.Manager(self.policy, self.state, KEY, 9001, 101)

    def test_read_group_owner_and_mode_preserved(self):
        before = self.target.stat()
        with patch.object(am.os, "fchown", wraps=os.fchown) as ownership:
            self.execute(self.manifest())
        after = self.target.stat()
        self.assertEqual((after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)), (before.st_uid, before.st_gid, 0o640))
        ownership.assert_called_once()
        self.assertEqual(ownership.call_args.args[1:], (-1, before.st_gid))

    def test_group_change_permission_failure_preserves_original(self):
        with patch.object(am.os, "fchown", side_effect=PermissionError("synthetic permission")), self.assertRaises(PermissionError):
            self.execute(self.manifest())
        self.assertEqual(self.target.read_bytes(), self.old)
        self.assertFalse(list(self.workspace.glob(".agent-manager-*")))
        self.assertEqual(self.execute(self.manifest())["state"], "held")

    def test_chmod_permission_failure_preserves_original(self):
        with patch.object(am.os, "fchmod", side_effect=PermissionError("synthetic permission")), self.assertRaises(PermissionError):
            self.execute(self.manifest())
        self.assertEqual(self.target.read_bytes(), self.old)
        self.assertEqual(self.manager.db.execute("SELECT backup FROM jobs").fetchone()[0], self.old)

    def test_unreadable_group_or_world_readable_write_model_refused(self):
        self.target.chmod(0o644)
        with self.assertRaises(ValueError):
            self.execute(self.manifest())
        self.assertEqual(self.target.read_bytes(), self.old)

    def test_excess_permission_bits_and_extended_acl_refused(self):
        self.target.chmod(0o4640)
        with self.assertRaises(ValueError):
            am.read_file(self.workspace, "AGENTS.md")
        self.target.chmod(0o640)
        with patch.object(am.os, "listxattr", return_value=["system.posix_acl_access"]), self.assertRaises(ValueError):
            am.read_file(self.workspace, "AGENTS.md")

    def test_default_directory_acl_refused(self):
        with patch.object(am.os, "listxattr", return_value=["system.posix_acl_default"]), self.assertRaises(ValueError):
            am.open_directory(self.workspace)

    def test_extended_file_metadata_not_silently_lost(self):
        with patch.object(am.os, "listxattr", return_value=["user.synthetic"]), self.assertRaises(ValueError):
            self.execute(self.manifest())
        self.assertEqual(self.target.read_bytes(), self.old)

    def test_unknown_state_schema_refused(self):
        with self.manager.db:
            self.manager.db.execute("PRAGMA user_version=99")
        with self.assertRaises(ValueError):
            am.Manager(self.policy, self.state, KEY, 9001, 101)

    def test_raw_configuration_fields_cannot_enter_snapshot(self):
        manifest = self.manifest("snapshot", agent="main", paths=["AGENTS.md"])
        response = self.execute(manifest)
        response["result"]["files"][0]["raw_config"] = {"synthetic": "private"}
        with self.assertRaises(ValueError):
            self.manager.publication_safe(manifest, response)

    def test_acl_inspection_failure_fails_closed(self):
        with patch.object(am.os, "listxattr", side_effect=PermissionError("synthetic xattr permission")), self.assertRaises(PermissionError):
            am.read_file(self.workspace, "AGENTS.md")

    def test_state_sidecar_symlink_refused_before_sqlite(self):
        self.manager.close()
        self.manager.close = lambda: None
        (self.state / "agent-management.sqlite3-journal").symlink_to(self.target)
        with self.assertRaises(ValueError):
            am.Manager(self.policy, self.state, KEY, 9001, 101)
        self.assertEqual(self.target.read_bytes(), self.old)

    def test_database_permission_failure_does_not_touch_target(self):
        with patch.object(self.manager, "event", side_effect=sqlite3.OperationalError("synthetic state failure")), self.assertRaises(sqlite3.OperationalError):
            self.execute(self.manifest())
        self.assertEqual(self.target.read_bytes(), self.old)
        self.assertEqual(self.manager.db.execute("SELECT count(*) FROM jobs").fetchone()[0], 0)

    def test_approval_expiring_while_waiting_for_lock_has_no_effect(self):
        @contextmanager
        def late_lock():
            with patch.object(am.time, "time", return_value=NOW + 301):
                yield
        manifest = self.manifest()
        proof = self.approval(manifest)
        with patch.object(self.manager, "lock", side_effect=late_lock), self.assertRaises(ValueError):
            self.manager.execute(manifest, proof, now=NOW)
        self.assertEqual(self.target.read_bytes(), self.old)
        self.assertEqual(self.manager.db.execute("SELECT count(*) FROM jobs").fetchone()[0], 0)

    def test_approval_expiring_during_staging_never_renames(self):
        original = am.read_at
        calls = 0
        late = [False]
        def staged(parent, name):
            nonlocal calls
            if name == "AGENTS.md":
                calls += 1
                if calls == 2:
                    late[0] = True
            return original(parent, name)
        with patch.object(am, "read_at", side_effect=staged), patch.object(am.time, "time", side_effect=lambda: NOW + 301 if late[0] else NOW), self.assertRaises(ValueError):
            self.execute(self.manifest())
        self.assertEqual(self.target.read_bytes(), self.old)

    def test_file_fsync_failure_leaves_original_and_backup(self):
        real_sync = os.fsync
        def fail_file(fd):
            if stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("synthetic interrupted sync")
            real_sync(fd)
        with patch.object(am.os, "fsync", side_effect=fail_file), self.assertRaises(OSError):
            self.execute(self.manifest())
        self.assertEqual(self.target.read_bytes(), self.old)
        self.assertEqual(self.manager.db.execute("SELECT backup FROM jobs").fetchone()[0], self.old)
        self.assertFalse(list(self.workspace.glob(".agent-manager-*")))

    def test_directory_sync_failure_is_recovered_before_acknowledgement(self):
        real_sync = os.fsync
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("synthetic directory sync failure")
            real_sync(fd)
        manifest = self.manifest()
        with patch.object(am.os, "fsync", side_effect=fail_directory), self.assertRaises(OSError):
            self.execute(manifest)
        self.assertEqual(self.target.read_bytes(), manifest["content"].encode())
        with patch.object(am.os, "fsync", side_effect=fail_directory), self.assertRaises(OSError):
            self.execute(manifest)
        self.assertEqual(self.manager.db.execute("SELECT state FROM jobs").fetchone()[0], "prepared")
        with patch.object(am.os, "fsync", wraps=real_sync) as sync:
            self.assertEqual(self.execute(manifest)["state"], "applied")
            self.assertTrue(sync.called)

    def test_crash_after_rename_then_same_content_different_inode_is_held(self):
        real_replace = os.replace
        def crash(*args, **kwargs):
            real_replace(*args, **kwargs)
            raise KeyboardInterrupt("synthetic crash")
        manifest = self.manifest()
        with patch.object(am.os, "replace", side_effect=crash), self.assertRaises(KeyboardInterrupt):
            self.execute(manifest)
        replacement = self.workspace / "synthetic-replacement"
        replacement.write_bytes(self.target.read_bytes())
        replacement.chmod(0o640)
        real_replace(replacement, self.target)
        self.assertEqual(self.execute(manifest)["state"], "held")

    def test_crash_after_rename_then_mode_change_is_held(self):
        real_replace = os.replace
        def crash(*args, **kwargs):
            real_replace(*args, **kwargs)
            raise KeyboardInterrupt("synthetic crash")
        manifest = self.manifest()
        with patch.object(am.os, "replace", side_effect=crash), self.assertRaises(KeyboardInterrupt):
            self.execute(manifest)
        self.target.chmod(0o600)
        self.assertEqual(self.execute(manifest)["state"], "held")

    def test_root_mapping_change_cannot_restore_other_workspace(self):
        self.execute(self.manifest())
        other = self.root / "other"
        other.mkdir(mode=0o700)
        (other / "AGENTS.md").write_bytes(self.target.read_bytes())
        (other / "AGENTS.md").chmod(0o640)
        policy = copy.deepcopy(self.policy)
        policy["roots"]["main-root"]["path"] = str(other)
        manager = am.Manager(policy, self.state, KEY, 9001, 101)
        self.addCleanup(manager.close)
        manifest = self.manifest("restore", ID2, agent="main", path="AGENTS.md", expected=am.digest(self.target.read_bytes()), backup=ID1)
        proof = self.approval(manifest)
        proof["claim"]["policy"] = manager.policy_hash
        proof["signature"] = am.signature(proof["claim"], KEY)
        with self.assertRaises(ValueError):
            manager.execute(manifest, proof, now=NOW)

    def test_restore_failure_does_not_destroy_current_file(self):
        self.execute(self.manifest())
        current = self.target.read_bytes()
        manifest = self.manifest("restore", ID2, agent="main", path="AGENTS.md", expected=am.digest(current), backup=ID1)
        with patch.object(am.os, "replace", side_effect=PermissionError("synthetic rollback failure")), self.assertRaises(PermissionError):
            self.execute(manifest)
        self.assertEqual(self.target.read_bytes(), current)
        self.assertEqual(self.execute(manifest)["state"], "held")

    def test_overlapping_workspace_roots_rejected(self):
        policy = copy.deepcopy(self.policy)
        policy["roots"]["chef-root"] = {"path": str(self.workspace / "knowledge"), "files": {}}
        with self.assertRaises(ValueError):
            am.validate_policy(policy)

    def test_live_policy_revocation_refuses_cached_publication(self):
        manifest = self.manifest("snapshot", agent="main", paths=["AGENTS.md"])
        response = self.execute(manifest)
        self.manager.policy_path = self.root / "synthetic-policy.json"
        revoked = copy.deepcopy(self.policy)
        revoked["roots"]["main-root"]["files"]["AGENTS.md"]["publish"] = []
        with patch.object(am, "load_policy", return_value=revoked), self.assertRaises(ValueError):
            self.manager.publication_safe(manifest, response)

    def test_cached_snapshot_secret_or_extra_fields_refused(self):
        manifest = self.manifest("snapshot", agent="main", paths=["AGENTS.md"])
        response = self.execute(manifest)
        for tamper in (lambda r: r["result"].update(raw_config="synthetic-private"),
                       lambda r: r["result"]["files"][0].update(content='"password": "synthetic"'),
                       lambda r: r["result"]["files"][0].update(path="USER.md")):
            value = copy.deepcopy(response)
            tamper(value)
            with self.assertRaises(ValueError):
                self.manager.publication_safe(manifest, value)

    def test_future_agent_inventory_is_whole_projection_fail_closed(self):
        self.projection["agents"].append({"id": "new-agent", "workspace": "new-root", "config_ref": "new-config", "whatsapp": {"configured": False, "binding_count": 0}})
        self.registry.write_bytes(am.canonical(self.projection))
        with self.assertRaises(ValueError):
            self.execute(self.manifest("list"))
        fresh = am.Manager(self.policy, self.state, KEY, 9001, 101)
        self.addCleanup(fresh.close)
        self.assertEqual(fresh.inventory()["agents"][-1]["id"], "new-agent")
        self.assertFalse(fresh.inventory()["agents"][-1]["managed"])

    def test_credential_links_permissions_and_oversize_refused(self):
        credential = self.root / "synthetic-credential"
        credential.write_text("synthetic_token")
        credential.chmod(0o600)
        self.assertEqual(worker.read_credential(self.root, credential.name), "synthetic_token")
        credential.chmod(0o644)
        with self.assertRaises(ValueError):
            worker.read_credential(self.root, credential.name)
        credential.chmod(0o600)
        link = self.root / "synthetic-link"
        link.symlink_to(credential)
        with self.assertRaises(OSError):
            worker.read_credential(self.root, link.name)
        credential.write_text("x" * 514)
        with self.assertRaises(ValueError):
            worker.read_credential(self.root, credential.name)


@unittest.skipUnless(os.name == "posix", "Linux capability filesystem required")
class HardenedPublicationTests(WorkerFixture, unittest.TestCase):
    def test_accepted_upload_lost_response_resumes_comment_but_never_upload(self):
        def lost(method, path, token, payload=None):
            result = self.fake(method, path, token, payload)
            if method == "PUT":
                raise OSError("synthetic lost upload response")
            return result
        with self.assertLogs(level="WARNING"):
            self.run_worker(lost)
        self.assertIsNotNone(self.artifact)
        self.assertIsNone(self.report)
        self.run_worker()
        self.assertEqual(sum(m == "PUT" for m, _ in self.calls), 1)
        self.assertEqual(sum(m == "POST" for m, _ in self.calls), 1)
        self.assertEqual(self.manager.db.execute("SELECT state FROM outbox").fetchone()[0], "posted")

    def test_crash_before_post_never_automatically_reposts(self):
        def crash(method, path, token, payload=None):
            if method == "POST":
                raise KeyboardInterrupt("synthetic interruption")
            return self.fake(method, path, token, payload)
        with self.assertRaises(KeyboardInterrupt):
            self.run_worker(crash)
        self.assertEqual(self.manager.db.execute("SELECT attempted FROM outbox").fetchone()[0], 1)
        self.run_worker()
        self.assertIsNone(self.report)
        self.assertEqual(sum(m == "PUT" for m, _ in self.calls), 1)

    def test_reserved_artifact_substitution_does_not_post(self):
        def lost(method, path, token, payload=None):
            result = self.fake(method, path, token, payload)
            if method == "PUT":
                raise OSError("synthetic ambiguity")
            return result
        with self.assertLogs(level="WARNING"):
            self.run_worker(lost)
        self.artifact = am.canonical({"synthetic": "substituted"})
        with self.assertLogs(level="WARNING"):
            self.run_worker()
        self.assertIsNone(self.report)

    def test_expired_publication_can_resume_only_with_fresh_owner_signature(self):
        def lost(method, path, token, payload=None):
            result = self.fake(method, path, token, payload)
            if method == "PUT":
                raise OSError("synthetic ambiguity")
            return result
        with self.assertLogs(level="WARNING"):
            self.run_worker(lost)
        with patch.object(am.time, "time", return_value=NOW + 301), self.assertLogs(level="WARNING"):
            self.run_worker()
        self.assertIsNone(self.report)
        claim = self.approval(self.request)["claim"]
        claim["expires"] = NOW + 600
        proof = am.signature(claim, KEY)
        self.comment["body"] = signer.approval_line(claim, self.request, KEY, now=NOW + 301)
        with patch.object(am.time, "time", return_value=NOW + 301):
            self.run_worker()
        self.assertIsNotNone(self.report)
        self.assertEqual(sum(m == "PUT" for m, _ in self.calls), 1)
        self.assertTrue(self.comment["body"].endswith(proof))

    def test_reconciliation_refetches_comment_and_rejects_changed_body(self):
        def lost(method, path, token, payload=None):
            result = self.fake(method, path, token, payload)
            if method == "POST":
                raise OSError("synthetic lost response")
            return result
        with self.assertLogs(level="WARNING"):
            self.run_worker(lost)
        def changed(method, path, token, payload=None):
            result = self.fake(method, path, token, payload)
            if path == "/issues/comments/401":
                return {**result, "body": "changed"}
            return result
        self.run_worker(changed)
        self.assertEqual(self.manager.db.execute("SELECT state FROM outbox").fetchone()[0], "reserved")

    def test_all_snapshot_paths_validated_before_any_upload(self):
        self.request = self.manifest("snapshot", agent="main", paths=["AGENTS.md", "USER.md"])
        proof = self.approval(self.request)
        self.comment["body"] = signer.approval_line(proof["claim"], self.request, KEY, now=NOW)
        with self.assertLogs(level="WARNING"):
            self.run_worker()
        self.assertIsNone(self.artifact)
        self.assertIsNone(self.report)


class HardenedParsingTests(unittest.TestCase):
    def test_duplicate_json_keys_and_nonfinite_numbers_rejected(self):
        for raw in ('{"operation":"list","operation":"write"}', '{"x":NaN}', '{"x":Infinity}'):
            with self.assertRaises(ValueError):
                am.strict_json(raw)

    def test_quoted_credentials_and_deceptive_unicode_excluded(self):
        for value in ('"password": "synthetic"', "'api_key': 'synthetic'", "Authorization: Bearer synthetic00000", "safe\u202etext", "safe\u200btext", "bad\x7ftext"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                am.safe_text(value)

    def test_signatures_have_protocol_domain_separation(self):
        import hmac
        claim = {"synthetic": 1}
        old = hmac.new(KEY, am.canonical(claim), hashlib.sha256).hexdigest()
        self.assertNotEqual(old, am.signature(claim, KEY))

    def test_permission_model_is_documented_and_disabled_unit_has_no_timer(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        unit = (root / "supervisor/agent-management.service.example").read_text()
        self.assertIn("User=openclaw-agent-manager", unit)
        self.assertIn("SUPERVISOR_AGENT_MANAGEMENT_ENABLED=0", unit)
        self.assertIn("CapabilityBoundingSet=", unit)
        self.assertNotIn("[Install]", unit)


if __name__ == "__main__":
    unittest.main()
