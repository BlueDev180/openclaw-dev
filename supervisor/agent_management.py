"""Linux-only capability-scoped agent files and signed, single-file transactions.

No raw OpenClaw configuration, shell, Docker socket, or model runtime access.
"""
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
import unicodedata
import uuid

MAX_FILE = 65536
HEX = re.compile(r"[0-9a-f]{64}")
IDENTIFIER = re.compile(r"[a-z][a-z0-9-]{0,63}")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
SECRET = re.compile(r"(?i)(BEGIN .*PRIVATE KEY|\b(?:api[_ -]?key|access[_ -]?token|token|password|secret|authorization|client[_ -]?secret)[\"']?\s*[:=]|\b(?:gh[pousr]_|github_pat_|sk-)[A-Za-z0-9_-]{8,}|\bBearer\s+[A-Za-z0-9_.-]{8,}|\b(?:broker-account|trading-strategy|trading-data|session-cookie|auth-store)\b)")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def strict_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    def invalid(value):
        raise ValueError("Non-finite JSON number")
    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid)


def no_acl(descriptor):
    # Extended/default ACLs invalidate the simple owner/read-group model.
    names = os.listxattr(descriptor)
    if any(name in {"system.posix_acl_access", "system.posix_acl_default"} for name in names):
        raise ValueError("Extended ACLs unsupported")


def identity(metadata):
    return [metadata.st_dev, metadata.st_ino, metadata.st_uid,
            metadata.st_gid, stat.S_IMODE(metadata.st_mode)]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def exact(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError("Invalid schema")


def identifier(value):
    if type(value) is not str or not IDENTIFIER.fullmatch(value) or SECRET.search(value):
        raise ValueError("Invalid identifier")
    return value


def approved_path(value):
    if type(value) is not str:
        raise ValueError("Invalid path")
    if value in {"AGENTS.md", "SOUL.md", "IDENTITY.md"}:
        return value
    if re.fullmatch(r"(?:prompts|knowledge)/[a-z][a-z0-9-]{0,63}\.md", value):
        return value
    raise ValueError("Path is not an approved instruction type")


def safe_text(value):
    if type(value) is not str:
        raise ValueError("Text required")
    data = value.encode("utf-8")
    if len(data) > MAX_FILE or any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} and c not in "\n\r\t" for c in value) or SECRET.search(value):
        raise ValueError("Content not releasable")
    return data


def open_directory(path):
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("Linux capability filesystem required")
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Absolute local root required")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            metadata = os.fstat(child)
            try:
                no_acl(child)
            except BaseException:
                os.close(child)
                raise
            if (metadata.st_mode & 0o022 and not metadata.st_mode & stat.S_ISVTX) or metadata.st_uid not in {0, os.getuid()}:
                os.close(child)
                raise ValueError('Unsafe directory')
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if metadata.st_mode & 0o022 or metadata.st_uid not in {0, os.getuid()}:
            raise ValueError('Unsafe directory ownership or permissions')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def parent_directory(root, relative):
    descriptor = open_directory(root)
    try:
        parts = relative.split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            metadata = os.fstat(child)
            try:
                no_acl(child)
            except BaseException:
                os.close(child)
                raise
            if metadata.st_mode & 0o022 or metadata.st_uid not in {0, os.getuid()}:
                os.close(child)
                raise ValueError('Unsafe directory')
            os.close(descriptor)
            descriptor = child
        yield descriptor, parts[-1]
    finally:
        os.close(descriptor)


def read_at(parent, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        before = os.fstat(descriptor)
        no_acl(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_FILE
                or before.st_mode & 0o022 or before.st_mode & 0o7111):
            raise ValueError("Unsafe file")
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, MAX_FILE + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_FILE:
                raise ValueError("File too large")
        after = os.fstat(descriptor)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("Concurrent file change")
        return b"".join(chunks), before
    finally:
        os.close(descriptor)


def read_file(root, path):
    with parent_directory(root, approved_path(path)) as (parent, name):
        return read_at(parent, name)[0]


def plain_write_metadata(parent, name, expected):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        if identity(os.fstat(descriptor)) != identity(expected) or os.listxattr(descriptor):
            raise ValueError("Unsupported or changing file metadata")
    finally:
        os.close(descriptor)


def load_policy(path):
    """Deployment policy is a private, root-owned, non-writable trust anchor."""
    path = Path(path)
    with parent_directory(path.parent, path.name) as (parent, name):
        data, metadata = read_at(parent, name)
    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ValueError("Policy must be root owned")
    return strict_json(data)


def validate_policy(policy):
    exact(policy, {"version", "registry", "roots"})
    if type(policy["version"]) is not int or policy["version"] != 1 or type(policy["roots"]) is not dict:
        raise ValueError("Invalid policy")
    if not Path(policy["registry"]).is_absolute():
        raise ValueError("Invalid registry")
    roots = []
    for alias, root in policy["roots"].items():
        identifier(alias)
        exact(root, {"path", "files"})
        if not Path(root["path"]).is_absolute() or type(root["files"]) is not dict:
            raise ValueError("Invalid root")
        if ".." in Path(root["path"]).parts or any(os.path.commonpath([root["path"], previous]) in {root["path"], previous} for previous in roots):
            raise ValueError("Overlapping or traversing roots")
        roots.append(root["path"])
        for path, rule in root["files"].items():
            approved_path(path)
            exact(rule, {"write", "publish"})
            if type(rule["write"]) is not bool or type(rule["publish"]) is not list or any(
                    type(item) is not str or not HEX.fullmatch(item) for item in rule["publish"]):
                raise ValueError("Invalid release rule")
    return policy


def discover(policy):
    """Read an operator-reviewed projection, never a credential-bearing config."""
    registry = Path(policy["registry"])
    with parent_directory(registry.parent, registry.name) as (parent, name):
        data, metadata = read_at(parent, name)
    if metadata.st_uid != 0:
        raise ValueError("Registry must be root owned")
    projection = strict_json(data)
    exact(projection, {"version", "source_version", "agents"})
    if type(projection["version"]) is not int or projection["version"] != 1 or type(projection["source_version"]) is not str or not re.fullmatch(
            r"[a-zA-Z0-9.-]{1,64}", projection["source_version"]) or type(projection["agents"]) is not list or len(projection["agents"]) > 128:
        raise ValueError("Invalid projection")
    safe_text(projection["source_version"])
    seen = set()
    result = []
    for entry in projection["agents"]:
        exact(entry, {"id", "workspace", "config_ref", "whatsapp"})
        agent = identifier(entry["id"])
        if agent in seen:
            raise ValueError("Duplicate agent")
        seen.add(agent)
        alias = identifier(entry["workspace"])
        identifier(entry["config_ref"])
        exact(entry["whatsapp"], {"configured", "binding_count"})
        routing = entry["whatsapp"]
        if type(routing["configured"]) is not bool or type(routing["binding_count"]) is not int or not 0 <= routing["binding_count"] <= 1000:
            raise ValueError("Invalid routing summary")
        result.append({**entry, "managed": alias in policy["roots"],
                       "files": sorted(policy["roots"].get(alias, {}).get("files", {}))})
    return {"source_version": projection["source_version"], "agents": result}


def signature(claim, key):
    if type(key) is not bytes or len(key) < 32:
        raise ValueError("Approval key too short")
    return hmac.new(key, b"openclaw-agent-management-approval:v1\0" + canonical(claim), hashlib.sha256).hexdigest()


class Manager:
    def __init__(self, policy, state, key, repo_id, owner_id, policy_path=None):
        if os.name != "posix" or os.getuid() == 0:
            raise ValueError("Unprivileged Linux manager required")
        self.policy = validate_policy(strict_json(canonical(policy)))
        self.policy_path = policy_path
        policy = self.policy
        self.inventory_hash = digest(canonical(discover(policy)))
        self.policy_hash = digest(canonical({'policy': policy, 'inventory': self.inventory_hash}))
        self.state = Path(state)
        self.key = key
        self.repo_id = repo_id
        self.owner_id = owner_id
        metadata = self.state.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o077 or metadata.st_uid != os.getuid():
            raise ValueError("State must be a private owned directory")
        # Precreate a single-link private database without following symlinks.
        with parent_directory(self.state, "agent-management.sqlite3") as (parent, name):
            fd = os.open(name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            try:
                meta = os.fstat(fd)
                no_acl(fd)
            finally:
                os.close(fd)
            if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_mode & 0o077 or meta.st_uid != os.getuid():
                raise ValueError("Unsafe state database")
        # Private state must include private, regular, single-link SQLite sidecars.
        with parent_directory(self.state, "agent-management.sqlite3") as (parent, name):
            for suffix in ("-journal", "-wal", "-shm"):
                try:
                    meta = os.stat(name + suffix, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_mode & 0o077 or meta.st_uid != os.getuid():
                    raise ValueError("Unsafe database sidecar")
        # Serialize schema/bootstrap as well as all file transactions.
        with self.lock():
            self.db = sqlite3.connect(self.state / "agent-management.sqlite3", timeout=5)
            try:
                if self.db.execute("PRAGMA user_version").fetchone()[0] not in {0, 2}:
                    raise ValueError("Unsupported state version")
                self.db.execute("PRAGMA synchronous=FULL")
                self.db.executescript("CREATE TABLE IF NOT EXISTS jobs (request TEXT PRIMARY KEY, manifest TEXT, policy TEXT, state TEXT, agent TEXT, path TEXT, before_hash TEXT, after_hash TEXT, backup BLOB, result TEXT, identity TEXT, root TEXT); CREATE TABLE IF NOT EXISTS audit (sequence INTEGER PRIMARY KEY, request TEXT, event TEXT, timestamp INTEGER); CREATE TABLE IF NOT EXISTS outbox(request TEXT PRIMARY KEY, hash TEXT, state TEXT, attempted INTEGER NOT NULL DEFAULT 1);")
                with self.db:
                    columns = {r[1] for r in self.db.execute("PRAGMA table_info(jobs)")}
                    for column in ("identity", "root"):
                        if column not in columns:
                            self.db.execute("ALTER TABLE jobs ADD COLUMN " + column + " TEXT")
                    if "attempted" not in {r[1] for r in self.db.execute("PRAGMA table_info(outbox)")}:
                        # Old reservations may already have attempted a comment.
                        self.db.execute("ALTER TABLE outbox ADD COLUMN attempted INTEGER NOT NULL DEFAULT 1")
                    self.db.execute("UPDATE jobs SET state='held' WHERE state='prepared' AND identity IS NULL")
                    self.db.execute("PRAGMA user_version=2")
                with parent_directory(self.state, "agent-management.sqlite3") as (parent, name):
                    os.fsync(parent)
            except BaseException:
                self.db.close()
                raise

    def close(self):
        self.db.close()

    @contextmanager
    def lock(self):
        import fcntl
        with parent_directory(self.state, "agent-management.lock") as (parent, name):
            descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            meta = os.fstat(descriptor)
            no_acl(descriptor)
            if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_mode & 0o077 or meta.st_uid != os.getuid():
                raise ValueError("Unsafe lock")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    def event(self, request, event):
        self.db.execute("INSERT INTO audit(request,event,timestamp) VALUES(?,?,?)", (request, event, int(time.time())))

    def inventory(self):
        if self.policy_path is not None and canonical(load_policy(self.policy_path)) != canonical(self.policy):
            raise ValueError("Policy changed; fresh approval required")
        value = discover(self.policy)
        if digest(canonical(value)) != self.inventory_hash:
            raise ValueError('Registry changed; fresh approval required')
        return value

    def location(self, agent, path, write=False):
        identifier(agent)
        approved_path(path)
        inventory = self.inventory()
        entries = [a for a in inventory["agents"] if a["id"] == agent and a["managed"]]
        if len(entries) != 1:
            raise ValueError("Agent is not managed")
        root = self.policy["roots"][entries[0]["workspace"]]
        rule = root["files"].get(path)
        if rule is None or write and not rule["write"]:
            raise ValueError("File is not allowed")
        return root["path"], rule

    def verify(self, manifest, approval, now):
        exact(approval, {"claim", "signature"})
        claim = approval["claim"]
        exact(claim, {"repo", "owner", "request", "commit", "manifest", "policy", "expires"})
        if (type(manifest) is not dict or type(manifest.get("version")) is not int or manifest["version"] != 1
                or type(manifest.get("request")) is not str or not UUID.fullmatch(manifest["request"])
                or type(claim["repo"]) is not int or claim["repo"] != self.repo_id
                or type(claim["owner"]) is not int or claim["owner"] != self.owner_id
                or claim["request"] != manifest["request"] or claim["manifest"] != digest(canonical(manifest))
                or claim["policy"] != self.policy_hash or type(claim["commit"]) is not str
                or not re.fullmatch(r"[0-9a-f]{40}", claim["commit"])
                or type(claim["expires"]) is not int or not now < claim["expires"] <= now + 3600
                or type(approval["signature"]) is not str or not HEX.fullmatch(approval["signature"])
                or not hmac.compare_digest(signature(claim, self.key), approval["signature"])):
            raise ValueError("Approval not valid")

    def released(self, agent, path):
        root, rule = self.location(agent, path)
        data = read_file(root, path)
        if digest(data) not in rule["publish"]:
            raise ValueError("Exact content not approved for publication")
        safe_text(data.decode("utf-8"))
        return {"path": path, "sha256": digest(data), "content": data.decode("utf-8")}

    def execute(self, manifest, approval, now=None):
        self.verify(manifest, approval, time.time() if now is None else now)
        request = manifest["request"]
        request_hash = digest(canonical({"manifest": manifest, "commit": approval["claim"]["commit"],
                                        "repo": self.repo_id, "owner": self.owner_id}))
        with self.lock():
            # Lock waits can outlive an approval; recheck before any effect.
            self.verify(manifest, approval, time.time())
            self.inventory()
            previous = self.db.execute("SELECT manifest,policy,state,agent,path,before_hash,after_hash,result FROM jobs WHERE request=?", (request,)).fetchone()
            if previous:
                if previous[0] != request_hash or previous[1] != self.policy_hash:
                    raise ValueError("Request conflict")
                if previous[2] == "prepared":
                    root, _ = self.location(previous[3], previous[4], write=True)
                    recorded = self.db.execute("SELECT identity,root FROM jobs WHERE request=?", (request,)).fetchone()
                    with parent_directory(root, previous[4]) as (parent, name):
                        content, metadata = read_at(parent, name)
                        status = "applied" if (digest(content) == previous[6] and recorded[0]
                            and identity(metadata) == strict_json(recorded[0]) and recorded[1] == root) else "held"
                        if status == "applied":
                            os.fsync(parent)  # Finish durability before recording recovery.
                    with self.db:
                        self.db.execute("UPDATE jobs SET state=? WHERE request=?", (status, request))
                        self.event(request, "recovered-" + status)
                    previous = self.db.execute("SELECT manifest,policy,state,agent,path,before_hash,after_hash,result FROM jobs WHERE request=?", (request,)).fetchone()
                return {"state": previous[2], "result": json.loads(previous[7]) if previous[7] else None}
            with self.db:
                self.db.execute("INSERT INTO jobs(request,manifest,policy,state) VALUES(?,?,?,'claimed')", (request, request_hash, self.policy_hash))
                self.event(request, "claimed")
            try:
                result = self.perform(manifest, approval)
                with self.db:
                    self.db.execute("UPDATE jobs SET state='applied', result=? WHERE request=?", (json.dumps(result), request))
                    self.event(request, "applied")
                return {"state": "applied", "result": result}
            except Exception:
                with self.db:
                    self.db.execute("UPDATE jobs SET state='held' WHERE request=? AND state='claimed'", (request,))
                    self.event(request, "held")
                raise

    def publication_safe(self, manifest, response):
        """Revalidate cached output; never publish arbitrary ledger JSON."""
        self.inventory()
        exact(response, {"state", "result"})
        if response["state"] != "applied":
            raise ValueError("Not publishable")
        result = response["result"]
        operation = manifest["operation"]
        if operation == "list":
            if result != self.inventory():
                raise ValueError("Inventory result changed")
        elif operation in {"read", "snapshot"}:
            exact(result, {"timestamp", "request", "source_version", "agent", "files"})
            if (type(result["timestamp"]) is not int or result["timestamp"] <= 0
                    or result["request"] != manifest["request"] or result["agent"] != manifest["agent"]
                    or result["source_version"] != self.inventory()["source_version"]
                    or type(result["files"]) is not list or len(result["files"]) != len(manifest["paths"])):
                raise ValueError("Snapshot result changed")
            for path, file in zip(manifest["paths"], result["files"]):
                exact(file, {"path", "sha256", "content"})
                _, rule = self.location(manifest["agent"], path)
                content = safe_text(file["content"])
                if file["path"] != path or file["sha256"] != digest(content) or digest(content) not in rule["publish"]:
                    raise ValueError("Snapshot release revoked or corrupted")
        elif operation in {"write", "restore"}:
            exact(result, {"agent", "path", "before", "after", "rollback"})
            if (result["agent"] != manifest["agent"] or result["path"] != manifest["path"]
                    or result["before"] != manifest["expected"] or result["rollback"] != manifest["request"]
                    or type(result["after"]) is not str or not HEX.fullmatch(result["after"])):
                raise ValueError("Write result changed")
            if operation == "write" and result["after"] != digest(safe_text(manifest["content"])):
                raise ValueError("Write result hash changed")
        elif operation in {"prepare_agent", "prepare_routing"}:
            exact(result, {"proposal_only", "operation", "agent", "workspace", "requires_separate_registration_or_routing_approval"})
            if (result["proposal_only"] is not True or result["requires_separate_registration_or_routing_approval"] is not True
                    or any(result[field] != manifest[field] for field in ("operation", "agent", "workspace"))):
                raise ValueError("Proposal result changed")
        else:
            raise ValueError("Unknown result operation")

    def perform(self, manifest, approval=None):
        operation = manifest.get("operation")
        common = {"version", "request", "operation"}
        if operation == "list":
            exact(manifest, common)
            return self.inventory()
        if operation in {"read", "snapshot"}:
            exact(manifest, common | {"agent", "paths"})
            if type(manifest["paths"]) is not list or not 1 <= len(manifest["paths"]) <= 16 or len(set(manifest["paths"])) != len(manifest["paths"]):
                raise ValueError("Invalid backup file list")
            return {"timestamp": int(time.time()), "request": manifest["request"],
                    "source_version": self.inventory()["source_version"], "agent": identifier(manifest["agent"]),
                    "files": [self.released(manifest["agent"], p) for p in manifest["paths"]]}
        if operation in {"prepare_agent", "prepare_routing"}:
            exact(manifest, common | {"agent", "workspace"})
            identifier(manifest["agent"])
            alias = identifier(manifest["workspace"])
            if alias not in self.policy["roots"]:
                raise ValueError("Workspace is not approved")
            return {"proposal_only": True, "operation": operation, "agent": manifest["agent"],
                    "workspace": alias, "requires_separate_registration_or_routing_approval": True}
        if operation not in {"write", "restore"}:
            raise ValueError("Unknown operation")
        if approval is None:
            raise ValueError("Write approval required")
        exact(manifest, common | {"agent", "path", "expected", "content" if operation == "write" else "backup"})
        root, _ = self.location(manifest["agent"], manifest["path"], write=True)
        if type(manifest["expected"]) is not str or not HEX.fullmatch(manifest["expected"]):
            raise ValueError("Expected version required")
        if operation == "write":
            replacement = safe_text(manifest["content"])
        else:
            if type(manifest["backup"]) is not str or not UUID.fullmatch(manifest["backup"]):
                raise ValueError("Invalid backup reference")
            row = self.db.execute("SELECT agent,path,before_hash,backup,root FROM jobs WHERE request=?", (manifest["backup"],)).fetchone()
            if row is None or row[:2] != (manifest["agent"], manifest["path"]) or row[3] is None or digest(row[3]) != row[2] or row[4] != root:
                raise ValueError("Backup is not valid for this file")
            replacement = safe_text(row[3].decode("utf-8"))
        with parent_directory(root, manifest["path"]) as (parent, name):
            directory = os.fstat(parent)
            if directory.st_uid != os.getuid() or directory.st_mode & 0o022:
                raise ValueError("Write directory must be manager owned")
            original, metadata = read_at(parent, name)
            if (metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) not in {0o600, 0o640}
                    or metadata.st_gid not in {os.getgid(), *os.getgroups()}):
                raise ValueError("Unsupported write ownership or permissions")
            plain_write_metadata(parent, name, metadata)
            if digest(original) != manifest["expected"]:
                raise ValueError("Concurrent change")
            self.verify(manifest, approval, time.time())
            result = {"agent": manifest["agent"], "path": manifest["path"], "before": digest(original),
                      "after": digest(replacement), "rollback": manifest["request"]}
            # Commit backup and intended result before touching the target.
            with self.db:
                self.db.execute("UPDATE jobs SET state='prepared',agent=?,path=?,before_hash=?,after_hash=?,backup=?,result=?,root=? WHERE request=?", (manifest["agent"], manifest["path"], digest(original), digest(replacement), original, json.dumps(result), root, manifest["request"]))
                self.event(manifest["request"], "prepared")
            temporary = ".agent-manager-" + str(uuid.uuid4())
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            try:
                with os.fdopen(fd, "wb") as output:
                    output.write(replacement)
                    output.flush()
                    os.fchown(output.fileno(), -1, metadata.st_gid)
                    os.fchmod(output.fileno(), metadata.st_mode & 0o777)
                    no_acl(output.fileno())
                    os.fsync(output.fileno())
                    staged_identity = identity(os.fstat(output.fileno()))
                with self.db:
                    self.db.execute("UPDATE jobs SET identity=? WHERE request=?", (json.dumps(staged_identity), manifest["request"]))
                current, observed = read_at(parent, name)
                if digest(current) != digest(original) or (observed.st_dev, observed.st_ino, observed.st_ctime_ns) != (metadata.st_dev, metadata.st_ino, metadata.st_ctime_ns):
                    raise ValueError("Concurrent change")
                self.verify(manifest, approval, time.time())
                self.inventory()
                plain_write_metadata(parent, name, observed)
                os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
                updated, updated_meta = read_at(parent, name)
                if digest(updated) != digest(replacement) or identity(updated_meta) != staged_identity:
                    raise ValueError("Write validation failed")
            finally:
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    pass
            return result
