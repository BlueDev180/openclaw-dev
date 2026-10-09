"""Opt-in private GitHub transport for the separate agent management identity."""
import base64
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import time
import urllib.request

from agent_management import Manager, canonical, digest, load_policy, UUID
from diagnostics import NoRedirect, trusted, AUTHOR_ID, REPOSITORY

API = "https://api.github.com/repos/" + REPOSITORY
TITLE = "Supervisor agent management"
BODY = "supervisor:agent-management-channel:v1"
LINE = re.compile(r"supervisor:agent-management:v1 request=(" + UUID.pattern + r") commit=([0-9a-f]{40}) manifest=([0-9a-f]{64}) policy=([0-9a-f]{64}) expires=([1-9][0-9]{0,11}) signature=([0-9a-f]{64})")
MAX_RESPONSE = 2 * 1024 * 1024
MAX_ARTIFACT = 512 * 1024


def github(method, path, token, payload=None):
    if type(token) is not str or not re.fullmatch(r"[A-Za-z0-9_]{1,512}", token):
        raise ValueError("Invalid credential")
    # No arbitrary hosts, query strings or paths are accepted by this transport.
    if not (path == "" or path == "user" or re.fullmatch(
            r"/issues/[1-9][0-9]*(?:/comments(?:\?per_page=100&page=[1-9][0-9]*)?)?|/issues/comments/[1-9][0-9]*|/git/commits/[0-9a-f]{40}|/contents/(?:agent-requests|agent-snapshots)/[0-9a-f-]{36}\.json(?:\?ref=[0-9a-f]{40})?", path)):
        raise ValueError("Endpoint forbidden")
    if method not in {"GET", "PUT", "POST"} or method == "PUT" and not re.fullmatch(r"/contents/agent-snapshots/[0-9a-f-]{36}\.json", path) or method == "POST" and not re.fullmatch(r"/issues/[1-9][0-9]*/comments", path):
        raise ValueError("Method forbidden")
    url = "https://api.github.com/user" if path == "user" else API + path
    headers = {"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
               "Content-Type": "application/json", "User-Agent": "agent-manager/1",
               "X-GitHub-Api-Version": "2022-11-28"}
    req = urllib.request.Request(url, headers=headers, method=method,
                                 data=canonical(payload) if payload is not None else None)
    with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect).open(req, timeout=15) as response:
        if response.status != (200 if method == "GET" else 201):
            raise ValueError("Unexpected API status")
        raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise ValueError("Response limit")
        return json.loads(raw)


def private(token, repo_id):
    value = github("GET", "", token)
    if (type(value) is not dict or value.get("private") is not True
            or type(value.get("id")) is not int or value["id"] != repo_id
            or value.get("full_name") != REPOSITORY or value.get("archived") is not False):
        raise ValueError("Private repository verification failed")


def channel(token, issue):
    value = github("GET", f"/issues/{issue}", token)
    if (type(value) is not dict or type(value.get("number")) is not int or value["number"] != issue
            or value.get("state") != "open" or "pull_request" in value
            or value.get("title") != TITLE or value.get("body") != BODY or not trusted(value.get("user"))):
        raise ValueError("Channel verification failed")


def comments(token, issue):
    result = []
    for page in range(1, 11):
        values = github("GET", f"/issues/{issue}/comments?per_page=100&page={page}", token)
        if type(values) is not list or len(values) > 100:
            raise ValueError("Invalid comments")
        result.extend(values)
        if len(values) < 100:
            return result
    raise ValueError("Channel limit")


def parse(comment, repo_id):
    if (type(comment) is not dict or not trusted(comment.get("user"))
            or type(comment.get("id")) is not int or comment["id"] <= 0
            or type(comment.get("created_at")) is not str
            or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", comment["created_at"])
            or comment.get("created_at") != comment.get("updated_at")
            or type(comment.get("body")) is not str):
        raise ValueError("Request identity failed")
    match = LINE.fullmatch(comment["body"])
    if not match:
        raise ValueError("Unrecognized request")
    request, commit, manifest, policy, expires, proof = match.groups()
    return {"claim": {"repo": repo_id, "owner": AUTHOR_ID, "request": request,
                      "commit": commit, "manifest": manifest, "policy": policy, "expires": int(expires)},
            "signature": proof}


def decode_content(value, limit):
    if type(value) is not dict or value.get("type") != "file" or value.get("encoding") != "base64" or type(value.get("content")) is not str:
        raise ValueError("Unexpected content response")
    if len(value["content"]) > limit * 2:
        raise ValueError("Content limit")
    raw = base64.b64decode(value["content"].replace("\n", ""), validate=True)
    if len(raw) > limit or value.get("sha") != hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest():
        raise ValueError("Content integrity failed")
    return raw


def report_matches(value, reporter, marker):
    return (type(value) is dict and type(value.get("user")) is dict
            and type(value["user"].get("id")) is int and value["user"]["id"] == reporter
            and value["user"].get("type") == "User" and type(value.get("body")) is str
            and value["body"].startswith(marker + "\n"))


def run_once(manager, token, issue, reporter):
    private(token, manager.repo_id)
    identity = github("GET", "user", token)
    if type(identity) is not dict or type(identity.get("id")) is not int or identity["id"] != reporter or identity.get("type") != "User":
        raise ValueError("Reporter identity failed")
    channel(token, issue)
    observed = comments(token, issue)
    manager.db.execute("CREATE TABLE IF NOT EXISTS outbox(request TEXT PRIMARY KEY, hash TEXT, state TEXT)")
    manager.db.commit()
    handled = 0
    for item in observed:
        # Ignore ordinary discussion without parsing it as instructions.
        if type(item) is not dict or type(item.get("body")) is not str or not item["body"].startswith("supervisor:agent-management:v1 "):
            continue
        try:
            approval = parse(item, manager.repo_id)
            completed = manager.db.execute("SELECT state FROM outbox WHERE request=?", (approval["claim"]["request"],)).fetchone()
            if completed and completed[0] == "posted":
                continue
            fresh = github("GET", f"/issues/comments/{item['id']}", token)
            if fresh.get("id") != item["id"] or parse(fresh, manager.repo_id) != approval:
                raise ValueError("Request changed")
            claim = approval["claim"]
            commit = github("GET", "/git/commits/" + claim["commit"], token)
            if type(commit) is not dict or commit.get("sha") != claim["commit"]:
                raise ValueError("Commit mismatch")
            blob = github("GET", f"/contents/agent-requests/{claim['request']}.json?ref={claim['commit']}", token)
            raw = decode_content(blob, 65536)
            manifest = json.loads(raw)
            if raw != canonical(manifest):
                raise ValueError("Canonical manifest required")
            manager.verify(manifest, approval, time.time())
            if handled >= 5:
                break
            handled += 1
            channel(token, issue)
            private(token, manager.repo_id)  # Refuse local effects if the repository became public.
            response = manager.execute(manifest, approval)
            if response["state"] != "applied":
                continue
            artifact = canonical({"version": 1, "request_commit": claim["commit"],
                                  "policy_sha256": claim["policy"], "response": response})
            if len(artifact) > MAX_ARTIFACT:
                raise ValueError("Artifact limit")
            artifact_hash = digest(artifact)
            marker = f"<!-- supervisor-agent-management:v1 request={claim['request']} result={artifact_hash} -->"
            path = f"/contents/agent-snapshots/{claim['request']}.json"
            with manager.lock():
                existing = manager.db.execute("SELECT hash,state FROM outbox WHERE request=?", (claim["request"],)).fetchone()
                if existing:
                    if existing[0] != artifact_hash:
                        raise ValueError("Artifact changed")
                    if existing[1] == "reserved":
                        remote = decode_content(github("GET", path, token), MAX_ARTIFACT)
                        if digest(remote) == artifact_hash and any(report_matches(c, reporter, marker) for c in observed):
                            with manager.db:
                                manager.db.execute("UPDATE outbox SET state='posted' WHERE request=?", (claim["request"],))
                    continue
                with manager.db:
                    manager.db.execute("INSERT INTO outbox VALUES(?,?,'reserved')", (claim["request"], artifact_hash))
                private(token, manager.repo_id)
                result = github("PUT", path, token, {"message": "Store approved agent management result", "content": base64.b64encode(artifact).decode("ascii")})
                expected_git = hashlib.sha1(b"blob " + str(len(artifact)).encode() + b"\0" + artifact).hexdigest()
                if type(result) is not dict or type(result.get("content")) is not dict or result["content"].get("sha") != expected_git:
                    raise ValueError("Ambiguous artifact write")
                private(token, manager.repo_id)
                channel(token, issue)
                body = marker + "\nApproved agent request completed. Result: agent-snapshots/" + claim["request"] + ".json"
                posted = github("POST", f"/issues/{issue}/comments", token, {"body": body})
                if not report_matches(posted, reporter, marker) or posted["body"] != body:
                    raise ValueError("Ambiguous report")
                with manager.db:
                    manager.db.execute("UPDATE outbox SET state='posted' WHERE request=?", (claim["request"],))
        except Exception:
            logging.warning("Agent management request held; inspect private audit state")


def poll_once():
    if os.environ.get("SUPERVISOR_AGENT_MANAGEMENT_ENABLED") != "1":
        return
    manager = None
    try:
        values = []
        for setting in ("SUPERVISOR_OPERATIONS_REPO_ID", "SUPERVISOR_AGENT_MANAGEMENT_ISSUE", "SUPERVISOR_OPERATIONS_REPORTER_ID"):
            value = os.environ.get(setting, "")
            if not re.fullmatch(r"[1-9][0-9]{0,17}", value):
                raise ValueError("Configuration required")
            values.append(int(value))
        credentials = Path(os.environ["CREDENTIALS_DIRECTORY"])
        with (credentials / "agent_management_token").open(encoding="ascii") as source:
            token = source.read(513).strip()
        if not re.fullmatch(r"[A-Za-z0-9_]{1,512}", token):
            raise ValueError("Invalid token")
        with (credentials / "agent_approval_key").open(encoding="ascii") as source:
            key = source.read(66).strip()
        if not re.fullmatch(r"[0-9a-f]{64}", key):
            raise ValueError("Invalid approval key")
        policy = load_policy(os.environ["SUPERVISOR_AGENT_POLICY"])
        manager = Manager(policy, os.environ["SUPERVISOR_AGENT_STATE_DIR"], bytes.fromhex(key), values[0], AUTHOR_ID)
        run_once(manager, token, values[1], values[2])
    except Exception:
        logging.warning("Agent management poll disabled or deferred; check private configuration")
    finally:
        if manager is not None:
            manager.close()


def main():
    # Standalone periodic invocation only; never imported into the live diagnostics loop.
    logging.basicConfig(level=logging.INFO)
    poll_once()


if __name__ == "__main__":
    main()
