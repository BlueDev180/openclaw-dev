"""Private, fixed-function diagnostics. No shell, subprocess, or model calls."""
from datetime import datetime, timezone
import json
import logging
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import time
import urllib.request

REPOSITORY = "BlueDev180/vps-operations"
API = "https://api.github.com/repos/" + REPOSITORY
AUTHOR = "BlueDev180"
AUTHOR_ID = 225409111
TITLE = "Supervisor private diagnostics"
CHANNEL_BODY = "supervisor:diagnostics-channel:v2"
REQUEST = re.compile(r"supervisor:diagnostics:v2 request=([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})")
MAX_BYTES = 1024 * 1024
MAX_PAGES = 10
MAX_REQUESTS = 5
MAX_AGE = 24 * 60 * 60


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def positive(value):
    return type(value) is int and 0 < value < 2**63


def configuration():
    # Old v1 settings cannot enable public reporting. No configurable destination.
    if os.environ.get("SUPERVISOR_DIAGNOSTICS_ENABLED") != "1":
        return None
    values = []
    for name in ("SUPERVISOR_OPERATIONS_REPO_ID", "SUPERVISOR_OPERATIONS_ISSUE",
                 "SUPERVISOR_OPERATIONS_REPORTER_ID"):
        value = os.environ.get(name, "")
        if not re.fullmatch(r"[1-9][0-9]{0,17}", value):
            return None
        values.append(int(value))
    return tuple(values)


def credential():
    directory = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if not directory:
        return ""
    # Separate from the legacy public observer's github_token; never fall back.
    with (Path(directory) / "operations_token").open(encoding="ascii") as source:
        token = source.read(513).strip()
    return token if re.fullmatch(r"[A-Za-z0-9_]{1,512}", token) else ""


def api(path, token, body=None):
    # All callers construct paths from constants and validated integers.
    url = "https://api.github.com/user" if path == "user" else API + path
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "vps-supervisor/0.4",
               "Authorization": "Bearer " + token, "X-GitHub-Api-Version": "2022-11-28"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps({"body": body}).encode("utf-8")
    req = urllib.request.Request(url, headers=headers, data=data,
                                 method="GET" if body is None else "POST")
    # Ignore ambient proxy settings and never forward tokens through redirects.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
    with opener.open(req, timeout=15) as response:
        if response.status != (200 if body is None else 201):
            raise ValueError("Unexpected API status")
        raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("API response too large")
        return json.loads(raw)


def verify_private(token, repo_id):
    repo = api("", token)
    if (type(repo) is not dict or repo.get("private") is not True
            or type(repo.get("id")) is not int or repo["id"] != repo_id
            or repo.get("full_name") != REPOSITORY or repo.get("archived") is not False):
        raise ValueError("Private repository verification failed")


def trusted(user):
    return (type(user) is dict and user.get("login") == AUTHOR
            and type(user.get("id")) is int and user["id"] == AUTHOR_ID
            and user.get("type") == "User")


def verify_issue(token, issue_number):
    issue = api(f"/issues/{issue_number}", token)
    if (type(issue) is not dict or type(issue.get("number")) is not int
            or issue["number"] != issue_number or issue.get("state") != "open"
            or "pull_request" in issue or issue.get("title") != TITLE
            or issue.get("body") != CHANNEL_BODY or not trusted(issue.get("user"))):
        raise ValueError("Request channel verification failed")


def request_id(comment, now):
    if (type(comment) is not dict or not positive(comment.get("id"))
            or not trusted(comment.get("user")) or type(comment.get("body")) is not str):
        return None
    match = REQUEST.fullmatch(comment["body"])
    if not match or comment.get("updated_at") != comment.get("created_at"):
        return None
    created = comment.get("created_at")
    if type(created) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", created):
        return None
    try:
        age = now - datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None
    return match[1] if -60 <= age <= MAX_AGE else None


def comments(token, issue):
    result = []
    for page in range(1, MAX_PAGES + 1):
        batch = api(f"/issues/{issue}/comments?per_page=100&page={page}", token)
        if type(batch) is not list or len(batch) > 100:
            raise ValueError("Invalid comments page")
        result.extend(batch)
        if len(batch) < 100:
            return result
    # Do not process a partial view or follow server-supplied pagination URLs.
    raise ValueError("Request channel exceeds page limit")


def report_marker(repo_id, issue, identifier, source):
    return f"<!-- supervisor-diagnostics:v2 repo={repo_id} issue={issue} request={identifier} source={source} -->"


def matching_report(comment, reporter, marker):
    return (type(comment) is dict and positive(comment.get("id"))
            and type(comment.get("user")) is dict
            and type(comment["user"].get("id")) is int and comment["user"]["id"] == reporter
            and comment["user"].get("type") == "User"
            and type(comment.get("body")) is str and comment["body"].startswith(marker + "\n"))


def ledger(state_dir):
    # State directory must be private and persistent; no metric/report bodies stored.
    db = sqlite3.connect(state_dir / "operations-diagnostics.sqlite3", timeout=5)
    try:
        db.execute("PRAGMA synchronous=FULL")
        db.execute("CREATE TABLE IF NOT EXISTS deliveries (repo INTEGER, issue INTEGER, "
                   "request TEXT, source INTEGER, state TEXT, PRIMARY KEY(repo, request))")
        db.commit()
    except Exception:
        db.close()
        raise
    return db


def claim(db, repo, issue, identifier, source):
    with db:
        cursor = db.execute("INSERT OR IGNORE INTO deliveries VALUES (?, ?, ?, ?, 'reserved')",
                            (repo, issue, identifier, source))
    return cursor.rowcount == 1


def delivered(db, repo, issue, identifier):
    with db:
        db.execute("UPDATE deliveries SET state='posted' WHERE repo=? AND issue=? AND request=?",
                   (repo, issue, identifier))


def cpu_counters():
    line = Path("/proc/stat").read_text(encoding="ascii").splitlines()[0].split()
    if len(line) < 9 or line[0] != "cpu" or any(not x.isdigit() for x in line[1:9]):
        raise ValueError("Invalid CPU counters")
    values = [int(x) for x in line[1:9]]  # Exclude guest counters already in user/nice.
    return values


def utilization():
    try:
        first = cpu_counters()
        time.sleep(0.2)
        second = cpu_counters()
        delta = [b - a for a, b in zip(first, second)]
        total = sum(delta)
        if any(v < 0 for v in delta) or total <= 0:
            return "unavailable"
        return f"{100 * (total - delta[3] - delta[4]) / total:.1f}%"
    except (OSError, ValueError, IndexError, OverflowError):
        return "unavailable"


def collect():
    load = os.getloadavg()
    memory = Path("/proc/meminfo").read_text(encoding="ascii")
    values = []
    for field in ("MemAvailable", "MemTotal"):
        match = re.search(r"^" + field + r":\s+(\d+) kB$", memory, re.MULTILINE)
        if match is None:
            raise ValueError("Required memory metric missing")
        values.append(int(match[1]) * 1024)
    available, total_ram = values
    disk = shutil.disk_usage("/")
    uptime = float(Path("/proc/uptime").read_text(encoding="ascii").split()[0])
    all_values = (*load, available, total_ram, disk.total, disk.free, uptime)
    if (len(load) != 3 or any(not math.isfinite(v) or v < 0 or v > 2**63 - 1 for v in all_values)
            or available > total_ram or total_ram <= 0 or disk.total <= 0 or disk.free > disk.total):
        raise ValueError("Invalid metrics")
    return ("Private read-only diagnostics (v2)\n\n"
            f"CPU load averages (1/5/15 min): {load[0]:.2f} / {load[1]:.2f} / {load[2]:.2f}\n"
            f"CPU utilization (0.2-second sample): {utilization()}\n"
            f"RAM: {available // 1048576} MiB available / {total_ram // 1048576} MiB total\n"
            f"Root disk: {disk.free // 1048576} MiB free / {disk.total // 1048576} MiB total\n"
            f"Uptime: {int(uptime)} seconds\n\n"
            "No commands executed; no service, process, or trading data inspected.")


def _poll(state_dir, config, token):
    repo_id, issue, reporter = config
    verify_private(token, repo_id)
    identity = api("user", token)
    if (type(identity) is not dict or type(identity.get("id")) is not int
            or identity["id"] != reporter or identity.get("type") != "User"):
        raise ValueError("Credential identity mismatch")
    verify_issue(token, issue)
    observed = comments(token, issue)
    db = ledger(state_dir)
    try:
        # Reconcile accepted comments after a lost response/crash; never resend.
        for identifier, source in db.execute(
                "SELECT request, source FROM deliveries WHERE repo=? AND issue=? AND state='reserved'",
                (repo_id, issue)).fetchall():
            marker = report_marker(repo_id, issue, identifier, source)
            if any(matching_report(c, reporter, marker) for c in observed):
                delivered(db, repo_id, issue, identifier)
        handled = 0
        for comment in observed:
            identifier = request_id(comment, time.time())
            if identifier is None or db.execute(
                    "SELECT 1 FROM deliveries WHERE repo=? AND issue=? AND request=?",
                    (repo_id, issue, identifier)).fetchone():
                continue
            if handled >= MAX_REQUESTS:
                break
            handled += 1
            try:
                # Revalidate edited/deleted requests and channel before collecting.
                fresh = api(f"/issues/comments/{comment['id']}", token)
                if (request_id(fresh, time.time()) != identifier
                        or fresh.get("id") != comment["id"]):
                    continue
                verify_issue(token, issue)
                body = report_marker(repo_id, issue, identifier, comment["id"]) + "\n" + collect()
                verify_private(token, repo_id)  # Check visibility immediately before each POST.
                if not claim(db, repo_id, issue, identifier, comment["id"]):
                    continue
                result = api(f"/issues/{issue}/comments", token, body)
                if not matching_report(result, reporter, body.split("\n", 1)[0]) or result["body"] != body:
                    raise ValueError("Ambiguous comment response")
                delivered(db, repo_id, issue, identifier)
            except Exception:
                # Never log exception strings, response bodies, IDs or private data.
                logging.warning("Private diagnostics request deferred; review delivery state")
    finally:
        db.close()


def diagnostics_once(state_dir):
    config = configuration()
    if config is None:
        return
    try:
        token = credential()
        if token:
            _poll(state_dir, config, token)
    except Exception:
        logging.warning("Private diagnostics poll deferred; check configuration and delivery state")
