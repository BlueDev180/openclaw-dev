"""Fixed local Linux diagnostics; no subprocesses or issue-directed paths."""
import json
import math
import os
import re
import shutil
import urllib.request
from pathlib import Path

TITLE = "Supervisor read-only diagnostics"
BODY = "supervisor:diagnostics:v1"
REPOSITORY = "BlueDev180/openclaw-dev"
AUTHOR = "BlueDev180"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(req):
    # Never forward a credential to a redirect destination.
    return urllib.request.build_opener(NoRedirect).open(req, timeout=15)


def credential():
    directory = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if not directory:
        return ""
    token = (Path(directory) / "github_token").read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[A-Za-z0-9_]+", token):
        return ""
    return token


def collect():
    load = os.getloadavg()
    memory = Path("/proc/meminfo").read_text(encoding="ascii")
    match = re.search(r"^MemAvailable:\s+(\d+) kB$", memory, re.MULTILINE)
    if match is None:
        raise ValueError("Available memory missing")
    available = int(match[1]) * 1024
    disk = shutil.disk_usage("/")
    uptime = float(Path("/proc/uptime").read_text(encoding="ascii").split()[0])
    values = (*load, available, disk.total, disk.free, uptime)
    if any(not math.isfinite(v) or v < 0 for v in values) or disk.free > disk.total:
        raise ValueError("Invalid metrics")
    return (f"Read-only diagnostics (v1)\n\n"
            f"CPU load averages (1/5/15 min): {load[0]:.2f} / {load[1]:.2f} / {load[2]:.2f}\n"
            f"Available RAM: {available // (1024 * 1024)} MiB\n"
            f"Root disk: {disk.free // (1024 * 1024)} MiB free / {disk.total // (1024 * 1024)} MiB total\n"
            f"Uptime: {int(uptime)} seconds\n\n"
            "No commands executed. No service or trading data inspected.")


def diagnostics_once(repo, state_dir):
    configured = os.environ.get("SUPERVISOR_DIAGNOSTICS_ISSUE", "")
    if repo != REPOSITORY or not re.fullmatch(r"[1-9][0-9]{0,8}", configured):
        return
    marker = state_dir / ("diagnostics-v1-issue-" + configured)
    if marker.exists():
        return
    token = credential()
    if not token:
        return
    url = f"https://api.github.com/repos/{REPOSITORY}/issues/{configured}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "vps-supervisor/0.3",
               "Authorization": "Bearer " + token}
    with request(urllib.request.Request(url, headers=headers)) as response:
        issue = json.load(response)
    if (type(issue) is not dict or type(issue.get("number")) is not int
            or issue["number"] != int(configured) or issue.get("state") != "open"
            or "pull_request" in issue or issue.get("title") != TITLE
            or issue.get("body") != BODY or type(issue.get("user")) is not dict
            or issue["user"].get("login") != AUTHOR or issue["user"].get("type") != "User"):
        return
    body = collect()
    # Exclusive reservation prevents concurrent workers and restarts posting twice.
    # A failed/ambiguous POST remains reserved: manual review is required.
    try:
        with marker.open("x", encoding="ascii") as reservation:
            reservation.write("reserved\n")
            reservation.flush()
            os.fsync(reservation.fileno())
    except FileExistsError:
        return
    data = json.dumps({"body": body}).encode("utf-8")
    post_headers = {**headers, "Content-Type": "application/json"}
    with request(urllib.request.Request(url + "/comments", data=data,
                                       headers=post_headers, method="POST")):
        pass
    marker.write_text("posted\n", encoding="ascii")
