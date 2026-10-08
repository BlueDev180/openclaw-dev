#!/usr/bin/env python3
"""Read-only GitHub task observer. No shell execution or OpenClaw access."""
import json
import logging
import os
import signal
import time
import urllib.request
from pathlib import Path

REPO = os.environ.get("SUPERVISOR_REPO", "BlueDev180/openclaw-dev")
INTERVAL = max(10, int(os.environ.get("SUPERVISOR_POLL_SECONDS", "30")))
STATE_DIR = Path(os.environ.get("SUPERVISOR_STATE_DIR", "/var/lib/vps-supervisor"))
STOP = False

def stop(_sig, _frame):
    global STOP
    STOP = True

def poll():
    url = f"https://api.github.com/repos/{REPO}/issues?state=open&per_page=30"
    credential_dir = os.environ.get("CREDENTIALS_DIRECTORY", "")
    token_file = Path(credential_dir) / "github_token" if credential_dir else None
    token = token_file.read_text(encoding="utf-8").strip() if token_file and token_file.is_file() else ""
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "vps-supervisor/0.2"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=15) as resp:
        issues = json.load(resp)
    tasks = [{"number": i["number"], "title": i["title"], "url": i["html_url"]}
             for i in issues if "pull_request" not in i]
    return tasks

def acknowledge_once(tasks):
    if not any(item["number"] == 1 and item["title"] == "Supervisor connection test" for item in tasks):
        return
    marker = STATE_DIR / "acknowledged-issue-1"
    if marker.exists():
        return
    credential_dir = os.environ.get("CREDENTIALS_DIRECTORY", "")
    token_file = Path(credential_dir) / "github_token" if credential_dir else None
    if not token_file or not token_file.is_file():
        return
    token = token_file.read_text(encoding="utf-8").strip()
    data = json.dumps({"body": "VPS Supervisor authenticated reply test successful. No tasks executed."}).encode("utf-8")
    req = urllib.request.Request("https://api.github.com/repos/" + REPO + "/issues/1/comments", data=data,
        headers={"Accept": "application/vnd.github+json", "Authorization": "Bearer " + token,
                 "Content-Type": "application/json", "User-Agent": "vps-supervisor/0.2"}, method="POST")
    with urllib.request.urlopen(req, timeout=15):
        pass
    marker.write_text("ok\\n", encoding="utf-8")

def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    while not STOP:
        try:
            tasks = poll()
            acknowledge_once(tasks)
            snapshot = {"repo": REPO, "checked_at": int(time.time()), "issues": tasks}
            temp = STATE_DIR / "status.json.tmp"
            temp.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
            temp.replace(STATE_DIR / "status.json")
            logging.info("GitHub reachable; observed %d open issues (read-only)", len(tasks))
        except Exception as exc:
            logging.warning("GitHub polling failed: %s", type(exc).__name__)
        for _ in range(INTERVAL):
            if STOP:
                break
            time.sleep(1)

if __name__ == "__main__":
    main()
