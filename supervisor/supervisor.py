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
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "vps-supervisor-readonly/0.1",
    })
    with urllib.request.urlopen(req, timeout=15) as resp:
        issues = json.load(resp)
    tasks = [{"number": i["number"], "title": i["title"], "url": i["html_url"]}
             for i in issues if "pull_request" not in i]
    return tasks

def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    while not STOP:
        try:
            tasks = poll()
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
