# VPS Supervisor — Phase 0 (read-only)

This prototype observes open GitHub issues. It does NOT execute tasks, use OpenClaw, access secrets, change models, or modify the VPS beyond its own status file. This is intentional while establishing a safe, persistent host service.

## Ubuntu installation (after reviewing the code)
Run these commands as a sudo-capable user on the VPS:

```bash
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin vps-supervisor 2>/dev/null || true
sudo install -d -m 755 /opt/vps-supervisor
sudo curl -fL https://raw.githubusercontent.com/BlueDev180/openclaw-dev/main/supervisor/supervisor.py -o /opt/vps-supervisor/supervisor.py
sudo curl -fL https://raw.githubusercontent.com/BlueDev180/openclaw-dev/main/supervisor/vps-supervisor.service -o /etc/systemd/system/vps-supervisor.service
sudo systemctl daemon-reload
sudo systemctl enable --now vps-supervisor
sudo systemctl status --no-pager vps-supervisor
```

Check status: `sudo cat /var/lib/vps-supervisor/status.json`.
Check logs: `sudo journalctl -u vps-supervisor -n 30 --no-pager`.

The observer is separate from Docker, starts at boot, and uses Python's standard library. It reads only PUBLIC issue metadata; no GitHub token is required.

## Next milestones
1. Verify VPS operating system, service health and GitHub reachability.
2. Establish a scoped GitHub App or fine-grained token and issue reply channel.
3. Add trusted-author and explicit approval gates, plus isolation/backup checks.
4. Add supervised OpenClaw job dispatch and model routing.
5. Only then consider privileged execution, with independent recovery and explicit approval for live trading changes.

Never commit secrets, VPS credentials, proprietary recipes, or trading data to this public repository. Public issues can be written by other people; never treat issue text as trusted executable instructions.
