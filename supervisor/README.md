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

## PR #3: opt-in local diagnostics

Repository development and CI never contact a VPS. This implementation is for
future, separately approved deployment on Linux; no deployment is part of this PR.
Diagnostics is disabled by default. A future operator can configure
`SUPERVISOR_DIAGNOSTICS_ISSUE` to one positive issue number (at most nine digits).
Only `BlueDev180/openclaw-dev` is supported. That issue must be open, must be an
issue rather than a pull request, and must have all of these exact fields:

- Author login: `BlueDev180`, account type `User`
- Title: `Supervisor read-only diagnostics`
- Entire body: `supervisor:diagnostics:v1` (no additional whitespace or instructions)

The request is fetched directly from a fixed GitHub API endpoint, independently
of the observer's first 30 issues. Issue URLs and other issue text are never used
as instructions, paths, output, or network destinations. No shell, SSH, subprocess,
OpenClaw dispatch, model call, or service control is involved.

A comment contains only numeric CPU load averages for 1/5/15 minutes (not CPU
utilization percentages), available RAM from `/proc/meminfo`, free/total space
for `/`, and uptime from `/proc/uptime`. No hostname, mount inventory, environment,
process list, raw file contents, credential, or trading data is published. These
aggregate host metrics would be public when posted to a public issue. Missing
or invalid metrics fail closed. Collection supports Linux only.

The credential comes only from `github_token` in the systemd credential directory;
it must be nonempty and contain only ASCII letters, digits and underscores.
Use a repository-scoped credential with only the issue permissions needed for
reading requests and writing comments. Diagnostics HTTP requests reject redirects
and use a 15-second timeout. Exceptions reach the existing main-loop handler,
which logs only the exception class, never response bodies or token values.

Deduplication uses an exclusive, flushed `diagnostics-v1-issue-N` reservation in
the existing private state directory before sending a comment. Multiple workers
sharing that directory and subsequent polls/restarts cannot post another comment.
A successful response changes the reservation to `posted`. An ambiguous or failed
POST leaves it `reserved`: automatic retries could duplicate an accepted comment.
An operator must review the issue and reservation before any manual recovery.
Retain state across restarts; deletion/loss of state or separate state directories
can permit another post. This is at-most-one POST attempt per retained reservation,
not guaranteed delivery. Protect the state directory from untrusted local writers.
The only local writes are Supervisor state; diagnostic collection is read-only.

No recognized diagnostics issue is created by this change, and no diagnostics
comment is sent during development. The existing connection acknowledgement is
unchanged. Existing observer/acknowledgement transport remains a legacy path;
the redirect protections described above apply to the new diagnostics transport.
