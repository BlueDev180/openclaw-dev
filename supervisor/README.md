# VPS Supervisor: public development, private operations

This standard-library Python observer has no shell, subprocess, SSH, model API,
OpenRouter/Sonnet token requirement, or service-control path. GPT-6 can develop
and review source in the public `BlueDev180/openclaw-dev` repository. The
Supervisor performs only the fixed, read-only diagnostics described below.
Development and CI use synthetic data and never contact the VPS.

## Private repository setup (manual, no repository created by this PR)

The GitHub connection returned 404 for `BlueDev180/vps-operations` during this
revision. This cannot distinguish absence from lack of connector access. Check
in the owner's GitHub account. If absent, create **a private repository** named
`vps-operations`, with Issues enabled. Never copy operational reports to public
issues, PRs, Actions artifacts, source fixtures, or public AI conversations.
Restrict membership and administrative rights; keep the repository private.
Do not add Actions workflows, deployment integrations, or production secrets.

The implementation supports this exact repository only. Obtain its numeric
repository ID from GitHub's repository API using an authorized account; it must
be configured locally and is checked against every metadata response. Wrong ID,
404/403, public visibility, missing fields, rename/transfer, or archived status
fail closed. Before each report POST, privacy and identity are checked again.
There is no public fallback.

Create an open issue authored by `BlueDev180` with exactly:

- Title: `Supervisor private diagnostics`
- Entire body: `supervisor:diagnostics-channel:v2`

Configure its issue number locally. An issue is a fixed communication channel,
not an executable task. PRs and other titles, bodies or authors are rejected.
The owner's login and public numeric GitHub account ID are both pinned in code.
Changing the trusted identity requires code review, not an issue instruction.

## Credential and configuration

Use a short-lived fine-grained personal access token, owned by the reporting
account, selected for **only vps-operations**, with **Issues: read and write** and
**Metadata: read**. No Contents, Actions, Administration, deployment, SSH or
trading permissions are required. GitHub's issue permissions allow reading
requests and writing issue comments. Confirm the token's account ID through
`GET /user` and pin that ID locally. This version supports user-owned PATs,
not GitHub App installation tokens; a dedicated least-privilege reporting account
is preferable where available. Keep the token's account and repository access
under owner control, set expiry, rotate/revoke it when needed, and protect the
owner account with MFA.

References: [fine-grained tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
and [REST permissions](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens).

The credential is read only from the systemd credential named `operations_token`
in `CREDENTIALS_DIRECTORY`. No environment token, repository secret, or legacy
`github_token` fallback is accepted. Provision it outside the repository through
systemd `LoadCredential`/`LoadCredentialEncrypted` as supported on the eventual
host; never put the token value in a unit file, command argument or shell history.
Do not give the operations token access to public development writes. The legacy
public observer uses only its separate optional `github_token` credential.

Diagnostics is **disabled by default**. A future, separately approved service
configuration must supply all of:

| Setting | Required value |
| --- | --- |
| `SUPERVISOR_DIAGNOSTICS_ENABLED` | Exactly `1` |
| `SUPERVISOR_OPERATIONS_REPO_ID` | Verified numeric ID of private vps-operations |
| `SUPERVISOR_OPERATIONS_ISSUE` | Number of the recognized channel issue |
| `SUPERVISOR_OPERATIONS_REPORTER_ID` | Numeric user ID returned for the PAT |
| `CREDENTIALS_DIRECTORY` | Provided by systemd; contains `operations_token` |
| `SUPERVISOR_STATE_DIR` | Private, persistent local state directory |

Numeric values must be positive decimal integers of at most 18 digits. The old
v1 diagnostics setting cannot enable diagnostics. `SUPERVISOR_REPO` no longer
changes the public observer's destination; it is pinned to `openclaw-dev` so
private requests cannot enter its legacy status snapshot. Operations responses,
request bodies and metrics are never written to `status.json`.

## Repeated requests and reports

In the private channel issue, `BlueDev180` posts a new, unedited comment containing
exactly one line with a fresh lowercase UUID v4:

```text
supervisor:diagnostics:v2 request=12345678-1234-4123-8123-123456789abc
```

This example is synthetic: generate a new UUID for each real request. No additional
whitespace or prose is accepted. GitHub-authenticated metadata must match the
pinned owner login, numeric ID and account type. Requests must be no more than
24 hours old and no more than 60 seconds in the future; edited comments are
rejected. The request is fetched again before collection. Issue text, URLs,
headers and pagination links never become instructions or destinations.
The credential's authenticated identity is checked separately on every poll.

The Supervisor posts a matching request UUID and source comment ID plus numeric
CPU load averages, a 0.2-second aggregate CPU utilization sample when available,
available/total RAM, root filesystem free/total capacity, and uptime. It reads
only fixed `/proc/meminfo`, `/proc/uptime`, aggregate `/proc/stat`, OS load and
root disk usage interfaces. CPU guest counters are excluded to avoid double
counting; idle and I/O wait are treated as nonbusy. Resets, a zero delta or missing
CPU counters yield `unavailable`. Invalid mandatory metrics fail before delivery
reservation and may be safely attempted in a later poll.

No hostnames, addresses, mount inventory, process/service lists, Docker metadata,
raw file contents, environment variables, credentials, logs or trading data are
reported. Optional service/container health checks are deliberately omitted.
The report is visible to private repository readers and GitHub; share it only
with authorized recipients. No diagnostics request or report was sent as part
of developing this PR.

API calls use fixed HTTPS endpoints, verified TLS, redirect rejection, no ambient
proxy, 15-second timeouts, and a 1 MiB response limit. Up to ten pages of 100
comments are read using constructed page numbers; a full ten-page window fails
closed rather than processing an incomplete history. At most five new valid
requests are handled per poll. Before reaching 1,000 comments, close the old
channel and configure a new recognized owner-authored issue, retaining the ledger.
Expired requests require a new comment and UUID. API/rate-limit failures wait for
a future regular poll without executing anything.

## Idempotency, concurrency and recovery

A private persistent SQLite ledger, `operations-diagnostics.sqlite3`, stores only
repository ID, channel number, UUID, source comment ID and delivery state. It
stores no report body or token. A transaction with `synchronous=FULL` reserves
one POST attempt per repository/UUID before posting. Independent local workers
must share this same persistent ledger. A duplicate UUID, including one in a
new comment or another channel issue, cannot cause another POST.

A verified successful API response marks delivery `posted`. Lost responses,
network failures, crashes after reservation, and unexpected POST responses leave
`reserved`. Later polls reconcile a matching report only when its sender ID
matches the authenticated reporting account and its marker matches the stored
source comment ID. They **never retry a reserved POST**, even if no report is
visible. New request UUIDs can still proceed. A crash after reservation but before
sending may therefore produce no report; this favors avoiding duplicate delivery.

For an unresolved reservation, an authorized operator reviews the private issue
and local ledger before issuing a fresh UUID if another sample is needed. Do not
delete reservations to force a retry. Preserve the ledger during updates and
rollback. Loss/corruption of the ledger, independent directories/hosts, or a
restored older backup defeats the at-most-once guarantee; GitHub has no atomic
idempotency key for issue comments. Corrupt/locked state fails closed. No automatic
state deletion, recovery command or escalation is provided.

Logs use fixed generic failure messages with no exception strings, tracebacks,
request IDs, token values, response bodies or diagnostic values. The committed
service template sets `StateDirectoryMode=0700` and `UMask=0077`. The eventual
operator must verify ownership, permissions, disk reliability and durable local
storage; untrusted local writers must not control state or credentials.

## Deployment plan (documentation only; separate explicit approval required)

1. Review PR #3 and all Python 3.11/3.12/3.13 checks. Obtain the owner's explicit
   approval before merging that specific PR. Passing CI is not approval.
2. Prepare the private repository, channel issue, scoped PAT and verified numeric
   IDs manually. Confirm repository access/visibility and keep sensitive values
   outside this public repository. No operational configuration is committed.
3. Propose an exact reviewed commit, target, maintenance window and rollback
   version; obtain separate explicit owner approval before any VPS access or
   deployment. This PR performs none of those actions.
4. After that separate approval, privately preserve the existing Supervisor code,
   unit/configuration and persistent state. Verify the host's Python, Linux proc
   interfaces, SQLite support and systemd credential support. Do not inspect or
   change OpenClaw, trading configurations or trading containers.
5. Stage both `supervisor.py` **and** its sibling `diagnostics.py` from the exact
   approved commit as an unprivileged Supervisor. A single-file download is no
   longer sufficient. Apply a reviewed unit/configuration with diagnostics still
   disabled; no automatic main-branch downloads or deployment workflow.
6. Verify the private state permissions and credential provision. Only under the
   approved deployment plan, enable diagnostics and restart the Supervisor alone.
   Submit one private synthetic request, then a fresh UUID, and confirm report
   identity and no duplicate on repeated polls. Observe only authorized private
   output. If validation fails, disable and follow the approved rollback plan.

## Rollback plan (documentation only)

Disable `SUPERVISOR_DIAGNOSTICS_ENABLED`, remove its credential mapping, and revoke
or rotate the PAT if privacy or credential integrity is in question. Under the
approved rollback authorization, restore the privately preserved predeployment
Supervisor version and unit/configuration, restart only the Supervisor, and retain
the complete v2 ledger and its permissions. Remove obsolete v1 diagnostic settings
too; do not restore a public-reporting v1 configuration. Confirm no private-channel
polling or new reports occur. Do not delete existing private reports automatically
or copy them into public rollback notes. Trading services remain outside this plan.

## Remaining security limits

This is authenticated GitHub polling, not a signed end-to-end command channel.
Compromise of the pinned owner, reporting account, GitHub, or local Supervisor
account remains in the trust boundary. The reporting account can edit its own
reports; a compromised trusted reporter can forge reconciliation markers. Access
controls, MFA, short-lived scoped credentials and restricted repository membership
must therefore be managed outside the code. HTTPS keeps tokens out of redirects
but cannot protect against compromised trust roots or the host itself.

Repository visibility cannot be atomically locked with a comment POST: a private-
to-public change immediately after the final check can expose a report, and
changing visibility later exposes existing reports. Keep the repository permanently
private and tightly restrict administrators. No system posting health data to a
GitHub repository can override that administrator-controlled visibility risk.
Metrics are host aggregates; root disk excludes other mounts, CPU utilization is
a brief sample, and mandatory interfaces require Linux. No live environment was
verified and no GPT/model runtime is required by this diagnostic implementation.
