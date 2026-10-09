# Secure agent management: architecture and deployment boundary

This is a disabled, standalone Linux worker for private GitHub requests. It never calls models, executes commands, accesses Docker, modifies native OpenClaw configuration, or changes the existing diagnostics worker. Development and CI stay public; requests, approvals and results belong exclusively in private `BlueDev180/vps-operations`. No deployment or production discovery has occurred.

## Implemented scope and missing production facts

Implemented: sanitized inventory; reads and timestamped snapshots of exact reviewed instruction/knowledge contents; approved edits to existing allowlisted files; durable local pre-write backups; approved restore; agent-registration and WhatsApp-routing proposals. Every operation requires a signed owner approval for an immutable request commit. This version does not create files or workspaces.

Native creation and routing activation remain proposals: the installed OpenClaw version, effective registry schema, workspace mounts, ownership and reload behavior are unverified. `prepare_agent` and `prepare_routing` do not register agents or change bindings. This is a foundation for review, not a complete production deployment.

The inventory includes every entry in a root-owned operator-reviewed projection, including `main`, `sous-chef` and future agents supplied by the operator. Native additions require the operator to refresh this projection; there is no automatic native registry parser. Unknown workspace aliases appear as unmanaged. Configuration references are opaque aliases; WhatsApp summaries contain only a boolean and binding count, never accounts, recipients, phone numbers or session material.

Official discovery references: [agent commands](https://docs.openclaw.ai/cli/agents), [workspaces](https://docs.openclaw.ai/agent-workspace), [multi-agent configuration](https://docs.openclaw.ai/multi-agent). Verify the installed version rather than assuming these current documents match it.

## Architecture and trust boundaries

1. Developers/GPT prepare canonical JSON at `agent-requests/<UUID-v4>.json` in the private repository and record its exact 40-character commit SHA. Repository text and model output are untrusted data.
   For normal operation, propose this through a private pull request describing the full edit, expected hash, validation and rollback reference. Run the reviewed offline validation suite with synthetic fixtures; the owner checks its results before signing. The worker does not install a private workflow or query Actions/PR approval status: the human signature certifies review of the exact commit. A PR approval or CI result alone is not execution authority.
2. The human owner independently reviews the complete immutable content, operation, target alias/path, expected current SHA-256 and trusted local policy/inventory fingerprint. The owner signs a bounded claim with a dedicated key outside GitHub. Comments alone cannot authorize execution.
3. The channel must have exact title `Supervisor agent management`, exact body `supervisor:agent-management-channel:v1`, remain open, and be authored by `BlueDev180`, numeric ID `225409111`, type `User`. Protocol comments must have that same identity and unchanged creation/update timestamps. Repeated requests use distinct UUIDs in the same channel.
4. The worker verifies private visibility, configured numeric repository ID, full name and non-archived status; pins the reporting identity; refetches the comment; fetches the exact commit and bounded blob; checks Git blob integrity and canonical encoding; checks HMAC signature, manifest hash, policy/inventory hash and expiry (maximum one hour).
5. A separate unprivileged OS identity sees only its private state, root-owned sanitized policy/projection and explicit instruction roots. Directory descriptors, no-follow opens and exact path/type rules deny arbitrary paths, links, devices, sockets, FIFOs and executables. Other-user writable paths are refused.
6. A process lock and durable SQLite ledger serialize changes. Backup and intended result are committed before staging a temporary file. Expected hash and inode/content are rechecked before atomic replacement, sync and validation. A UUID cannot identify different content; successful retries return the cached result.
7. Results are created at `agent-snapshots/<UUID>.json` without an existing-file SHA. The worker never updates an existing artifact. A persistent outbox reserves publication before GitHub calls. Comments contain a result hash and relative artifact reference rather than contents or infrastructure details.

Manifest text cannot select a host, command, credential name, filesystem root or arbitrary API path. HTTPS endpoints are fixed, proxies/redirects disabled, responses bounded and requests timed out after 15 seconds. No shell/subprocess, native reload, model client or automatic deployment is included.

## Threat model and limitations

- Forged identities, changed manifests, edited comments, wrong repository/commit/policy, expired or unsigned claims fail closed. Ordinary discussion is ignored. A GitHub write token alone is insufficient without the dedicated owner signing key.
- HMAC is a shared secret: the verifier has the key. A compromised manager/host or operator who reads it can forge approvals. This is not hardware-backed signing or non-repudiation. Root, compromised policy, administrators, or theft of both owner identity and key are outside the boundary. A future asymmetric verifier could narrow this risk.
- Pattern matching cannot identify every secret. Export additionally requires an independently reviewed **exact content hash** in local policy, UTF-8/size checks and deny-pattern scanning. Exclude raw configuration, credentials, logs, sessions, conversations, trading data and credential-bearing files entirely. A write does not authorize publishing its resulting text. Private GitHub is not a secret store.
- Pre-write backups stay in private local SQLite state, never automatically uploaded. Restore checks their hash and target identity. These backups can contain previously unreviewed instruction text; protect them privately. Worker code never overwrites backups, but host administrators can alter/delete state. GitHub artifacts are append-only to this worker; administrators can rewrite history or visibility.
- Visibility checks cannot atomically guarantee the repository stays private during/after an API write. Administratively restrict visibility, membership and integrations. If this residual risk is unacceptable, leave publication disabled.
- POSIX rename is not compare-and-swap against unrelated writers. Deployment MUST give this worker sole write ownership of each managed file **and parent**, with OpenClaw/other identities read-only. Locks serialize cooperating workers; hash/inode checks detect prior changes, but cannot eliminate a last-instant hostile external write. Shared writable mounts are unsuitable.
- Transactions change one existing file at a time. Multi-file atomic edits, native registration and routing activation are unsupported. Schema-valid prose still requires human semantic review. Do not approve instructions that alter trading behavior as incidental management work.
- A crash before rename is held; after rename, the intended content hash can identify completion without reapplying. Differing current content is held for investigation. A hard crash can leave staging files; inspect and remove them only with the worker stopped and separate operator approval.
- An ambiguous GitHub response never triggers automatic reposting/overwrite. Reconciliation marks posted only when the expected artifact and authenticated reporter comment are both visible. Otherwise keep the reservation; never delete ledger rows to force a retry. Expired approvals require a newly signed claim for the same immutable manifest with fresh expiry; no local effect is repeated.
- Each invocation processes at most five valid pending requests and loads at most 1,000 comments. Completed requests do not block later ones. Rotate to a separately verified/configured channel before the comment bound. No scheduler is installed.

## Private policy and projection

Actual paths remain private and unverified. Root owns policy/projection; the manager cannot write them. Trusted ancestors and non-group/world-writable roots are mandatory. Any policy/projected inventory change requires a new fingerprint and approval.

Illustrative policy (synthetic locations; replace the hash placeholder with an independently reviewed SHA-256):

```json
{"version":1,"registry":"/operator-selected/private/registry.json","roots":{"main-root":{"path":"/operator-selected/workspace","files":{"AGENTS.md":{"write":true,"publish":["<reviewed 64-character SHA-256>"]},"knowledge/reference.md":{"write":false,"publish":[]}}}}}
```

Projection: include all privately verified registered agents using aliases and sanitized counts only; never paste native configuration:

```json
{"version":1,"source_version":"verified-version","agents":[{"id":"main","workspace":"main-root","config_ref":"main-config","whatsapp":{"configured":true,"binding_count":1}},{"id":"sous-chef","workspace":"chef-root","config_ref":"chef-config","whatsapp":{"configured":false,"binding_count":0}}]}
```

Only exact configured `AGENTS.md`, `SOUL.md`, `IDENTITY.md`, `prompts/<lowercase-slug>.md` and `knowledge/<lowercase-slug>.md` are permitted. Exclude `USER.md`, `MEMORY.md`, `TOOLS.md`, hidden files, JSON, scripts and auth/session/config trees. Existing files must be regular, single-link, non-executable and at most 64 KiB. Request limit: 64 KiB. Snapshots: 1–16 unique files within a 512 KiB result envelope.

## Owner approval protocol

Canonical encoding is sorted-key JSON, compact separators, ASCII escaping and UTF-8 without BOM/trailing newline (`agent_management.canonical`). Never edit a request after hashing/approval.

All manifests have `version:1`, `request:<fresh UUID-v4>` and `operation`. Exact additional fields:

| Operation | Fields | Effect |
|---|---|---|
| `list` | none | Sanitized projected inventory |
| `read`, `snapshot` | `agent`, `paths` | Exact hash-approved contents, timestamp/version |
| `write` | `agent`, `path`, `expected`, `content` | One existing file, durable backup first |
| `restore` | `agent`, `path`, `expected`, `backup` | Local pre-write backup identified by prior UUID |
| `prepare_agent`, `prepare_routing` | `agent`, `workspace` | Proposal only; no native/file changes |

Claim fields: `repo` (verified private repo numeric ID), `owner` (225409111), `request`, `commit` (exact request commit), `manifest` (canonical manifest SHA-256), `policy` (Manager.policy_hash), `expires` (Unix seconds, future within one hour). The policy hash is SHA-256 of canonical `{"policy":<local policy>,"inventory":<SHA-256 of canonical discover(policy)>}`. Obtain it through trusted local administration after approved deployment, never merely from a model/comment.

After independent review, the owner may run the offline helper on an owner-controlled Linux computer:

```text
python3 supervisor/agent_approval.py --claim <private-claim-file> --manifest <reviewed-manifest-file> --key-file <owner-private-key-file>
```

It checks hash/claim shape and prints only the signed protocol line. It does not review semantics, verify the remote commit or post to GitHub: the owner must independently verify those, then post the unchanged line in the private channel as the pinned owner. Keep the key outside GitHub, chat, logs and command-line arguments. This development task created no keys/tokens.

## Manual GitHub and VPS prerequisites

- Verify `BlueDev180/vps-operations` is private; pin its numeric ID; enable Issues; restrict membership, integrations, visibility and history. Create the management channel with the exact title/body above as the pinned owner, recording its issue number. Do not repurpose diagnostics issue #1. This task creates no operations issue/request.
- Use a separate expiring fine-grained management token restricted to this private repo: Metadata read, Contents read/write (request reads/new results), Issues read/write. No Actions, administration, deployments, workflows, public/unrelated repository permissions. Current transport supports a pinned `User` reporter, not GitHub Apps. Prefer a dedicated restricted reporter account. GitHub's Contents permission is broader than a directory-only grant; the token can do more than worker code permits.
- Keep existing diagnostics identity/permissions unchanged. Provision a dedicated 32-byte approval key under a separately reviewed procedure; load its hex representation through systemd credentials. Retain an owner-controlled signing copy. Never include either copy in GitHub backups.
- Settings: `SUPERVISOR_AGENT_MANAGEMENT_ENABLED` defaults off; set `1` only after explicit activation approval. Also configure `SUPERVISOR_OPERATIONS_REPO_ID`, `SUPERVISOR_AGENT_MANAGEMENT_ISSUE`, `SUPERVISOR_OPERATIONS_REPORTER_ID`, `SUPERVISOR_AGENT_POLICY`, `SUPERVISOR_AGENT_STATE_DIR`, and systemd `CREDENTIALS_DIRECTORY` containing `agent_management_token`/`agent_approval_key`. No token belongs in environment values.

Required private production information: installed OpenClaw version/schema; all agent IDs; actual workspace paths/mounts, uid/gid and permissions; effective instruction files; sanitized routing counts; read-only workspace compatibility; supported reload behavior; existing Supervisor state/ownership; Python/runtime paths; private repo ID/channel/reporter; secure backup location. Server addresses, accounts and credentials stay out of public PRs.

After separate authorization, the operator may adapt read-only discovery commands `openclaw --version`, `openclaw agents list --bindings`, `openclaw agents bindings --json`. For an operator-confirmed container, `docker inspect --format '{{json .Mounts}}' <confirmed-container>` shows mounts without environment dumping. The manager must never receive Docker access. Outputs can contain private paths/routes: inspect locally and manually sanitize the projection. Never paste raw output/config into GitHub or chat. None of these commands was run against the VPS.

## Deployment checklist — separate explicit approval required

1. Review/merge the public PR only with approval. Freeze the exact reviewed source commit with passing full offline Python 3.10–3.13 CI. Never deploy a moving branch or add an automatic deployment workflow.
2. Privately back up the existing Supervisor code, unit/drop-ins, persistent diagnostics state, ownership/modes and last known commit. Separately back up managed instructions and management state with integrity hashes outside GitHub. Do not publish production material.
3. Verify the production facts above. Stop if sole-write isolation cannot be established. OpenClaw/trading mounts, routes, permissions and configs cannot be changed incidentally; any necessary change requires its own reviewed plan and approval.
4. Install the exact commit in a separate versioned directory. Use unprivileged `openclaw-agent-manager` with no sudo, Docker socket or unrelated groups. Restrict it to explicit file roots/private state and read-only root-owned policy/projection. Deny trading paths, auth/session/native config and unrelated Supervisor state.
5. Review `supervisor/agent-management.service.example`: disabled default, no install/timer. Configure exact state/approved-parent `ReadWritePaths`, read-only policy/projection, and `LoadCredential` entries through a separately reviewed drop-in. Its code path is illustrative, not verified. Validate sandbox options against the installed systemd version. No scheduler/automatic retry is configured.
6. Run separately approved staged offline tests under the target identity with synthetic fixtures and mocked GitHub: visibility, identities/signatures, denied paths, stale versions, crash recovery and rollback. No trading credential/container is a fixture.
7. With explicit enablement approval, manually invoke a signed private `list`, then a hash-approved snapshot. Verify private artifact/comment, public repository unchanged and no extra data. Each instruction edit/restore requires exact-content approval; use an authorized disposable non-trading fixture first. Native activation/routing are unsupported and need a future adapter plus approval.
8. Compare separately authorized read-only trading health checks with a pre-deployment baseline: container identities/start times, mounts/config hashes and service status. No trading restart/write is part of this plan.

## Rollback and failure recovery

Under separate production approval, disable/stop only the new management invocation. Preserve SQLite state, audit and pending outbox reservations; never reset the ledger or reuse UUIDs. Leave existing diagnostics/Supervisor and trading services untouched.

For an applied instruction edit, verify backup target/hash. Create a **new** immutable `restore` manifest containing the current target hash and original request UUID as `backup`; obtain a fresh owner signature. Restore follows the same durable backup, atomic replacement and validation, preserving the replaced version for reversing the restore. Unexpected current content requires investigation rather than overwrite. Offline tests cover rollback, corruption refusal, rename failure and post-rename crash recovery.

For worker regression, restore prior reviewed code/unit/drop-in and leave management disabled. Restore privately backed-up policy/projection only after integrity and retained-state compatibility checks. Ambiguous publication is reconciled only against the expected immutable artifact and authenticated comment. Missing/uncertain publication remains held; there is no resend/reset switch. Never overwrite artifacts or delete ledger records to force execution.

Native configuration rollback is outside scope because native configuration is never written. No trading/OpenClaw restart is required by the file algorithm; any runtime reload requires separate approval after behavior is verified.

## Verification

Offline tests use synthetic root-ownership projections, temporary Linux files, mocked GitHub responses, synthetic keys/tokens and a network-call guard. Coverage includes authenticated content binding/expiry, path/type restrictions, release hashes/secret gates, future-agent inventory, backups/rollback, concurrency, deduplication, rename failures/crashes, forged markers and uncertain publication. Existing diagnostics and Python 3.10–3.13 CI remain intact. Linux filesystem tests skip on Windows; Linux CI is the complete run. Python 3.10 CI does not establish compatibility with a specific Ubuntu 3.10.12 patch release or unverified production layout.
