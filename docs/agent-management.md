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
6. A process lock and durable SQLite ledger serialize changes and schema initialization. Backup, target root, intended result and staged inode identity are persisted before replacement. Expected hash and inode/content are rechecked, the original read group/mode preserved, and the directory synced before completion. A UUID is bound to repository, owner, commit, manifest and policy; successful retries return the cached result. Approvals are checked again after lock waits and immediately before replacement.
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
- A crash before rename is held. Post-rename recovery requires the intended hash AND recorded device/inode/owner/group/mode on the same root, followed by a successful directory sync. Different identity/content or failed sync cannot be acknowledged as complete. A hard crash may leave staging files; inspect/remove only with the worker stopped and separate operator approval.
- Artifact PUTs are reserved and never repeated automatically. If an upload was accepted but its response was lost, a later exact artifact verification can proceed to the first comment. The comment-attempt flag is committed BEFORE POST: uncertain comment acceptance, including a crash before the call, is reconciled only against an authenticated, refetched exact comment and matching artifact. It is never reposted. Otherwise hold the reservation; never delete ledger rows to force retries. Expired approvals need a fresh signature for the same immutable manifest; no local effect is repeated.
- Each invocation processes at most five valid pending requests, newest first, loading at most 1,000 comments. Completed requests are skipped, and recent work is not trapped behind old held reservations. Rotate to a separately verified/configured channel before the comment bound. No scheduler is installed.

## Private policy and projection

Actual paths remain private and unverified. Root owns policy/projection; the manager cannot write them. Trusted ancestors and non-group/world-writable roots are mandatory. Workspace roots must not overlap. Any policy/projected inventory change requires a new fingerprint and approval. The production worker rechecks its policy file before file effects and publication, and revalidates cached output against current release rules. Revocation is still not atomic against a concurrent administrator: stop invocation before changing policy.

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
Duplicate JSON keys and non-finite numbers are refused. HMAC-SHA256 signs `b"openclaw-agent-management-approval:v1\0" + canonical(claim)` with a dedicated key; `\0` denotes a single NUL byte. Manifest hashing includes the intended operation, exact replacement/backup reference and expected hash. Protocol-domain separation prevents a signature from another key use being accepted. Signatures from the earlier PR implementation must be regenerated with this reviewed helper; no downgrade verifier is provided.

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

For worker regression, restore prior reviewed code/unit/drop-in and leave management disabled. Preserve the upgraded state separately rather than opening it with older worker code. State schema v2 adds inode/root and comment-attempt records; unknown schema versions are refused. Migration retains old audit/backups, holds legacy prepared operations without inode proof, and assumes any legacy outbox reservation may already have attempted a comment. Old request fingerprints/backups cannot be silently replayed or rebound; use separately approved offline recovery if necessary. No prior version was deployed in this development task. Restore privately backed-up policy/projection only after integrity/compatibility checks. Uncertain publication stays held; never overwrite artifacts or delete ledger rows to force execution.

Native configuration rollback is outside scope because native configuration is never written. No trading/OpenClaw restart is required by the file algorithm; any runtime reload requires separate approval after behavior is verified.

## Verification

Offline tests use synthetic root-ownership projections, temporary Linux files, mocked GitHub responses, synthetic keys/tokens and a network-call guard. Coverage includes content binding/expiry during lock/staging waits, path/type/ACL restrictions, release hashes/secret gates, future-agent inventory, backups/rollback, concurrent workers, deduplication, permission and file/directory sync failures, inode-checked recovery, forged markers and interrupted/uncertain publication. Linux filesystem tests skip on Windows; Ubuntu 22.04 CI runs the complete suite on Python 3.10–3.13, with an additional distribution-Python lane. CI is not verification of the production mounts, identities or reload behavior.

## Filesystem model for Sous Chef — verify before production

Use an **instruction-only directory**, not a broad existing OpenClaw workspace with authentication, conversations, logs, runtime state or unrelated siblings. The worker needs write access to the parent for atomic rename; that permission cannot be restricted to one basename by ordinary Unix modes. If approved files currently share a writable parent with private/runtime files, leave writes disabled until a separately approved isolation plan is verified. Do not change live mounts or ownership to satisfy this model during repository development.

| Object | Owner/group | Mode | Intended access |
|---|---|---|---|
| Trusted parent/code tree | root/root | directories 0755, code 0444 | Manager reads; cannot alter code/parent |
| Agent instruction directory and approved subdirectories | manager/dedicated reader group | 2750 | Manager sole writer; OpenClaw reader can traverse |
| Approved instructions/knowledge | manager/same reader group | 0640 | Manager writes; OpenClaw reads |
| Policy and projection | root/manager primary group | 0440 | Manager reads; operator alone changes authority |
| Management state | manager/manager primary group | directory 0700, files 0600 | No OpenClaw access |
| systemd credentials | root or manager/isolated identity | 0400 | Only worker reads; never exported |

Names and numeric IDs here are roles, not verified accounts. Primary service group remains private; add only the dedicated instruction-reader group as a supplementary group. The worker can preserve a target group only if it is in its effective/supplementary groups; no root capability is used. Write targets must already be worker-owned 0600/0640, parents worker-owned and non-group/world-writable. Group/world readable 0644 writes, special permission bits and access/default POSIX ACLs are rejected. Unsupported xattr/ACL inspection fails closed. Writes reject any existing file xattrs rather than silently stripping user metadata or MAC labels; labelled files need a separately reviewed adapter. Avoid ACL-based sharing; it would be lost or broadened during replacement.

OpenClaw's confirmed container identity/GID mapping must be able to read the 0640 files and traverse all parents, while having no write authority. Use a **directory** read-only bind mount of the isolated instructions, with no unreviewed submounts; do not bind individual instruction files, which pin the old inode across atomic replacement. Test reopen-after-replacement behavior and consumption of changed instructions in staging. An open file descriptor or application cache can still retain old contents. No automatic runtime reload is implemented. If the installed runtime requires writes to this same directory, or existing mounts are incompatible, stop; do not restart/reconfigure OpenClaw incidentally. [Docker bind mount reference](https://docs.docker.com/engine/storage/bind-mounts/).

`ProtectSystem=strict` denies writes, not reads. Production must add a reviewed allowlist namespace: preferably a minimal root-owned `RootDirectory` jail containing only the verified Ubuntu Python 3.10 runtime, standard libraries/shared libraries, CA certificates and minimal DNS configuration. Expose the pinned code/policy/projection read-only, isolated instruction directories writable only to this worker, private state and systemd credentials. Never bind the entire host root, broad workspaces, Docker socket, auth directories, trading paths or existing diagnostics state. Keep numeric ownership consistent across the jail and container mappings. systemd sets up mounts as the service manager; the worker receives no mount/root capability. Alternative masking/bind approaches require the same full negative-access tests. Home-hosted workspaces cannot be exposed by simply disabling `ProtectHome`; bind only an isolated instruction tree into a reviewed namespace location. [Ubuntu 22.04 systemd 249 reference](https://manpages.ubuntu.com/manpages/jammy/man5/systemd.exec.5.html).

The example unit is deliberately incomplete and disabled: it adds process/network restrictions and no AF_UNIX sockets, timer or restart policy. Verify DNS with the chosen NSS configuration (AF_UNIX-dependent resolvers need a separately reviewed alternative, not Docker socket access). Verify Python imports, TLS, SQLite, group preservation and fsync under the staged jail. Unknown directive errors, unsupported filesystem semantics, a mixed workspace, inaccessible required runtime files or failed negative-access checks block activation; never weaken the sandbox merely to make a smoke test pass.

## Signing-key decision and rotation

Asymmetric signatures would materially improve approval provenance: an Ed25519 owner key retained offline/hardware-backed would let the worker hold only a pinned public verifier, so verifier-key disclosure would not enable owner signatures for healthy workers or later requests. A compromised process could still directly change files it already owns; signatures cannot replace filesystem isolation. This PR retains HMAC and does not introduce unreviewed crypto code/dependencies. Before unattended production management, review an audited-library asymmetric migration with a versioned domain, pinned public-key fingerprint, key ID, bounded validity and no HMAC downgrade path. Do not implement Ed25519 primitives by hand. Human approval remains mandatory.

For HMAC provisioning, generate the independent 32-byte key on an owner-controlled device through a separately approved procedure. Deliver the verifier copy out of band as a systemd credential; owner signing copy must be a private regular single-link no-ACL file. Never deliver it through GitHub, conversations, an environment value or command-line argument. The worker also rejects linked/shared/oversized credential files. Stop management before rotation, preserve all state, invalidate old signatures, replace owner/verifier copies together, verify synthetic signed/refused requests and obtain new approvals before resuming. There is no old-key fallback. Revoking the management token/key does not delete snapshots already stored privately.

## Ordered activation and rollback gates

1. Approve merge separately; record the exact reviewed source commit and complete CI results. Do not deploy a branch tip.
2. After separate authorization, privately confirm Sous Chef's runtime/schema, full inventory, directory contents, numeric ownership/GID mappings, mounts/submounts, storage/fsync semantics and read/reopen/cache behavior. Inspect only authorized OpenClaw information, never trading files/processes. Keep raw discovery data local.
3. Create/verify a separate private management channel and least-privilege credentials; build the operator-reviewed projection and exact release hashes. These are future configuration steps, not actions performed by this PR.
4. Privately back up approved instruction bytes, modes/UID/GID, original mount/config baseline and existing Supervisor state through an explicitly authorized operator procedure. Do not alter running services. Create an isolated staged worker/jail and synthetic instruction tree; use no production credentials in staging.
5. Validate reader access before/after replacement, and denial of auth/trading/diagnostics/root/sudo/Docker paths. Run interruption, concurrency, fsync, stale approval, ambiguous POST and restore tests under the target identity. Verify the example unit with the installed systemd, without enabling it. If production layout cannot meet the model without OpenClaw changes, submit a separate plan; stop here.
6. Only after exact-target deployment approval, stage pinned code and disabled worker configuration. No existing Supervisor/diagnostics unit changes, automatic deployment, OpenClaw restart, routing changes or runtime reload. Preserve source/config/state hashes privately.
7. Obtain separate activation and signed `list`/snapshot approvals. Start with Sous Chef's exact reviewed instruction hashes and a disposable authorized fixture edit/restore; verify private output and no public data. A real instruction edit or restore needs its own exact manifest approval. Never infer consumption of new instructions without verified runtime behavior.
8. Rollback: stop only new invocations under approval; preserve the v2 ledger/outbox/backups. For files, use a fresh signed restore with current expected hash and matching original root/agent/path. Failed restore preserves current contents and its local backup. If the worker cannot run, an explicitly authorized operator may restore the privately verified bytes plus original UID/GID/mode atomically offline; do not bypass stale-content checks. Do not perform an unapproved reload. For code, restore the prior reviewed disabled configuration, retaining upgraded state separately; do not downgrade/open v2 state with old code. Leave live diagnostics and trading services unchanged.
