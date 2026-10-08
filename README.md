# openclaw-dev

Python Supervisor development repository. This public repository must contain only source code, documentation, and synthetic test fixtures.

## Supported Python runtimes

Python 3.10, 3.11, 3.12, and 3.13 are supported by the complete 43-test offline suite. CI uses the available maintenance release of each minor version; the initial Python 3.10 validation used CPython 3.10.22. This verifies code compatibility, not a specific operating-system distribution or vendor-packaged interpreter build. Live-host validation requires separate approval.

## Develop and review

1. Create a feature branch from current main for each change.
2. Edit and test in an isolated development checkout. Run:
   `python -m unittest discover -s tests -v`
3. Open a pull request describing the behavior change, test results, and risks.
4. GitHub Actions runs offline tests on Python 3.10, 3.11, 3.12, and 3.13. It uses GitHub-hosted runners and read-only repository permission, with no production secrets or deployment steps.
5. Review the diff and successful checks. Obtain explicit human-owner approval for that specific PR before merging. Do not use auto-merge.
6. Deployment is a separate action requiring explicit approval for an exact commit, target, and reviewed deployment/rollback plan. Merging does not deploy.

Future development requests can ask the assistant to inspect, implement, test, and open a PR. The assistant must stop before merging until the owner explicitly approves. Production access requires a separate explicit instruction; repository development never authorizes it.

## GitHub enforcement settings

The initial inspection found main unprotected. The approval rules in AGENTS.md guide assistants but do not enforce GitHub access controls.

In Settings > Rules > Rulesets, protect main: require a pull request, require the Python 3.10 / Python 3.11 / Python 3.12 / Python 3.13 checks after their first successful run, block force pushes and deletion, and restrict bypass rights. Require independent approving review when another reviewer is available; GitHub does not let PR authors approve their own PR. For a solo owner, retain the explicit owner approval step before an assistant merges and understand that a ruleset cannot verify conversational approval.

Do not configure a main push webhook or workflow to deploy automatically. No existing GitHub Actions workflows were present at inspection. External integrations and live VPS configuration were not accessed or verified.

## Secrets and live services

Never publish tokens, SSH keys, environment files, private trading data, or runtime state. Ignore patterns reduce accidental additions but do not detect every secret: inspect the staged diff before each push. Tests use only a synthetic token in a temporary directory.

PR #3 adds an opt-in private operations channel; source and service-template edits are repository-only. Tests mock HTTP requests; they never start a live service or contact a VPS, OpenClaw, or trading service. The existing Supervisor can post a one-time authenticated GitHub acknowledgement; tests cover that behavior without sending a comment.

See supervisor/README.md for the private request protocol, manual least-privilege configuration, deployment plan and rollback. Those plans require separate explicit approval before any production access. Diagnostic reports must never be posted to this public repository.
