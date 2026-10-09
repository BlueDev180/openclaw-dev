"""Owner-operated offline signing helper. Never invoked by the worker."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

from agent_management import canonical, digest, exact, signature, UUID, HEX


def approval_line(claim, manifest, key, now=None):
    exact(claim, {"repo", "owner", "request", "commit", "manifest", "policy", "expires"})
    now = time.time() if now is None else now
    if (type(manifest) is not dict or type(manifest.get("version")) is not int or manifest["version"] != 1
            or type(claim["repo"]) is not int or claim["repo"] <= 0
            or type(claim["owner"]) is not int or claim["owner"] <= 0
            or type(claim["request"]) is not str or not UUID.fullmatch(claim["request"])
            or manifest.get("request") != claim["request"]
            or claim["manifest"] != digest(canonical(manifest))
            or type(claim["policy"]) is not str or not HEX.fullmatch(claim["policy"])
            or type(claim["commit"]) is not str or not re.fullmatch(r"[0-9a-f]{40}", claim["commit"])
            or type(claim["expires"]) is not int or not now < claim["expires"] <= now + 3600):
        raise ValueError("Invalid approval inputs")
    proof = signature(claim, key)
    return (f"supervisor:agent-management:v1 request={claim['request']} commit={claim['commit']} "
            f"manifest={claim['manifest']} policy={claim['policy']} expires={claim['expires']} signature={proof}")


def read_key(path):
    if os.name != "posix":
        raise ValueError("Private Linux owner key required")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        meta = os.fstat(descriptor)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_nlink != 1 or meta.st_mode & 0o077:
            raise ValueError("Key must be a private owner file")
        raw = os.read(descriptor, 67).decode("ascii").strip()
        if not re.fullmatch(r"[0-9a-f]{64}", raw):
            raise ValueError("Invalid approval key")
        return bytes.fromhex(raw)
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description="Sign only after independently reviewing the exact private GitHub commit, manifest and policy hash")
    parser.add_argument("--claim", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--key-file", required=True)
    args = parser.parse_args()
    try:
        values = []
        for path in (args.claim, args.manifest):
            with Path(path).open("rb") as source:
                raw = source.read(65537)
            if len(raw) > 65536:
                raise ValueError("Input limit")
            values.append(json.loads(raw))
        print(approval_line(values[0], values[1], read_key(args.key_file)))
    except Exception:
        print("Approval refused; inspect private inputs locally", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
