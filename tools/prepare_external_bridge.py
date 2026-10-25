"""Fetch and verify a pinned, separately licensed bridge. Never build or flash."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "evidence" / "external-bridge-source.json"


def git(*args):
    return subprocess.run(["git", *map(str, args)], check=True,
                          capture_output=True, text=True).stdout.strip()


def verify_checkout(target, manifest):
    target = Path(target)
    actual = git("-C", target, "rev-parse", "HEAD")
    if actual != manifest["commit"]:
        raise ValueError("upstream HEAD does not match pinned commit")
    hashes = {}
    for name, expected in manifest["sha256"].items():
        path = target / name
        if not path.resolve().is_relative_to(target.resolve()):
            raise ValueError("source path escapes checkout")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError("source SHA-256 mismatch: " + name)
        hashes[name] = actual
    return {"source": manifest["source"], "commit": manifest["commit"],
            "license": manifest["license"], "sha256": hashes,
            "scope": "Source identity only; no build, flash, controller access or hardware validation."}


def prepare(target, manifest):
    target = Path(target).resolve()
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise ValueError("target must be absent or an empty directory")
    target.parent.mkdir(parents=True, exist_ok=True)
    git("clone", "--config", "core.autocrlf=false", "--no-checkout", "--", manifest["source"], target)
    git("-C", target, "checkout", "--detach", manifest["commit"])
    provenance = verify_checkout(target, manifest)
    (target / "stadia-research-provenance.json").write_text(
        json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    return provenance


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path, help="absent or empty upstream checkout directory")
    parser.add_argument("--verify-only", action="store_true", help="verify an existing checkout without fetching")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    try:
        result = (verify_checkout if args.verify_only else prepare)(args.target, manifest)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, "Bridge preparation failed: " + str(exc) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
