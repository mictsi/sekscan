#!/usr/bin/env python3
"""Validate a release.published event and attach its complete build output.

Requires Git and (for publication) GitHub CLI. Never creates releases, moves tags,
uses shell-expanded tag names, or overwrites an existing asset.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping
from urllib.parse import quote, urlencode

LOG = logging.getLogger("release")
TARGETS = tuple(json.loads((Path(__file__).resolve().parent / "release" / "targets.json").read_text(encoding="utf-8")))
if not TARGETS or len(set(TARGETS)) != len(TARGETS) or any(
    not isinstance(target, str) or not re.fullmatch(r"(linux|darwin|windows)/(amd64|arm64)", target)
    for target in TARGETS
):
    raise ValueError("invalid release target manifest")
VERSION = re.compile(r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")
COMMIT = re.compile(r"[0-9a-f]{40}")


def validate_event(event: dict[str, Any], env: Mapping[str, str]) -> dict[str, Any]:
    release = event.get("release", {})
    if env.get("GITHUB_EVENT_NAME") != "release" or event.get("action") != "published":
        raise ValueError("only release.published events may build or upload release binaries")
    if release.get("draft") is not False or type(release.get("id")) is not int or release["id"] <= 0:
        raise ValueError("a published non-draft release with a valid ID is required")
    if release.get("immutable") is True:
        raise ValueError("published immutable releases cannot accept new assets; use an approved draft-first release process instead")
    tag = release.get("tag_name", "")
    match = VERSION.fullmatch(tag) if isinstance(tag, str) else None
    if not match or any(p.isdecimal() and len(p) > 1 and p.startswith("0") for p in (match[4] or "").split(".")):
        raise ValueError("release tag must be a version such as v0.6.3-preview or 1.0.0")
    if env.get("GITHUB_REF") != "refs/tags/" + tag or not COMMIT.fullmatch(env.get("GITHUB_SHA", "")):
        raise ValueError("release event ref/commit does not identify its exact tag")
    repo = env.get("GITHUB_REPOSITORY", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) or event.get("repository", {}).get("full_name") != repo:
        raise ValueError("release repository identity mismatch")
    return {"tag": tag, "version": tag.removeprefix("v"), "commit": env["GITHUB_SHA"], "repository": repo, "release_id": release["id"]}


def command(args: list[str]) -> str:
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, text=True, timeout=900).stdout.strip()


def context(require_modules: bool = False) -> dict[str, Any]:
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    info = validate_event(event, os.environ)
    if command(["git", "rev-parse", "HEAD"]) != info["commit"]:
        raise ValueError("checkout differs from the release event commit")
    if command(["git", "rev-parse", "--verify", f"refs/tags/{info['tag']}^{{commit}}"] ) != info["commit"]:
        raise ValueError("release tag moved or does not match the checked-out commit")
    if require_modules:
        for name in ("go.mod", "go.sum"):
            path = Path(name)
            if path.is_symlink() or not path.is_file() or not path.stat().st_size:
                raise ValueError("tag must contain resolved go.mod/go.sum: build, review and commit both BEFORE publishing")
            command(["git", "ls-files", "--error-unmatch", name])
        command(["git", "diff", "--exit-code", "HEAD", "--", "go.mod", "go.sum"])
    return info


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def artifact_names(version: str) -> set[str]:
    return {f"sekscan-{version}-{target.replace('/', '-')}.zip" for target in TARGETS} | {f"sekscan-{version}-source.zip"}


def regular_files(directory: Path) -> dict[str, Path]:
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError("artifact directory is missing or a symlink")
    result = {}
    for path in directory.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError("release contains a non-regular artifact")
        result[path.name] = path
    return result


def verify_manifest(directory: Path, info: dict[str, Any]) -> None:
    files = regular_files(directory)
    expected = artifact_names(info["version"])
    if not expected <= files.keys():
        raise ValueError("release is missing a platform/source ZIP")
    manifest = json.loads((directory / "release.json").read_text(encoding="utf-8"))
    if manifest.get("application") != "sekscan" or manifest.get("version") != info["version"] or manifest.get("host_tests") != "passed":
        raise ValueError("release manifest identity or test status mismatch")
    if len(manifest.get("targets", [])) != len(TARGETS) or set(manifest["targets"]) != set(TARGETS):
        raise ValueError("release manifest must include every supported target")
    artifacts = manifest.get("artifacts", [])
    if len(artifacts) != len(expected) or {a.get("file") for a in artifacts} != expected:
        raise ValueError("release manifest artifact set mismatch")
    for artifact in artifacts:
        name = artifact["file"]
        if digest(files[name]) != artifact.get("sha256"):
            raise ValueError("release ZIP checksum mismatch")
        target = artifact.get("target")
        if name.endswith("-source.zip"):
            if target:
                raise ValueError("source archive incorrectly identified as a platform binary")
        elif target not in TARGETS or name != f"sekscan-{info['version']}-{target.replace('/', '-')}.zip":
            raise ValueError("release platform identity mismatch")


def seal(directory: Path, info: dict[str, Any]) -> None:
    verify_manifest(directory, info)
    if set(regular_files(directory)) != artifact_names(info["version"]) | {"release.json", "SHA256SUMS.txt"}:
        raise ValueError("unexpected files in build output")
    (directory / "release-source.json").write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    files = regular_files(directory)
    text = "".join(f"{digest(files[name])}  {name}\n" for name in sorted(files) if name != "SHA256SUMS.txt")
    (directory / "SHA256SUMS.txt").write_text(text, encoding="utf-8")
    verify_seal(directory, info)


def verify_seal(directory: Path, info: dict[str, Any]) -> dict[str, Path]:
    verify_manifest(directory, info)
    files = regular_files(directory)
    expected = artifact_names(info["version"]) | {"release.json", "release-source.json", "SHA256SUMS.txt"}
    if set(files) != expected:
        raise ValueError("unexpected or missing publication artifacts")
    if json.loads(files["release-source.json"].read_text(encoding="utf-8")) != info:
        raise ValueError("artifacts were not built for this release ID/tag/commit")
    seen = set()
    for line in files["SHA256SUMS.txt"].read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.+-]+)", line)
        if not match or match[2] not in files or match[2] in seen or match[2] == "SHA256SUMS.txt":
            raise ValueError("invalid, duplicate, or unsafe checksum entry")
        seen.add(match[2])
        if digest(files[match[2]]) != match[1]:
            raise ValueError("publication checksum mismatch")
    if seen != expected - {"SHA256SUMS.txt"}:
        raise ValueError("not every publication artifact is checksummed")
    return files


def upload_plan(files: dict[str, Path], release: dict[str, Any], info: dict[str, Any]) -> list[Path]:
    if release.get("id") != info["release_id"] or release.get("tag_name") != info["tag"] or release.get("draft") is not False:
        raise ValueError("remote release identity changed")
    if release.get("immutable") is True:
        raise ValueError("cannot append assets to a published immutable release")
    assets = release.get("assets", [])
    existing = {a["name"]: a for a in assets}
    if len(existing) != len(assets):
        raise ValueError("remote release contains duplicate asset names")
    pending = []
    # Validate all collisions before starting ANY uploads. Partial network failure
    # may still leave a subset uploaded; retry accepts only checksum-matched assets.
    for name, path in sorted(files.items()):
        if name in existing:
            asset = existing[name]
            if asset.get("state") != "uploaded" or asset.get("digest") != "sha256:" + digest(path):
                raise ValueError("existing release asset differs or lacks a verifiable digest; refusing overwrite: " + name)
            LOG.info("already uploaded and checksum-matched: %s", name)
        else:
            pending.append(path)
    return pending


def publish(directory: Path, info: dict[str, Any]) -> None:
    files = verify_seal(directory, info)
    release = json.loads(command(["gh", "api", f"repos/{info['repository']}/releases/{info['release_id']}"]))
    # GitHub resolves lightweight/annotated tags through the commits endpoint.
    tag = json.loads(command(["gh", "api", f"repos/{info['repository']}/commits/{quote(info['tag'], safe='')}"]))
    if tag.get("sha") != info["commit"]:
        raise ValueError("remote tag moved after the build; refusing publication")
    for path in upload_plan(files, release, info):
        LOG.info("uploading %s to release %s", path.name, info["release_id"])
        address = f"https://uploads.github.com/repos/{info['repository']}/releases/{info['release_id']}/assets?" + urlencode({"name": path.name})
        response = json.loads(command(["gh", "api", "--method", "POST", "-H", "Content-Type: application/octet-stream", "--input", str(path), address]))
        if response.get("name") != path.name or response.get("state") != "uploaded" or response.get("digest") != "sha256:" + digest(path):
            raise ValueError("uploaded asset identity/checksum was not confirmed")


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("validate", "seal", "verify", "publish"))
    parser.add_argument("--require-modules", action="store_true")
    parser.add_argument("--dist", type=Path)
    args = parser.parse_args()
    try:
        info = context(args.require_modules)
        if args.action == "validate":
            if os.environ.get("GITHUB_OUTPUT"):
                with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
                    stream.write(f"version={info['version']}\n")
            if os.environ.get("GITHUB_ENV"):
                epoch = command(["git", "show", "-s", "--format=%ct", info["commit"]])
                if not epoch.isdecimal():
                    raise ValueError("invalid commit timestamp")
                with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as stream:
                    stream.write("SOURCE_DATE_EPOCH=" + epoch + "\n")
            LOG.info("validated release %s at %s", info["tag"], info["commit"])
            return 0
        if args.dist is None:
            raise ValueError("--dist is required")
        if args.action == "seal":
            seal(args.dist, info)
        elif args.action == "publish":
            publish(args.dist, info)
        else:
            verify_seal(args.dist, info)
        LOG.info("release artifacts %s: %s", args.action, args.dist)
        return 0
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        LOG.error("release stopped: %s", error)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
