import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "release_event.py"
spec = importlib.util.spec_from_file_location("release_event", SCRIPT)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def sample(tag="v0.6.3-preview"):
    event = {"action": "published", "release": {"id": 12, "tag_name": tag, "draft": False}, "repository": {"full_name": "example/sekscan"}}
    env = {"GITHUB_EVENT_NAME": "release", "GITHUB_REF": "refs/tags/" + tag, "GITHUB_SHA": "a" * 40, "GITHUB_REPOSITORY": "example/sekscan"}
    return event, env


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.event, self.env = sample()
        self.info = release.validate_event(self.event, self.env)

    def artifacts(self):
        manifest = {"application": "sekscan", "version": self.info["version"], "host_tests": "passed", "targets": list(release.TARGETS), "artifacts": []}
        for target in (*release.TARGETS, None):
            suffix = target.replace("/", "-") if target else "source"
            path = self.root / f"sekscan-{self.info['version']}-{suffix}.zip"
            path.write_bytes(b"synthetic archive, not a real binary " + suffix.encode())
            manifest["artifacts"].append({"file": path.name, "target": target, "sha256": release.digest(path)})
        (self.root / "release.json").write_text(json.dumps(manifest))
        (self.root / "SHA256SUMS.txt").write_text("placeholder, replaced by seal")
        return manifest

    def test_only_published_release(self):
        for action in ("created", "edited", "deleted", "prereleased", "released"):
            with self.subTest(action=action):
                event = copy.deepcopy(self.event); event["action"] = action
                with self.assertRaises(ValueError): release.validate_event(event, self.env)
        for name in ("push", "pull_request", "workflow_dispatch"):
            env = self.env | {"GITHUB_EVENT_NAME": name}
            with self.assertRaises(ValueError): release.validate_event(self.event, env)

    def test_stable_and_prerelease_tags(self):
        for tag in ("v1.0.0", "0.6.3-preview", "v2.0.0-rc.1+build.2"):
            with self.subTest(tag=tag):
                event, env = sample(tag)
                self.assertEqual(release.validate_event(event, env)["version"], tag.removeprefix("v"))

    def test_unsafe_and_invalid_tags(self):
        for tag in ("main", "latest", "v01.2.3", "1.2.3-01", "../1.2.3", "v1.2.3\nINJECT=x", "$(whoami)", "1.2.3 --bad"):
            with self.subTest(tag=tag):
                event, env = sample(tag)
                with self.assertRaises(ValueError): release.validate_event(event, env)

    def test_draft_immutable_and_identity_mismatch(self):
        for update in ({"draft": True}, {"immutable": True}, {"id": 0}, {"id": True}):
            event = copy.deepcopy(self.event); event["release"].update(update)
            with self.assertRaises(ValueError): release.validate_event(event, self.env)
        for env in (self.env | {"GITHUB_REF": "refs/heads/main"}, self.env | {"GITHUB_SHA": "bad"}, self.env | {"GITHUB_REPOSITORY": "other/repo"}):
            with self.assertRaises(ValueError): release.validate_event(self.event, env)

    def test_complete_artifact_set_and_seal(self):
        self.artifacts(); release.seal(self.root, self.info)
        self.assertEqual(len(release.verify_seal(self.root, self.info)), len(release.TARGETS) + 4)

    def test_windows_arm64_is_required(self):
        self.assertIn("windows/arm64", release.TARGETS)
        self.artifacts()
        (self.root / f"sekscan-{self.info['version']}-windows-arm64.zip").unlink()
        with self.assertRaises(ValueError): release.seal(self.root, self.info)

    def test_missing_platform(self):
        self.artifacts(); (self.root / next(iter(release.artifact_names(self.info["version"])))).unlink()
        with self.assertRaises(ValueError): release.seal(self.root, self.info)

    def test_unexpected_artifact(self):
        self.artifacts(); (self.root / "private.log").write_text("secret")
        with self.assertRaises(ValueError): release.seal(self.root, self.info)

    def test_tampered_zip(self):
        self.artifacts(); release.seal(self.root, self.info)
        (self.root / next(iter(release.artifact_names(self.info["version"])))).write_bytes(b"changed")
        with self.assertRaises(ValueError): release.verify_seal(self.root, self.info)

    def test_different_event_commit(self):
        self.artifacts(); release.seal(self.root, self.info)
        with self.assertRaises(ValueError): release.verify_seal(self.root, self.info | {"commit": "b" * 40})

    def test_duplicate_or_unsafe_checksum(self):
        self.artifacts(); release.seal(self.root, self.info)
        p = self.root / "SHA256SUMS.txt"; original = p.read_text()
        for extra in (original.splitlines()[0], "a" * 64 + "  ../escape.zip"):
            p.write_text(original + extra + "\n")
            with self.assertRaises(ValueError): release.verify_seal(self.root, self.info)

    def test_test_status_and_platform_gate(self):
        manifest = self.artifacts(); manifest["host_tests"] = "skipped"
        (self.root / "release.json").write_text(json.dumps(manifest))
        with self.assertRaises(ValueError): release.seal(self.root, self.info)
        manifest["host_tests"] = "passed"; manifest["targets"].append("linux/amd64")
        (self.root / "release.json").write_text(json.dumps(manifest))
        with self.assertRaises(ValueError): release.seal(self.root, self.info)

    def test_retry_skips_only_matching_assets(self):
        self.artifacts(); release.seal(self.root, self.info)
        files = release.verify_seal(self.root, self.info); one = next(iter(files.values()))
        remote = self.event["release"] | {"assets": [{"name": one.name, "state": "uploaded", "digest": "sha256:" + release.digest(one)}]}
        self.assertEqual(len(release.upload_plan(files, remote, self.info)), len(files) - 1)
        remote["assets"][0]["digest"] = "sha256:" + "f" * 64
        with self.assertRaises(ValueError): release.upload_plan(files, remote, self.info)

    def test_immutable_remote_stops_upload(self):
        self.artifacts(); release.seal(self.root, self.info)
        with self.assertRaises(ValueError): release.upload_plan(release.regular_files(self.root), self.event["release"] | {"immutable": True}, self.info)

    def test_publication_uses_release_id_and_verifies_server_digest(self):
        self.artifacts(); release.seal(self.root, self.info); calls = []
        def fake(args):
            calls.append(args)
            if args[-1].endswith("/releases/12"): return json.dumps(self.event["release"] | {"assets": []})
            if "/commits/" in args[-1]: return json.dumps({"sha": self.info["commit"]})
            path = Path(args[args.index("--input") + 1])
            self.assertIn("/releases/12/assets?", args[-1])
            return json.dumps({"name": path.name, "state": "uploaded", "digest": "sha256:" + release.digest(path)})
        with patch.object(release, "command", fake): release.publish(self.root, self.info)
        self.assertEqual(sum("POST" in c for c in calls), len(release.TARGETS) + 4)

    def test_moved_remote_tag_never_uploads(self):
        self.artifacts(); release.seal(self.root, self.info); calls = []
        def fake(args):
            calls.append(args)
            return json.dumps({"sha": "b" * 40} if "/commits/" in args[-1] else self.event["release"])
        with patch.object(release, "command", fake), self.assertRaises(ValueError): release.publish(self.root, self.info)
        self.assertFalse(any("POST" in c for c in calls))

    def test_real_git_tag_and_locked_modules(self):
        def git(*args): return subprocess.check_output(["git", "-C", str(self.root), *args], text=True).strip()
        git("init", "-q"); git("config", "user.name", "Test"); git("config", "user.email", "test@localhost")
        (self.root / "go.mod").write_text("module fixture\ngo 1.23\n")
        (self.root / "go.sum").write_text("fixture only, not a real module lock\n")
        git("add", "."); git("commit", "-qm", "fixture"); git("tag", self.info["tag"])
        env = self.env | {"GITHUB_SHA": git("rev-parse", "HEAD"), "GITHUB_EVENT_PATH": str(self.root / "event.json")}
        Path(env["GITHUB_EVENT_PATH"]).write_text(json.dumps(self.event))
        old = Path.cwd()
        try:
            os.chdir(self.root)
            with patch.dict(os.environ, env):
                self.assertEqual(release.context(True)["commit"], env["GITHUB_SHA"])
                (self.root / "go.sum").unlink()
                with self.assertRaises(ValueError): release.context(True)
        finally: os.chdir(old)

    def test_workflow_is_published_only_and_pinned(self):
        workflow = (SCRIPT.parents[1] / ".github/workflows/release.yml").read_text()
        self.assertIn("types: [published]", workflow)
        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertNotIn("push:", workflow)
        self.assertNotIn("pull_request:", workflow)
        import re
        for uses in re.findall(r"uses: ([^\s]+)", workflow): self.assertRegex(uses, r"^actions/[a-z-]+@[0-9a-f]{40}$")
        self.assertIn("--require-modules", workflow)
        self.assertIn("ref: ${{ github.sha }}", workflow)


if __name__ == "__main__": unittest.main()
