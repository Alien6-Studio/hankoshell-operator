"""Failure handling at the fixture registry boundary."""

import json
import subprocess
import unittest

from tools.qualification.fixtures import python_image as image


class ImageLoading(unittest.TestCase):
    def execute(self, args):
        self.calls.append(args)
        if args[:2] == ["docker", "pull"]:
            if self.timeout:
                raise subprocess.TimeoutExpired(args, 180)
            return subprocess.CompletedProcess(args, 0 if args[2] == image.SOURCES[-1] else 1)
        if args[:3] == ["docker", "image", "inspect"]:
            repository = image.SOURCES[-1].split("@")[0].rsplit(":", 1)[0]
            return subprocess.CompletedProcess(args, 0, json.dumps([{
                "RepoDigests": [repository + "@" + self.digest], "Os": "linux",
                "Architecture": "arm64", "Id": "sha256:" + "a" * 64}]).encode())
        return subprocess.CompletedProcess(args, self.load_status if args[0] == "kind" else 0)

    def setUp(self):
        self.calls, self.digest, self.load_status, self.timeout = [], image.DIGEST, 0, False

    def test_rate_limited_sources_fall_back_and_load_once(self):
        record = image.load("kind", "owned-test", self.execute)
        self.assertEqual(record["source"], image.SOURCES[-1])
        self.assertEqual(self.calls[-1][:3], ["kind", "load", "image-archive"])
        self.assertEqual(self.calls[-1][-2:], ["--name", "owned-test"])
        self.assertEqual(self.calls[-2][:6], ["docker", "image", "save", "--platform", "linux/arm64", "--output"])
        self.assertEqual(sum(c[:2] == ["docker", "pull"] for c in self.calls), 3)

    def test_wrong_digest_is_not_loaded_or_retried(self):
        self.digest = "sha256:" + "b" * 64
        with self.assertRaises(ValueError):
            image.load("kind", "owned-test", self.execute)
        self.assertFalse(any(c[0] == "kind" for c in self.calls))

    def test_loading_failure_is_not_hidden_by_a_mirror_retry(self):
        self.load_status = 1
        with self.assertRaises(RuntimeError):
            image.load("kind", "owned-test", self.execute)

    def test_all_sources_timeout_without_starting_a_pod(self):
        self.timeout = True
        with self.assertRaises(RuntimeError):
            image.load("kind", "owned-test", self.execute)
        self.assertEqual(len(self.calls), 3)


if __name__ == "__main__":
    unittest.main()
