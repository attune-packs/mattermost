from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib import mattermost_client as client_module
from lib.mattermost_client import MattermostClient, MattermostPackError, validate_credentials


def load_sensor_module():
    path = ROOT / "sensors" / "mattermost_websocket.py"
    spec = importlib.util.spec_from_file_location("mattermost_websocket", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


sensor_module = load_sensor_module()


class FakeResponse:
    def __init__(self, status=200, data=None, headers=None, content=None):
        self.status_code = status
        self._data = data
        self.headers = headers or {}
        self.content = content if content is not None else (
            b"" if data is None else json.dumps(data).encode("utf-8")
        )

    def json(self):
        return self._data

    def iter_content(self, chunk_size=65536):
        for offset in range(0, len(self.content), chunk_size):
            yield self.content[offset : offset + chunk_size]

    def close(self):
        pass


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


def credentials(**overrides):
    value = {"base_url": "https://chat.example.test", "token": "top-secret"}
    value.update(overrides)
    return value


class MetadataTests(unittest.TestCase):
    def test_action_refs_and_entry_points_are_consistent(self):
        action_files = sorted((ROOT / "actions").glob("*.yaml"))
        self.assertGreaterEqual(len(action_files), 8)
        for path in action_files:
            data = yaml.safe_load(path.read_text())
            self.assertEqual(data["ref"], f"mattermost.{path.stem}")
            if "entry_point" in data:
                self.assertTrue((ROOT / "actions" / data["entry_point"]).is_file())
                self.assertEqual(data["parameter_delivery"], "stdin")
                self.assertEqual(data["parameter_format"], "json")
                self.assertEqual(data["output_format"], "json")
                self.assertEqual(data["default_execution_permission_set_refs"], ["standard"])
            if "workflow_file" in data:
                self.assertTrue((ROOT / "actions" / data["workflow_file"]).is_file())

    def test_sensor_and_trigger_refs_match_pack(self):
        sensor = yaml.safe_load((ROOT / "sensors" / "mattermost_websocket.yaml").read_text())
        trigger = yaml.safe_load((ROOT / "triggers" / "post_created.yaml").read_text())
        self.assertEqual(sensor["trigger_types"], [trigger["ref"]])
        self.assertTrue((ROOT / "sensors" / sensor["entry_point"]).is_file())

    def test_thread_workflow_is_bounded_and_serial(self):
        action = yaml.safe_load((ROOT / "actions" / "post_thread.yaml").read_text())
        workflow = yaml.safe_load(
            (ROOT / "actions" / "workflows" / "post_thread.workflow.yaml").read_text()
        )
        self.assertEqual(action["parameters"]["replies"]["maxItems"], 20)
        replies = next(task for task in workflow["tasks"] if task["name"] == "create_replies")
        self.assertEqual(replies["concurrency"], 1)
        self.assertIn("create_root.result.post.id", replies["input"]["root_id"])


class CredentialTests(unittest.TestCase):
    def test_https_credentials_get_safe_defaults(self):
        result = validate_credentials(credentials())
        self.assertEqual(result["token"], "top-secret")

    def test_rejects_http_without_explicit_opt_in(self):
        with self.assertRaisesRegex(MattermostPackError, "must use HTTPS"):
            validate_credentials(credentials(base_url="http://chat.example.test"))

    def test_allows_explicit_http_for_local_development(self):
        result = validate_credentials(
            credentials(base_url="http://127.0.0.1:8065", allow_insecure_http=True)
        )
        self.assertEqual(result["base_url"], "http://127.0.0.1:8065")

    def test_rejects_embedded_credentials_and_invalid_websocket_bounds(self):
        with self.assertRaisesRegex(MattermostPackError, "must not contain credentials"):
            validate_credentials(credentials(base_url="https://user:pass@example.test"))
        with self.assertRaisesRegex(MattermostPackError, "must not be below"):
            validate_credentials(
                credentials(
                    websocket_reconnect_min_seconds=10,
                    websocket_reconnect_max_seconds=5,
                )
            )


class ClientTests(unittest.TestCase):
    def test_get_retries_rate_limit_and_never_leaks_token(self):
        session = FakeSession(
            [
                FakeResponse(429, {"message": "top-secret"}, {"Retry-After": "0"}),
                FakeResponse(200, {"token": "returned-token", "ok": True}),
            ]
        )
        sleeps = []
        client = MattermostClient(credentials(), session=session, sleep=sleeps.append)
        status, result = client.request("GET", "/users/me")
        self.assertEqual(status, 200)
        self.assertEqual(result, {"token": "REDACTED", "ok": True})
        self.assertEqual(sleeps, [0.0])
        self.assertEqual(len(session.calls), 2)
        self.assertEqual(session.calls[0][2]["headers"]["Authorization"], "Bearer top-secret")

    def test_mutation_is_not_retried(self):
        session = FakeSession([FakeResponse(429, {"message": "slow down"})])
        client = MattermostClient(credentials(), session=session)
        with self.assertRaisesRegex(MattermostPackError, "HTTP status 429"):
            client.request("POST", "/posts", body={"message": "hello"})
        self.assertEqual(len(session.calls), 1)

    def test_rejects_redirect_traversal_and_oversized_response(self):
        client = MattermostClient(credentials(), session=FakeSession([]))
        with self.assertRaisesRegex(MattermostPackError, "traversal"):
            client.request("GET", "/users/../admin")
        with self.assertRaisesRegex(MattermostPackError, "traversal"):
            client.request("GET", "/users/%2e%2e/admin")
        redirect_client = MattermostClient(
            credentials(), session=FakeSession([FakeResponse(302, headers={"Location": "https://evil.test"})])
        )
        with self.assertRaisesRegex(MattermostPackError, "redirect"):
            redirect_client.request("GET", "/users/me")
        large_client = MattermostClient(
            credentials(),
            session=FakeSession([FakeResponse(200, content=b"x" * (2 * 1024 * 1024 + 1))]),
        )
        with self.assertRaisesRegex(MattermostPackError, "size limit"):
            large_client.request("GET", "/users/me")

    def test_list_posts_honors_page_bound_and_normalizes(self):
        first = {
            "order": ["a" * 26, "b" * 26],
            "posts": {
                "a" * 26: {"id": "a" * 26, "message": "one", "metadata": {"secret": "x"}},
                "b" * 26: {"id": "b" * 26, "message": "two"},
            },
        }
        second = {
            "order": ["c" * 26],
            "posts": {"c" * 26: {"id": "c" * 26, "message": "three"}},
        }
        fake_client = MattermostClient(
            credentials(), session=FakeSession([FakeResponse(data=first), FakeResponse(data=second)])
        )
        with mock.patch.object(client_module, "_client", return_value=fake_client):
            result = client_module.list_channel_posts(
                {"channel_id": "d" * 26, "per_page": 2, "max_pages": 2}
            )
        self.assertEqual(result["count"], 3)
        self.assertEqual(result["pages_fetched"], 2)
        self.assertFalse(result["truncated"])
        self.assertNotIn("metadata", result["posts"][0])

    def test_list_posts_rejects_page_range_past_bound(self):
        with self.assertRaisesRegex(MattermostPackError, "must not exceed"):
            client_module.list_channel_posts(
                {"channel_id": "d" * 26, "page": 1_000_000, "max_pages": 2}
            )

    def test_upload_reads_only_from_artifact_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "report.txt"
            allowed.write_text("report")
            response = {"file_infos": [{"id": "f" * 26, "name": "report.txt", "size": 6}]}
            fake_client = MattermostClient(
                credentials(), session=FakeSession([FakeResponse(data=response)])
            )
            with mock.patch.dict(os.environ, {"ATTUNE_ARTIFACTS_DIR": str(root)}), mock.patch.object(
                client_module, "_client", return_value=fake_client
            ):
                result = client_module.upload_file(
                    {"channel_id": "d" * 26, "file_path": str(allowed)}
                )
            self.assertEqual(result["files"][0]["name"], "report.txt")
            with mock.patch.dict(os.environ, {"ATTUNE_ARTIFACTS_DIR": str(root)}):
                with self.assertRaisesRegex(MattermostPackError, "below ATTUNE_ARTIFACTS_DIR"):
                    client_module._artifact_file("/etc/passwd")


class SensorHelperTests(unittest.TestCase):
    def test_websocket_url_preserves_installation_path(self):
        self.assertEqual(
            sensor_module.websocket_url("https://chat.example.test/mattermost"),
            "wss://chat.example.test/mattermost/api/v4/websocket",
        )

    def test_posted_event_is_normalized(self):
        post = {
            "id": "p" * 26,
            "channel_id": "c" * 26,
            "user_id": "u" * 26,
            "message": "deploy complete",
            "root_id": "r" * 26,
            "type": "",
            "create_at": 1234,
            "props": {"untrusted": True},
        }
        frame = json.dumps(
            {
                "event": "posted",
                "data": {
                    "post": json.dumps(post),
                    "channel_name": "ops",
                    "team_id": "t" * 26,
                    "sender_name": "robot",
                },
            }
        )
        result = sensor_module.posted_payload(frame)
        self.assertEqual(result["message"], "deploy complete")
        self.assertNotIn("props", result)

    def test_filters_channel_author_self_and_system_posts(self):
        payload = {
            "channel_id": "c" * 26,
            "user_id": "u" * 26,
            "post_type": "",
        }
        self.assertTrue(sensor_module.rule_matches(payload, {"channel_id": "c" * 26}, "x" * 26))
        self.assertFalse(sensor_module.rule_matches(payload, {"channel_id": "x" * 26}, "x" * 26))
        self.assertFalse(sensor_module.rule_matches(payload, {"channel_id": "c" * 26}, "u" * 26))
        self.assertTrue(
            sensor_module.rule_matches(
                payload, {"channel_id": "c" * 26, "allow_self_posts": True}, "u" * 26
            )
        )
        system = dict(payload, post_type="system_join_channel")
        self.assertFalse(sensor_module.rule_matches(system, {"channel_id": "c" * 26}, "x" * 26))


if __name__ == "__main__":
    unittest.main()
