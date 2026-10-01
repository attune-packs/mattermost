#!/usr/bin/env python3
"""Mattermost WebSocket sensor with credential-scoped connections."""

from __future__ import annotations

import json
import os
import ssl
import sys
import threading
import time
from collections import OrderedDict
from typing import Any, Dict, Mapping
from urllib.parse import quote, urlsplit, urlunsplit

_PACK_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PACK_ROOT not in sys.path:
    sys.path.insert(0, _PACK_ROOT)

from lib.mattermost_client import (  # noqa: E402
    DEFAULT_CREDENTIAL_KEY,
    MattermostClient,
    MattermostPackError,
    validate_credentials,
)


def websocket_url(base_url: str) -> str:
    parts = urlsplit(base_url.rstrip("/"))
    scheme = "wss" if parts.scheme == "https" else "ws"
    return urlunsplit((scheme, parts.netloc, f"{parts.path}/api/v4/websocket", "", ""))


def posted_payload(frame: Any) -> Dict[str, Any] | None:
    if isinstance(frame, bytes):
        try:
            frame = frame.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if not isinstance(frame, str):
        return None
    try:
        envelope = json.loads(frame)
    except json.JSONDecodeError:
        return None
    if not isinstance(envelope, dict) or envelope.get("event") != "posted":
        return None
    data = envelope.get("data")
    if not isinstance(data, dict):
        return None
    post = data.get("post")
    if isinstance(post, str):
        try:
            post = json.loads(post)
        except json.JSONDecodeError:
            return None
    if not isinstance(post, dict):
        return None
    required_strings = ("id", "channel_id", "user_id", "message")
    if any(not isinstance(post.get(field), str) or not post[field] for field in required_strings):
        return None
    create_at = post.get("create_at")
    if isinstance(create_at, bool) or not isinstance(create_at, int):
        return None
    return {
        "post_id": post["id"],
        "channel_id": post["channel_id"],
        "channel_name": str(data.get("channel_name", "")),
        "team_id": str(data.get("team_id", "")),
        "user_id": post["user_id"],
        "sender_name": str(data.get("sender_name", "")),
        "root_id": str(post.get("root_id", "")),
        "message": post["message"],
        "post_type": str(post.get("type", "")),
        "create_at": create_at,
    }


def rule_matches(payload: Mapping[str, Any], params: Mapping[str, Any], own_user_id: str) -> bool:
    if payload.get("channel_id") != params.get("channel_id"):
        return False
    if params.get("user_id") is not None and payload.get("user_id") != params.get("user_id"):
        return False
    if payload.get("user_id") == own_user_id and params.get("allow_self_posts", False) is not True:
        return False
    if payload.get("post_type") and params.get("allow_system_posts", False) is not True:
        return False
    return True


def _production_sensor() -> type:
    import attune
    import websocket

    class MattermostWebSocketSensor(attune.Sensor):
        def __init__(self) -> None:
            super().__init__()
            self._connections: Dict[str, Dict[str, Any]] = {}
            self._rule_credentials: Dict[int, str] = {}
            self._pending: Dict[int, Dict[str, Any]] = {}
            self._lock = threading.Lock()

        def _fetch_credentials(self, credential_key: Any) -> tuple[str, Dict[str, Any]]:
            if not isinstance(credential_key, str) or not credential_key.startswith("pack.mattermost."):
                raise ValueError("credential_key must reference a pack.mattermost Key")
            response = self.http_client.get(f"/api/v1/keys/{quote(credential_key, safe='')}")
            if response.status_code == 404:
                raise ValueError("credential Key was not found")
            if not 200 <= response.status_code < 300:
                raise RuntimeError(f"credential Key lookup failed with HTTP status {response.status_code}")
            try:
                value = response.json()["data"]["value"]
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("credential Key response was invalid") from exc
            try:
                return credential_key, validate_credentials(value)
            except MattermostPackError as exc:
                raise ValueError(str(exc)) from exc

        @staticmethod
        def _validate_rule(rule: Any) -> Dict[str, Any]:
            params = dict(rule.trigger_params or {})
            channel_id = params.get("channel_id")
            if not isinstance(channel_id, str) or not channel_id:
                raise ValueError("channel_id must be configured")
            for field in ("allow_self_posts", "allow_system_posts"):
                if field in params and not isinstance(params[field], bool):
                    raise ValueError(f"{field} must be a boolean")
            return params

        def _handle_message(self, connection: Dict[str, Any], frame: Any) -> None:
            payload = posted_payload(frame)
            if payload is None:
                return
            with self._lock:
                rules = list(connection["rules"].values())
            for rule in rules:
                params = dict(rule.trigger_params or {})
                if not rule_matches(payload, params, connection["own_user_id"]):
                    continue
                dedupe_key = (int(rule.rule_id), payload["post_id"])
                with connection["seen_lock"]:
                    if dedupe_key in connection["seen"]:
                        continue
                try:
                    event_id = self.emit(dict(payload), rule=rule, target_rule=True)
                    if event_id is None:
                        raise RuntimeError("Attune event emission failed")
                except Exception as exc:
                    self.logger.warning(
                        "Mattermost event emission failed for rule %s: %s",
                        rule.rule_id,
                        type(exc).__name__,
                    )
                    continue
                with connection["seen_lock"]:
                    connection["seen"][dedupe_key] = None
                    while len(connection["seen"]) > 10000:
                        connection["seen"].popitem(last=False)

        def _connection_loop(self, connection: Dict[str, Any]) -> None:
            credentials = connection["credentials"]
            delay = float(credentials.get("websocket_reconnect_min_seconds", 1))
            maximum = float(credentials.get("websocket_reconnect_max_seconds", 60))
            open_timeout = float(credentials.get("websocket_open_timeout_seconds", 10))
            ssl_options = {"cert_reqs": ssl.CERT_REQUIRED if credentials.get("verify_tls", True) else ssl.CERT_NONE}
            while not connection["stop"].is_set():
                app = None
                try:
                    app = websocket.create_connection(
                        websocket_url(credentials["base_url"]),
                        timeout=open_timeout,
                        header=[f"Authorization: Bearer {credentials['token']}"],
                        sslopt=ssl_options,
                        redirect_limit=0,
                    )
                    if app.getstatus() != 101:
                        raise RuntimeError("Mattermost WebSocket handshake was not accepted")
                    with connection["app_lock"]:
                        connection["app"] = app
                        if connection["stop"].is_set():
                            app.close()
                            connection["app"] = None
                            break
                    app.settimeout(1)
                    delay = float(credentials.get("websocket_reconnect_min_seconds", 1))
                    while not connection["stop"].is_set():
                        try:
                            frame = app.recv()
                        except websocket.WebSocketTimeoutException:
                            continue
                        if frame is None:
                            break
                        self._handle_message(connection, frame)
                except Exception as exc:
                    if not connection["stop"].is_set():
                        self.logger.warning("Mattermost WebSocket connection failed: %s", type(exc).__name__)
                finally:
                    with connection["app_lock"]:
                        if app is not None:
                            app.close()
                        connection["app"] = None
                if connection["stop"].wait(delay):
                    break
                delay = min(maximum, delay * 2)

        def _ensure_connection(self, credential_key: Any, rule: Any) -> str:
            params = self._validate_rule(rule)
            if not isinstance(credential_key, str) or not credential_key:
                raise ValueError("credential_key must be a non-empty string")
            with self._lock:
                existing = self._connections.get(credential_key)
                if existing is not None:
                    existing["rules"][rule.rule_id] = rule
                    return credential_key
            credential_key, credentials = self._fetch_credentials(credential_key)
            client = MattermostClient(credentials)
            _, user = client.request("GET", "/users/me")
            own_user_id = user.get("id") if isinstance(user, dict) else None
            if not isinstance(own_user_id, str) or not own_user_id:
                raise RuntimeError("Mattermost current-user response was invalid")
            connection: Dict[str, Any] = {
                "credentials": credentials,
                "rules": {rule.rule_id: rule},
                "own_user_id": own_user_id,
                "seen": OrderedDict(),
                "seen_lock": threading.Lock(),
                "app_lock": threading.Lock(),
                "stop": threading.Event(),
                "app": None,
            }
            thread = threading.Thread(
                target=self._connection_loop,
                args=(connection,),
                name=f"mattermost-websocket-{len(self._connections) + 1}",
                daemon=True,
            )
            connection["thread"] = thread
            with self._lock:
                existing = self._connections.get(credential_key)
                if existing is not None:
                    existing["rules"][rule.rule_id] = rule
                    return credential_key
                self._connections[credential_key] = connection
            thread.start()
            return credential_key

        @staticmethod
        def _stop_connection(connection: Dict[str, Any]) -> None:
            connection["stop"].set()
            with connection["app_lock"]:
                app = connection.get("app")
                if app is not None:
                    try:
                        app.close()
                    except Exception:
                        pass
            thread = connection.get("thread")
            if thread is not None and thread is not threading.current_thread():
                open_timeout = float(connection["credentials"].get("websocket_open_timeout_seconds", 10))
                thread.join(timeout=open_timeout + 2)

        def _subscribe(self, rule: Any) -> None:
            params = self._validate_rule(rule)
            credential_key = self._ensure_connection(
                params.get("credential_key", DEFAULT_CREDENTIAL_KEY), rule
            )
            with self._lock:
                previous = self._rule_credentials.get(rule.rule_id)
                self._rule_credentials[rule.rule_id] = credential_key
                self._pending.pop(rule.rule_id, None)
            if previous is not None and previous != credential_key:
                self._remove_rule(rule.rule_id, previous)

        def _remove_rule(self, rule_id: int, credential_key: str) -> None:
            stopped = None
            with self._lock:
                connection = self._connections.get(credential_key)
                if connection is None:
                    return
                connection["rules"].pop(rule_id, None)
                if not connection["rules"]:
                    stopped = self._connections.pop(credential_key)
            if stopped is not None:
                self._stop_connection(stopped)

        def _unsubscribe(self, rule_id: int) -> None:
            with self._lock:
                credential_key = self._rule_credentials.pop(rule_id, None)
                self._pending.pop(rule_id, None)
            if credential_key is not None:
                self._remove_rule(rule_id, credential_key)

        def _subscribe_or_queue(self, rule: Any) -> None:
            try:
                self._subscribe(rule)
            except Exception as exc:
                with self._lock:
                    prior = self._pending.get(rule.rule_id, {})
                    delay = min(60.0, float(prior.get("delay", 1.0)) * 2)
                    self._pending[rule.rule_id] = {
                        "rule": rule,
                        "delay": delay,
                        "next_attempt": time.monotonic() + float(prior.get("delay", 1.0)),
                    }
                self.logger.warning(
                    "Mattermost rule %s subscription failed and will retry: %s",
                    rule.rule_id,
                    type(exc).__name__,
                )

        def on_rule_created(self, rule: Any) -> None:
            self._subscribe_or_queue(rule)

        def on_rule_enabled(self, rule: Any) -> None:
            self._subscribe_or_queue(rule)

        def on_rule_updated(self, rule: Any, old_params: Dict[str, Any]) -> None:
            self._unsubscribe(rule.rule_id)
            self._subscribe_or_queue(rule)

        def on_rule_disabled(self, rule: Any) -> None:
            self._unsubscribe(rule.rule_id)

        def on_rule_deleted(self, rule: Any) -> None:
            self._unsubscribe(rule.rule_id)

        def run(self) -> None:
            while not self.is_shutting_down:
                now = time.monotonic()
                with self._lock:
                    due = [item["rule"] for item in self._pending.values() if item["next_attempt"] <= now]
                for rule in due:
                    self._subscribe_or_queue(rule)
                time.sleep(1)

        def cleanup(self) -> None:
            with self._lock:
                connections = list(self._connections.values())
                self._connections.clear()
                self._rule_credentials.clear()
                self._pending.clear()
            for connection in connections:
                self._stop_connection(connection)

    return MattermostWebSocketSensor


def main() -> None:
    import attune

    attune.run_sensor(_production_sensor())


if __name__ == "__main__":
    main()
