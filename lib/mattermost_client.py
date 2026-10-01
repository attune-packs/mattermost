"""Bounded Mattermost REST API client and action operations."""

from __future__ import annotations

import json
import math
import os
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping
from urllib.parse import quote, unquote, urlsplit

import requests


DEFAULT_CREDENTIAL_KEY = "pack.mattermost.credentials"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_UPLOAD_BYTES = 100 * 1024 * 1024
POST_FIELDS = (
    "id", "channel_id", "user_id", "root_id", "message", "type",
    "create_at", "update_at", "edit_at", "delete_at", "is_pinned",
    "file_ids", "has_reactions", "reply_count", "last_reply_at",
)
FILE_FIELDS = ("id", "user_id", "channel_id", "name", "extension", "size", "mime_type")
SECRET_FIELDS = {"access_token", "password", "secret", "token"}


class MattermostPackError(RuntimeError):
    """Safe operator-facing Mattermost pack error."""


def _fetch_key(ref: str) -> Dict[str, Any]:
    if not isinstance(ref, str) or not ref.startswith("pack.mattermost."):
        raise MattermostPackError("credential_key must reference a pack.mattermost Key")
    try:
        import attune
        from attune.api_client.api.secrets import get_key
    except ImportError as exc:
        raise MattermostPackError("attune-sdk is required to resolve credential_key") from exc
    try:
        response = get_key.sync_detailed(ref, client=attune.context.client)
    except Exception as exc:
        raise MattermostPackError(f"unable to read credential Key {ref!r}") from exc
    status = int(response.status_code)
    if status == 404:
        raise MattermostPackError(f"credential Key {ref!r} was not found")
    if status >= 400 or not response.parsed:
        raise MattermostPackError(f"credential Key lookup failed with status {status}")
    value = response.parsed.data.value
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise MattermostPackError("credential Key must contain a JSON object") from exc
    if not isinstance(value, dict):
        raise MattermostPackError("credential Key must contain an object")
    return value


def _number(config: Mapping[str, Any], name: str, default: float, low: float, high: float) -> float:
    value = config.get(name, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MattermostPackError(f"{name} must be a number")
    result = float(value)
    if not math.isfinite(result) or result < low or result > high:
        raise MattermostPackError(f"{name} must be between {low:g} and {high:g}")
    return result


def _integer(value: Any, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < low or value > high:
        raise MattermostPackError(f"{name} must be an integer between {low} and {high}")
    return value


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise MattermostPackError(f"{name} must be a non-empty Mattermost identifier")
    if not all(character.isascii() and (character.islower() or character.isdigit()) for character in value):
        raise MattermostPackError(f"{name} must contain lowercase ASCII letters and digits")
    return value


def validate_credentials(value: Any) -> Dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise MattermostPackError("credential Key must contain a JSON object") from exc
    if not isinstance(value, dict):
        raise MattermostPackError("credential Key must contain a JSON object")
    base_url = value.get("base_url")
    if not isinstance(base_url, str) or not base_url or base_url != base_url.strip():
        raise MattermostPackError("credential Key requires base_url")
    if any(character.isspace() or ord(character) < 32 for character in base_url):
        raise MattermostPackError("base_url must not contain whitespace or control characters")
    try:
        parts = urlsplit(base_url.rstrip("/"))
        hostname = parts.hostname
        parts.port
    except ValueError as exc:
        raise MattermostPackError("base_url is not a valid URL") from exc
    allow_http = value.get("allow_insecure_http", False)
    if not isinstance(allow_http, bool):
        raise MattermostPackError("allow_insecure_http must be a boolean")
    if parts.scheme not in {"http", "https"} or not parts.netloc or not hostname:
        raise MattermostPackError("base_url must be an HTTP(S) URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise MattermostPackError("base_url must not contain credentials, a query, or a fragment")
    if parts.scheme != "https" and not allow_http:
        raise MattermostPackError("base_url must use HTTPS unless allow_insecure_http is true")
    token = value.get("token")
    if not isinstance(token, str) or not token:
        raise MattermostPackError("credential Key requires token")
    verify_tls = value.get("verify_tls", True)
    if not isinstance(verify_tls, bool):
        raise MattermostPackError("verify_tls must be a boolean")
    _number(value, "connect_timeout_seconds", 10, 1, 120)
    _number(value, "read_timeout_seconds", 30, 1, 300)
    _integer(value.get("max_get_rate_limit_retries", 2), "max_get_rate_limit_retries", 0, 5)
    _number(value, "websocket_open_timeout_seconds", 10, 1, 120)
    reconnect_min = _number(value, "websocket_reconnect_min_seconds", 1, 1, 60)
    reconnect_max = _number(value, "websocket_reconnect_max_seconds", 60, 1, 300)
    if reconnect_max < reconnect_min:
        raise MattermostPackError("websocket_reconnect_max_seconds must not be below websocket_reconnect_min_seconds")
    return dict(value)


def _redact(value: Any, secrets: Iterable[str] = ()) -> Any:
    secret_values = tuple(item for item in secrets if item)
    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            normalized = str(key).lower()
            sensitive = normalized in SECRET_FIELDS or normalized.endswith(("_password", "_secret", "_token"))
            result[key] = "REDACTED" if sensitive else _redact(item, secret_values)
        return result
    if isinstance(value, list):
        return [_redact(item, secret_values) for item in value]
    if isinstance(value, str):
        for secret in secret_values:
            value = value.replace(secret, "REDACTED")
    return value


def normalize_post(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise MattermostPackError("Mattermost post response was not an object")
    return {field: value[field] for field in POST_FIELDS if field in value}


class MattermostClient:
    def __init__(self, config: Mapping[str, Any], *, session: Any = None, sleep: Any = time.sleep):
        checked = validate_credentials(config)
        self.base_url = str(checked["base_url"]).rstrip("/")
        self.api_root = f"{self.base_url}/api/v4"
        self.token = str(checked["token"])
        self.headers = {"Accept": "application/json", "Authorization": f"Bearer {self.token}"}
        self.verify = checked.get("verify_tls", True)
        self.timeout = (
            _number(checked, "connect_timeout_seconds", 10, 1, 120),
            _number(checked, "read_timeout_seconds", 30, 1, 300),
        )
        self.max_get_rate_limit_retries = _integer(
            checked.get("max_get_rate_limit_retries", 2), "max_get_rate_limit_retries", 0, 5
        )
        self.session = session or requests.Session()
        self.sleep = sleep

    def _url(self, endpoint: str) -> str:
        if not isinstance(endpoint, str) or not endpoint.startswith("/") or endpoint.startswith("//"):
            raise MattermostPackError("endpoint must be an absolute path below /api/v4")
        parts = urlsplit(endpoint)
        decoded_path = parts.path
        for _ in range(3):
            decoded_path = unquote(decoded_path)
        if (
            parts.scheme
            or parts.netloc
            or parts.query
            or parts.fragment
            or ".." in decoded_path.split("/")
            or "\\" in decoded_path
            or any(character.isspace() or ord(character) < 32 for character in decoded_path)
        ):
            raise MattermostPackError("endpoint must be a path without an origin, query, fragment, or traversal")
        return f"{self.api_root}{endpoint}"

    @staticmethod
    def _read_response(response: Any) -> bytes:
        raw_length = response.headers.get("Content-Length")
        if raw_length is not None:
            try:
                parsed_length = int(raw_length)
                if parsed_length < 0:
                    raise ValueError
                if parsed_length > MAX_RESPONSE_BYTES:
                    raise MattermostPackError("Mattermost API response exceeded the size limit")
            except ValueError as exc:
                raise MattermostPackError("Mattermost API returned an invalid Content-Length") from exc
        chunks = []
        size = 0
        iterator = getattr(response, "iter_content", None)
        if callable(iterator):
            source = iterator(chunk_size=65536)
        else:
            source = (getattr(response, "content", b""),)
        for chunk in source:
            if not chunk:
                continue
            size += len(chunk)
            if size > MAX_RESPONSE_BYTES:
                raise MattermostPackError("Mattermost API response exceeded the size limit")
            chunks.append(chunk)
        return b"".join(chunks)

    @staticmethod
    def _retry_after(response: Any) -> float:
        raw = response.headers.get("Retry-After") or response.headers.get("X-RateLimit-Reset") or "1"
        try:
            value = float(raw)
            if value > time.time() + 1:
                value -= time.time()
            return min(60.0, max(0.0, value))
        except (TypeError, ValueError, OverflowError):
            return 1.0

    def request(
        self,
        method: str,
        endpoint: str,
        *,
        params: Mapping[str, Any] | None = None,
        body: Any = None,
        data: bytes | None = None,
        content_type: str | None = None,
    ) -> tuple[int, Any]:
        method = str(method).upper()
        if method not in {"GET", "POST", "PUT", "DELETE"}:
            raise MattermostPackError("method must be GET, POST, PUT, or DELETE")
        headers = dict(self.headers)
        kwargs: Dict[str, Any] = {
            "headers": headers,
            "params": params,
            "timeout": self.timeout,
            "verify": self.verify,
            "allow_redirects": False,
            "stream": True,
        }
        if body is not None:
            kwargs["json"] = body
        if data is not None:
            kwargs["data"] = data
            headers["Content-Type"] = content_type or "application/octet-stream"
        attempts = self.max_get_rate_limit_retries + 1 if method == "GET" else 1
        response = None
        for attempt in range(attempts):
            try:
                response = self.session.request(method, self._url(endpoint), **kwargs)
            except (requests.RequestException, OSError) as exc:
                suffix = "; mutation outcome may be unknown" if method != "GET" else ""
                raise MattermostPackError(
                    f"Mattermost API {method} transport failed ({type(exc).__name__}){suffix}"
                ) from exc
            if response.status_code == 429 and method == "GET" and attempt + 1 < attempts:
                delay = self._retry_after(response)
                response.close()
                self.sleep(delay)
                continue
            break
        assert response is not None
        status = int(response.status_code)
        if 300 <= status < 400:
            response.close()
            raise MattermostPackError(f"Mattermost API {method} refused HTTP redirect status {status}")
        if status >= 400:
            request_id = response.headers.get("X-Request-ID", "")
            response.close()
            detail = f" request_id={request_id}" if request_id and len(request_id) <= 128 and request_id.isprintable() else ""
            raise MattermostPackError(f"Mattermost API {method} failed with HTTP status {status}{detail}")
        try:
            content = self._read_response(response)
        finally:
            response.close()
        if status == 204 or not content:
            return status, None
        try:
            decoded = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MattermostPackError("Mattermost API returned invalid JSON") from exc
        return status, _redact(decoded, (self.token,))


def _client(params: Mapping[str, Any]) -> MattermostClient:
    key = params.get("credential_key", DEFAULT_CREDENTIAL_KEY)
    return MattermostClient(_fetch_key(key))


def api_call(params: Mapping[str, Any]) -> Dict[str, Any]:
    query = params.get("query", {})
    body = params.get("body")
    if not isinstance(query, dict):
        raise MattermostPackError("query must be an object")
    if body is not None and not isinstance(body, dict):
        raise MattermostPackError("body must be an object")
    status, data = _client(params).request(
        params.get("method", "GET"), params.get("endpoint"), params=query, body=body
    )
    return {"status_code": status, "data": data}


def post_message(params: Mapping[str, Any]) -> Dict[str, Any]:
    message = params.get("message")
    if not isinstance(message, str) or not message or len(message) > 16383:
        raise MattermostPackError("message must contain between 1 and 16383 characters")
    body = {"channel_id": _identifier(params.get("channel_id"), "channel_id"), "message": message}
    if params.get("root_id") is not None:
        body["root_id"] = _identifier(params["root_id"], "root_id")
    _, result = _client(params).request("POST", "/posts", body=body)
    return {"post": normalize_post(result)}


def get_post(params: Mapping[str, Any]) -> Dict[str, Any]:
    post_id = _identifier(params.get("post_id"), "post_id")
    _, result = _client(params).request("GET", f"/posts/{quote(post_id, safe='')}")
    return {"post": normalize_post(result)}


def update_post(params: Mapping[str, Any]) -> Dict[str, Any]:
    post_id = _identifier(params.get("post_id"), "post_id")
    message = params.get("message")
    if not isinstance(message, str) or not message or len(message) > 16383:
        raise MattermostPackError("message must contain between 1 and 16383 characters")
    _, result = _client(params).request("PUT", f"/posts/{quote(post_id, safe='')}/patch", body={"message": message})
    return {"post": normalize_post(result)}


def delete_post(params: Mapping[str, Any]) -> Dict[str, Any]:
    post_id = _identifier(params.get("post_id"), "post_id")
    status, _ = _client(params).request("DELETE", f"/posts/{quote(post_id, safe='')}")
    return {"deleted": True, "post_id": post_id, "status_code": status}


def list_channel_posts(params: Mapping[str, Any]) -> Dict[str, Any]:
    channel_id = _identifier(params.get("channel_id"), "channel_id")
    page = _integer(params.get("page", 0), "page", 0, 1_000_000)
    per_page = _integer(params.get("per_page", 60), "per_page", 1, 100)
    max_pages = _integer(params.get("max_pages", 1), "max_pages", 1, 10)
    if page + max_pages - 1 > 1_000_000:
        raise MattermostPackError("page plus max_pages must not exceed page 1000000")
    client = _client(params)
    posts = []
    seen = set()
    full_last_page = False
    for offset in range(max_pages):
        _, result = client.request(
            "GET", f"/channels/{quote(channel_id, safe='')}/posts",
            params={"page": page + offset, "per_page": per_page},
        )
        if not isinstance(result, dict) or not isinstance(result.get("order"), list) or not isinstance(result.get("posts"), dict):
            raise MattermostPackError("Mattermost channel posts response was invalid")
        order = result["order"]
        full_last_page = len(order) >= per_page
        for post_id in order:
            if post_id in seen or post_id not in result["posts"]:
                continue
            seen.add(post_id)
            posts.append(normalize_post(result["posts"][post_id]))
        if not full_last_page:
            break
    return {
        "posts": posts,
        "count": len(posts),
        "pages_fetched": offset + 1,
        "truncated": full_last_page and offset + 1 == max_pages,
    }


def _artifact_file(value: Any) -> Path:
    root_value = os.environ.get("ATTUNE_ARTIFACTS_DIR")
    if not root_value:
        raise MattermostPackError("ATTUNE_ARTIFACTS_DIR is required for file_path uploads")
    root = Path(root_value).resolve()
    candidate = Path(str(value)).resolve()
    if candidate == root or root not in candidate.parents or not candidate.is_file():
        raise MattermostPackError("file_path must be a file below ATTUNE_ARTIFACTS_DIR")
    return candidate


def upload_file(params: Mapping[str, Any]) -> Dict[str, Any]:
    channel_id = _identifier(params.get("channel_id"), "channel_id")
    file_path = params.get("file_path")
    content = params.get("content")
    if (file_path is None) == (content is None):
        raise MattermostPackError("provide exactly one of file_path or content")
    if file_path is not None:
        path = _artifact_file(file_path)
        with path.open("rb") as artifact:
            data = artifact.read(MAX_UPLOAD_BYTES + 1)
        if len(data) > MAX_UPLOAD_BYTES:
            raise MattermostPackError("file exceeds the 100 MiB action upload limit")
        filename = params.get("filename") or path.name
    else:
        if not isinstance(content, str):
            raise MattermostPackError("content must be a string")
        data = content.encode("utf-8")
        if len(data) > MAX_UPLOAD_BYTES:
            raise MattermostPackError("content exceeds the 100 MiB action upload limit")
        filename = params.get("filename")
    if not isinstance(filename, str) or not filename or len(filename) > 255 or "/" in filename or "\\" in filename:
        raise MattermostPackError("filename must be a plain file name of at most 255 characters")
    _, result = _client(params).request(
        "POST", "/files", params={"channel_id": channel_id, "filename": filename}, data=data
    )
    if not isinstance(result, dict) or not isinstance(result.get("file_infos"), list):
        raise MattermostPackError("Mattermost file upload response was invalid")
    files = [
        {field: item[field] for field in FILE_FIELDS if field in item}
        for item in result["file_infos"] if isinstance(item, dict)
    ]
    return {"files": files, "count": len(files)}


OPERATIONS = {
    "api_call": api_call,
    "post_message": post_message,
    "get_post": get_post,
    "update_post": update_post,
    "delete_post": delete_post,
    "list_channel_posts": list_channel_posts,
    "upload_file": upload_file,
}


def execute_action(operation: str, params: Mapping[str, Any]) -> Dict[str, Any]:
    handler = OPERATIONS.get(operation)
    if handler is None:
        raise MattermostPackError(f"unsupported Mattermost operation {operation!r}")
    return handler(params)
