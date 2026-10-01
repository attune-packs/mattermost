# Mattermost pack

This pack connects Attune to Mattermost API v4. It includes REST actions, a serial thread-posting workflow, and a WebSocket sensor for new posts.

## Credentials

Create the Attune Key `pack.mattermost.credentials` with a JSON object:

```json
{
  "base_url": "https://chat.example.com",
  "token": "MATTERMOST_PERSONAL_ACCESS_TOKEN"
}
```

The Mattermost token needs only the permissions used by the actions and channels assigned to it. Do not grant system administrator access solely for this pack.

Optional fields:

| Field | Default | Bounds |
| --- | ---: | ---: |
| `verify_tls` | `true` | Boolean |
| `allow_insecure_http` | `false` | Boolean |
| `connect_timeout_seconds` | `10` | 1 to 120 |
| `read_timeout_seconds` | `30` | 1 to 300 |
| `max_get_rate_limit_retries` | `2` | 0 to 5 |
| `websocket_open_timeout_seconds` | `10` | 1 to 120 |
| `websocket_reconnect_min_seconds` | `1` | 1 to 60 |
| `websocket_reconnect_max_seconds` | `60` | 1 to 300 |

Plain HTTP is rejected unless `allow_insecure_http` is `true`. Use that override only for local development. TLS certificate checks remain enabled unless `verify_tls` is explicitly set to `false`.

## Actions

- `mattermost.api_call` calls one `/api/v4` path with a two MiB response limit. It rejects redirects and does not accept an absolute URL.
- `mattermost.post_message` creates a channel post or threaded reply.
- `mattermost.get_post`, `mattermost.update_post`, and `mattermost.delete_post` manage one post.
- `mattermost.list_channel_posts` fetches at most 10 pages of 100 posts each.
- `mattermost.upload_file` accepts UTF-8 content or one file below `ATTUNE_ARTIFACTS_DIR`, capped at 100 MiB.
- `mattermost.post_thread` creates one root post and up to 20 replies in order.

GET requests retry HTTP 429 responses within the configured limit. Mutating requests never retry because a transport failure can leave their outcome unknown.

## Live post trigger

Create a rule for `mattermost.post_created` and set `channel_id`. The sensor opens one outbound WebSocket per credential Key and routes matching posts directly to each rule.

The sensor refuses WebSocket redirects so the bearer token stays on the configured origin. Failed rule subscriptions retry with exponential backoff and do not stop healthy connections.

Optional rule filters:

- `user_id` accepts posts only from one author.
- `allow_self_posts` defaults to `false` to prevent simple automation loops.
- `allow_system_posts` defaults to `false` to exclude Mattermost system post types.

The sensor keeps a process-local deduplication window. Mattermost does not provide durable WebSocket replay, so messages sent while the sensor is disconnected are not recovered. Use a polling workflow if complete historical capture is required.

Interactive message buttons are not part of this release. Mattermost sends interaction callbacks to a public HTTP endpoint, not through its WebSocket. A future callback adapter or server plugin should own that boundary.

## Test and validate

```bash
python -m unittest discover -s tests -p 'test_*.py'
attune --output json pack check .
```

The tests mock Mattermost. They need no live token or network access.
