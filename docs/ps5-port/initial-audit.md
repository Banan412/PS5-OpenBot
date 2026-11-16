# PS5 port: initial contract audit

Upstream baseline: `3083c34b0e9153b86c532112bdf0048202e91000`.

This is an initial inventory, not a claim of complete compatibility. `api/openapi/common.yaml` indexes 334 API paths with schemas and operations in domain-specific files. The upstream checkout does not contain `server/`; the backend is distributed as an image. Implementations must be derived from the published specifications and observed client behavior.

## Frontend connectivity

- `app/src/lib/client.ts` uses same-origin requests with credentials. Better Auth and direct fetches also need consideration if a separate API origin is introduced.
- `app/src/lib/socket-url.ts` derives production WebSocket URLs from the page origin. The Vite development and preview servers proxy `/api` including WebSockets.
- Building the app requires the root configuration generation and the `shared` workspace.

## Realtime contracts

See `api/asyncapi.yaml` for the authoritative message schemas. Conversation AG-UI uses Phoenix Channels v2, with `/websocket?join_token=...&vsn=2.0.0` and frames `[join_ref, ref, topic, event, payload]`. The REST-provided join token is short-lived and single-use; replay uses `metadata.cpki_event_id`. Conversation events require REST resynchronization after disconnect. Screen frames are complete images, and input is gated. Terminal data uses binary frames and JSON control messages. Voice and recorder use separate transports.

## Implementation constraints

The PS5 runtime must avoid process creation and shared-memory SQLite WAL. Validate the FreeBSD ABI and PS5 SDK integration before claiming a working ELF. Use same-origin serving initially to preserve upstream authentication and avoid cross-origin cookie complications.

## Environment observed

Both specified SDK directories exist, Debian WSL is installed, and Rust and Node are available on Windows. Bun was not found on PATH. PS5LM at `192.168.10.3:8081` did not accept a connection during the initial check; live verification remains outstanding.
