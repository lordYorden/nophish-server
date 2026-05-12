# FastAPI Analysis Pipeline Plan

## Goal

Update the FastAPI backend/analyzer so it matches the app's privacy-first secure notification flow.

The backend should:

- Accept notification submissions from the phone and return immediately.
- Analyze notifications asynchronously.
- Send plaintext malicious details through FCM only when malicious.
- Never store notification title, body, or URL list as durable backend history.

## Incoming App Upload

The app uploads a captured notification with a stable `eventId` generated on device.

Expected request shape:

```json
{
  "eventId": "...",
  "sourceUserId": "...",
  "title": "...",
  "body": "...",
  "packageName": "com.example.app",
  "timestamp": 123456789,
  "contentHash": "...",
  "urls": []
}
```

Required fields:

- `eventId`
- `sourceUserId`
- `body`
- `packageName`
- `timestamp`
- `contentHash`

Optional fields:

- `title`
- `urls`

Backend behavior:

1. Validate required fields.
2. Authenticate the request if the backend currently supports auth.
3. If auth is available, confirm the authenticated user matches `sourceUserId`.
4. Queue the notification for analysis.
5. Return immediately.

Suggested response:

```json
{
  "accepted": true,
  "eventId": "..."
}
```

The phone must not wait for the analysis verdict.

## Async Analysis

Move verdict work into a background job or task queue.

Possible options:

- FastAPI `BackgroundTasks` for a simple first version.
- Celery/RQ/Arq/Redis queue for more durable processing.
- Existing analyzer worker if one already exists.

Flow:

```text
POST notification
  -> validate payload
  -> enqueue analysis job
  -> return immediately

analysis job
  -> classify notification
  -> if benign/inconclusive: do nothing
  -> if malicious: send FCM malicious payload
```

If the notification is benign or inconclusive:

- Do not send FCM.
- The app's pending state expires naturally.

If the notification is malicious:

- Send the malicious FCM payload to the relevant app devices.
- The receiving app stores plaintext locally.


## Canonical Hash Compatibility

The app computes:

```text
contentHash = SHA-256(canonical JSON payload)
```

Canonical payload fields, in this exact order:

```json
{
  "eventId": "...",
  "title": "...",
  "body": "...",
  "packageName": "...",
  "urls": [],
  "timestamp": 123456789,
  "sourceUserId": "..."
}
```

Rules:

- `urls` are sorted before hashing.
- Do not include FCM receive time.
- Do not include backend receive time.
- Do not include database insert time.
- Do not include device-specific values.

For the first backend update:

```text
Trust and pass through the app-provided contentHash.
```

Only add backend recomputation after tests prove the Python JSON output matches the Android Kotlin serializer byte-for-byte.

If recomputing in Python later, start with compact JSON:

```python
json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
```

Then verify against Android-generated test vectors before enforcing.

## Malicious FCM Payload

For malicious notifications, send FCM with one top-level `data` key whose value is a JSON string.

The Android app intentionally rejects flat FCM fields.

FCM data payload shape:

```json
{
  "data": "{\"eventId\":\"...\",\"sourceUserId\":\"...\",\"title\":\"...\",\"body\":\"...\",\"packageName\":\"com.example.app\",\"timestamp\":123456789,\"contentHash\":\"...\",\"urls\":[\"https://example.com\"]}"
}
```

Required inside the JSON string:

- `eventId`
- `sourceUserId`
- `body`
- `packageName`
- `timestamp`
- `contentHash`

Optional inside the JSON string:

- `title`
- `urls`

Important:

- If top-level `"data"` is missing, the app drops the payload.
- If a required field inside the JSON is missing or invalid, the app drops the payload.
- FCM plaintext is expected for malicious callbacks.

## Circle / Device Targeting

For v1, if the current backend only sends to a test topic, update that topic payload format first

## Idempotency

Use `eventId` as the idempotency key for analysis jobs and FCM retries.

Backend should avoid duplicate processing where practical:

- If the same `eventId` is submitted twice, do not enqueue duplicate analysis jobs if a job/result already exists.
- If FCM retry happens, use the same payload and same `eventId`.
- Do not generate a new event id on the backend.

## Error Handling

Upload endpoint:

- Missing required field: `400 Bad Request`.
- Unauthenticated request: `401 Unauthorized`, if auth is enforced.
- Auth user does not match `sourceUserId`: `403 Forbidden`, if auth is enforced.
- Queue unavailable: `503 Service Unavailable`.

Analysis worker:

- Benign/inconclusive verdict: log and stop.
- Malicious verdict but FCM fails: log retryable error.
- FCM payload construction missing required field: fail the job and log event id.

## Logging Rules

Do not log full notification plaintext in production logs.

Safe logs:

- `eventId`
- `sourceUserId`
- `packageName`
- `timestamp`
- verdict
- error category

Avoid logs:

- `title`
- `body`
- full URL list
- raw analyzer input
- full FCM payload

## Tests

Add backend tests for:

- Upload returns immediately after enqueueing.
- Missing required upload fields return `400`.
- Benign verdict sends no FCM.
- Malicious verdict sends one FCM malicious payload.
- FCM payload uses top-level `"data"` JSON string.
- Flat FCM fields are not used.
- FCM JSON contains every required field.
- FCM JSON preserves the original `eventId`.
- FCM JSON preserves the app-provided `contentHash`.
- Duplicate `eventId` does not enqueue duplicate work where idempotency is implemented.
