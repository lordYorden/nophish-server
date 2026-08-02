# NoPhish Server

![Python](https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.127.0-009688?logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL%20%2B%20pgvector-16-4169E1?logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-7-DC382D?logo=redis&logoColor=white)
![License](https://img.shields.io/badge/license-Apache%202.0-lightgrey)

NoPhish Server is the REST and detection backend for the NoPhish Android security app. It receives relevant notification submissions, queues them for phishing analysis, stores event state in Postgres, and sends Firebase Cloud Messaging alerts to trusted circles when a notification is flagged as malicious.

Android app: [lordYorden/nophish-android](https://github.com/lordYorden/nophish-android)

## What It Does

- Accepts relevant Android notification submissions through `POST /notifications/rel`.
- Deduplicates relevant-notification analysis submissions by client `eventId`.
- Stores analysis-event and malicious URL records in Postgres.
- Uses Redis and `arq` to run phishing detection outside the request path.
- Checks submitted notification text with an OpenRouter/OpenAI-compatible LLM.
- Scans submitted URLs for redirects, shorteners, unsafe hosts, IDN/confusable tricks, and browser-load failures.
- Compares submitted URLs with known malicious URL embeddings through pgvector.
- Sends malicious-event alerts through Firebase Cloud Messaging topics.
- Can seed known malicious URL vectors from the local fuzzing datasets.

## Book-to-Code Highlights

- **Three-layer phishing detection:** The worker combines [LLM message analysis](https://github.com/lordYorden/nophish-server/blob/main/app/detectors/tasks.py#L57-L67), [dynamic URL scanning](https://github.com/lordYorden/nophish-server/blob/main/app/detectors/tasks.py#L70-L90), and [malicious-URL vector matching](https://github.com/lordYorden/nophish-server/blob/main/app/detectors/tasks.py#L93-L134), running the modules [in parallel](https://github.com/lordYorden/nophish-server/blob/main/app/detectors/tasks.py#L210-L215).
- **Majority-vote verdicts:** When external AI analysis is enabled, an event is malicious only when [at least two detection modules agree](https://github.com/lordYorden/nophish-server/blob/main/app/detectors/tasks.py#L137-L152). This makes a single detector signal insufficient to alert the trusted circle.
- **Short-link expansion and redirect-chain analysis:** The URL scanner [follows HTTP redirects, detects loops and redirect limits, and probes HTML and JavaScript redirects](https://github.com/lordYorden/nophish-server/blob/main/app/detectors/url_scanner/http_redirects.py#L21-L128), with a [headless-browser fallback for shorteners](https://github.com/lordYorden/nophish-server/blob/main/app/detectors/url_scanner/scanner.py#L58-L77).
- **Obfuscation and impersonation resistance:** URLs are [normalised and checked for punycode, Unicode-confusable, mixed-script, IP-host, excessive-subdomain, and brand-impersonation signals](https://github.com/lordYorden/nophish-server/blob/main/app/detectors/url_scanner/normalization.py#L26-L90).
- **Trusted-circle alerts:** A malicious verdict is routed to a [circle-specific FCM topic](https://github.com/lordYorden/nophish-server/blob/main/app/detectors/tasks.py#L163-L172), where [Firebase Cloud Messaging delivers the event](https://github.com/lordYorden/nophish-server/blob/main/fcm/firebase.py#L11-L22) to a family member or trusted contact.
- **Known-malicious URL similarity matching:** The system performs [exact URL matching and vector-distance lookup](https://github.com/lordYorden/nophish-server/blob/main/app/detectors/tasks.py#L93-L134) against a [pgvector-backed URL corpus](https://github.com/lordYorden/nophish-server/blob/main/app/scheme/malicious_url.py#L6-L14), helping it recognise variants of known phishing URLs.
- **Privacy-aware analysis:** Clients explicitly choose whether to allow [external LLM analysis](https://github.com/lordYorden/nophish-server/blob/main/app/scheme/notification.py#L21-L33); when they opt out, the worker skips the LLM and [continues with local URL-based detection](https://github.com/lordYorden/nophish-server/blob/main/app/detectors/tasks.py#L216-L220).

## Architecture

![NoPhish architecture](./docs/archi-v6.png)

```text
Android app
  Relevant notification upload client
  Circle-aware FCM topic subscriptions

FastAPI service
  main.py
  /notifications/rel

Storage and queue
  Postgres + pgvector
  Redis
  arq jobs

Detection worker
  LLM content check
  Dynamic URL scanner
  Malicious URL embedding lookup
  Firebase Cloud Messaging alert sender
```

Important modules:

```text
app/
  routers/          FastAPI route handlers for relevant notification analysis
  scheme/           SQLModel and request/response models
  detectors/        arq worker task and URL scanner modules
  database.py       Postgres, pgvector, Redis, and optional seed setup

fcm/
  firebase.py       Firebase Admin initialization and topic messaging

llm/
  openr.py          OpenRouter chat call and sentence-transformer embeddings

pgvec/
  distance.py       pgvector nearest-distance lookup

fuzzing/
  data/             Seed and evaluation URL datasets
  seed_malicious_urls.py
  url_fuzzing.py
```

## Tech Stack

- Python 3.13
- FastAPI, Pydantic, SQLModel, and fastapi-pagination
- Postgres 16 with the pgvector extension
- Redis and `arq`
- Firebase Admin SDK for FCM
- OpenAI Python SDK against OpenRouter
- sentence-transformers for URL embeddings
- Playwright and httpx for dynamic URL scanning
- Docker Compose and `uv`

## Requirements

- Python 3.13
- [uv](https://docs.astral.sh/uv/getting-started/installation/)
- Docker and Docker Compose
- Firebase service-account JSON, usually `serviceKey.json`
- OpenRouter API key
- A chat model configured in `LLM_MODEL`
- A 384-dimension sentence-transformer model configured in `EMBED_MODEL`

## Configuration

Local infrastructure is configured through `compose.yml`. The Compose setup starts Postgres with pgvector, Redis, and the detection worker.

Postgres is configured in `compose.yml` with:

```yaml
POSTGRES_USER=nophish
POSTGRES_PASSWORD=nophish
POSTGRES_DB=nophish
```

The worker container is configured in `compose.yml` with:

```yaml
DYNAMIC_URL_SCANNER_ENABLE_BROWSER=true
REDIS_HOST=redis
DATABASE_URL=postgresql+psycopg://nophish:nophish@postgres:5432/nophish
GOOGLE_APPLICATION_CREDENTIALS=/run/secrets/serviceKey.json
```

`serviceKey.json` must exist at the repo root. Compose mounts it into the worker container at `/run/secrets/serviceKey.json`.

The LLM and embedding settings are still required by the worker. Add them to the worker environment in `compose.yml` or provide them through a Compose `env_file`:

```env
OPEN_ROUTER_KEY=your-openrouter-key
LLM_MODEL=your-openrouter-model
EMBED_MODEL=sentence-transformers/all-MiniLM-L6-v2
```

When running the API directly on the host, it connects to the Compose services through local defaults:

- `DATABASE_URL` falls back to `postgresql+psycopg://nophish:nophish@localhost:5432/nophish`.
- `REDIS_HOST` falls back to `localhost`.
- `REDIS_PORT` falls back to `6379`.
- `GOOGLE_APPLICATION_CREDENTIALS` falls back to `serviceKey.json`.

Optional malicious URL seeding is controlled by:

```env
SEED_MALICIOUS_URLS_ON_INIT=false
CLEAR_MALICIOUS_URLS_ON_INIT=false
MALICIOUS_URL_SEED_IF_EMPTY_ONLY=true
MALICIOUS_URL_SEED_LIMIT=500
MALICIOUS_URL_SEED_FUZZ_VARIANTS=2
MALICIOUS_URL_SEED_BATCH_SIZE=50
```

## Run

Build and run the Docker services with Compose:

```bash
docker compose up --build -d
```

Run the server:

```bash
uv run main.py
```

## Self-Hosting

For a self-hosted backend that should be reachable outside a USB-connected development session, publish it inside your tailnet with Tailscale. See the [Tailscale Services docs](https://tailscale.com/docs/features/tailscale-services).

## API

Relevant notification endpoints:

```text
POST   /notifications/rel
GET    /notifications/rel
DELETE /notifications/rel
```

`POST /notifications/rel` accepts relevant notification analysis submissions from the Android app, persists the event, and queues the detection worker. The submitted `circleId` is used for the FCM topic `circle_{circleId}`.

## Data Flow

1. The Android app identifies a relevant notification for analysis.
2. The app submits the notification payload to `POST /notifications/rel`.
3. The API rejects duplicate `eventId` submissions and stores new analysis events.
4. The API enqueues `detector_pipeline` in Redis through `arq`.
5. The worker runs the LLM content check, dynamic URL scanner, and malicious URL embedding lookup.
6. A notification is considered malicious when at least two of the three modules vote phishing.
7. The worker marks the event as alerted, sends an FCM alert to `circle_{circleId}`, and indexes newly observed malicious URLs.
8. The Android app receives the FCM payload and updates the trusted-circle experience.

## Data Model

The active flow uses `ReleventInfo` and `MaliciousUrl`.

### `ReleventInfo`

| Column | Type | Description |
| --- | --- | --- |
| `id` | string | UUID primary key |
| `eventId` | string | Unique client event ID |
| `sourceUserId` | string | User that submitted the notification |
| `circleId` | string | Circle used for FCM topic routing |
| `packageName` | string | Source Android package |
| `timestamp` | integer | Android notification timestamp |
| `contentHash` | string | Client content hash |
| `alerted` | boolean | Whether an FCM alert was sent |

### `MaliciousUrl`

| Column | Type | Description |
| --- | --- | --- |
| `id` | integer | Primary key |
| `url` | string | Canonical URL used for exact and vector lookup |
| `embedding` | vector(384) | Normalized URL embedding |

## Troubleshooting

- API startup failures usually mean Postgres or Redis is not running, or `DATABASE_URL` points at the wrong host.
- Worker startup failures usually point to Redis connectivity, missing `serviceKey.json`, missing `OPEN_ROUTER_KEY`, or an unset `EMBED_MODEL`.
- FCM delivery issues usually point to `GOOGLE_APPLICATION_CREDENTIALS`, Firebase project setup, or Android topic subscription state.
- Browser scan failures are expected unless `DYNAMIC_URL_SCANNER_ENABLE_BROWSER=true` and Playwright Chromium is installed in the worker environment.
- pgvector lookup failures usually mean the Postgres `vector` extension is unavailable or the database user cannot create extensions.
- The repository currently creates tables with SQLModel on startup; it does not have an active migration workflow.
