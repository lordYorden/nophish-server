# NoPish (backend)

Phishing prevention tool for Android, as part of my Final Project.

You can find the android app repo [here](https://github.com/lordYorden/NoPhish-App)

## Quick Start Guide

### Prerequisites

- Python 3.13 or higher
- Docker (for Redis and background workers)
- [uv](https://docs.astral.sh/uv/getting-started/installation/)

### Installation & Setup

1. **Sync dependencies**

   ```bash
   uv sync
   ```

2. **Run database migrations**

   ```bash
   uv run alembic upgrade head
   ```

3. **Run the server**

   ```bash
   uv run python main.py
   ```

   **Note**: The server uses `Testcontainers` to automatically manage a Redis instance and a worker container for the detection pipeline. Ensure Docker is running.

4. **Access the API**
   - API Base URL: `http://localhost:8000`
   - Interactive API Documentation: `http://localhost:8000/docs`

## Tech Specification

### Architecture

- **Framework**: `FastAPI` with `Pydantic`
- **Database**: `SQLite` with `SQLModel` ORM
- **Background Tasks**: `arq` (Redis-based job queue) for asynchronous phishing detection
- **AI Engine**: `OpenAI` (via LLM module) for message analysis
- **Infrastructure**: `Docker` integration via `Testcontainers` for seamless development
- **Messaging**: `Firebase Cloud Messaging (FCM)` for real-time phishing alerts
- **Migrations**: `Alembic` for schema versioning
- **Package Manager**: `uv`

### Detection Pipeline

When "Relevant Info" is uploaded, a background job is enqueued:

1. **LLM Check**: Analyzes the message content for phishing patterns using LLM.
2. **Parallel Modules**: Runs multiple detection logic modules simultaneously.
3. **Aggregation**: Results are aggregated; if a majority flags the content as phishing, a push notification is sent to the user via FCM.

### API Endpoints

#### SMS Messages

- `POST /messages` - Upload SMS message data
- `GET /messages` - Get paginated list of all SMS messages
- `GET /messages/{message_id}` - Get specific SMS message by ID
- `GET /messages/byNumber/{phone_number}` - Get paginated SMS messages by phone number

#### Notifications

- `POST /notifications` - Upload standard notification data
- `GET /notifications` - Get paginated list of all notifications
- `GET /notifications/byPackage/{package_name}` - Get notifications filtered by app package
- `POST /notifications/rel` - Upload "Relevant Info" for analysis (triggers detection pipeline)
- `GET /notifications/rel` - List all uploaded relevant info
- `DELETE /notifications/rel` - Clear all relevant info data

## SQL Models Overview

All models use UUID v4 for primary keys to ensure uniqueness.

### SMS Message Table (`SmsMessage`)

| Column         | Type    | Constraints | Description           |
| -------------- | ------- | ----------- | --------------------- |
| `id`           | STRING  | PRIMARY KEY | UUID v4 identifier    |
| `phone_number` | STRING  | NOT NULL    | Sender's phone number |
| `body`         | STRING  | NULLABLE    | SMS message content   |
| `timestamp`    | INTEGER | NULLABLE    | Android SMS timestamp |

### Notification Table (`Notification`)

| Column        | Type    | Constraints | Description                  |
| ------------- | ------- | ----------- | ---------------------------- |
| `id`          | STRING  | PRIMARY KEY | UUID v4 identifier           |
| `title`       | STRING  | NOT NULL    | Notification title           |
| `body`        | STRING  | NULLABLE    | Notification content         |
| `timestamp`   | INTEGER | NULLABLE    | Unix timestamp               |
| `packageName` | STRING  | NULLABLE    | Android package name         |
| `extraTitle`  | STRING  | NULLABLE    | Additional title info        |
| `isGroup`     | BOOLEAN | NULLABLE    | Flag for group notifications |

### Relevant Info Table (`ReleventInfo`)

| Column        | Type   | Constraints | Description                         |
| ------------- | ------ | ----------- | ----------------------------------- |
| `id`          | STRING | PRIMARY KEY | UUID v4 identifier                  |
| `body`        | STRING | NULLABLE    | Content to analyze                  |
| `packageName` | STRING | NULLABLE    | Source package                      |
| `hash`        | STRING | NULLABLE    | Unique hash of the content          |
| `urls`        | JSON   | NULLABLE    | List of URLs extracted from content |
