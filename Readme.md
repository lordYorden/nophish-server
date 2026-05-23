# NoPish (backend)

Phishing prevention tool for Android, as part of my Final Project.

You can find the android app repo [here](https://github.com/lordYorden/NoPhish-App)

## Quick Start Guide

### Prerequisites

- Docker and Docker Compose

### Installation & Setup

1. **Prepare runtime configuration**

   Ensure `serviceKey.json` exists in the repository root. It is mounted into
   the containers at runtime and is not copied into the image.

   This is a Firebase service account key, which can be downloaded from the
   [Firebase Console](https://console.firebase.google.com/).


   If you exercise the LLM or embedding paths, provide these values through
   your shell environment or a local `.env` file:

   ```bash
   OPEN_ROUTER_KEY=...
   LLM_MODEL=...
   EMBED_MODEL=...
   ```
2. **Run the stack**

   ```bash
   docker compose up --build
   ```
3. **Access the API**

   - API Base URL: `http://localhost:8000`
   - Interactive API Documentation: `http://localhost:8000/docs`

## Tech Specification

### Architecture

- **Framework**: `FastAPI` with `Pydantic`
- **Database**: `Postgres` with `pgvector` and `SQLModel` ORM
- **Background Tasks**: `arq` worker service with Redis for asynchronous phishing detection
- **AI Engine**: `OpenAI` (via LLM module) for message analysis
- **Infrastructure**: `Docker Compose` for the API server, Redis, Postgres, and worker
- **Messaging**: `Firebase Cloud Messaging (FCM)` for real-time phishing alerts
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

| Column           | Type    | Constraints | Description           |
| ---------------- | ------- | ----------- | --------------------- |
| `id`           | STRING  | PRIMARY KEY | UUID v4 identifier    |
| `phone_number` | STRING  | NOT NULL    | Sender's phone number |
| `body`         | STRING  | NULLABLE    | SMS message content   |
| `timestamp`    | INTEGER | NULLABLE    | Android SMS timestamp |

### Notification Table (`Notification`)

| Column          | Type    | Constraints | Description                  |
| --------------- | ------- | ----------- | ---------------------------- |
| `id`          | STRING  | PRIMARY KEY | UUID v4 identifier           |
| `title`       | STRING  | NOT NULL    | Notification title           |
| `body`        | STRING  | NULLABLE    | Notification content         |
| `timestamp`   | INTEGER | NULLABLE    | Unix timestamp               |
| `packageName` | STRING  | NULLABLE    | Android package name         |
| `extraTitle`  | STRING  | NULLABLE    | Additional title info        |
| `isGroup`     | BOOLEAN | NULLABLE    | Flag for group notifications |

### Relevant Info Table (`ReleventInfo`)

| Column          | Type   | Constraints | Description                         |
| --------------- | ------ | ----------- | ----------------------------------- |
| `id`          | STRING | PRIMARY KEY | UUID v4 identifier                  |
| `body`        | STRING | NULLABLE    | Content to analyze                  |
| `packageName` | STRING | NULLABLE    | Source package                      |
| `hash`        | STRING | NULLABLE    | Unique hash of the content          |
| `urls`        | JSON   | NULLABLE    | List of URLs extracted from content |
