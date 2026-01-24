# NoPish (backend) - outdated

Phishing prevention tool for Android, as part of my Final Project.

You can find the android app repo [here](https://github.com/lordYorden/NoPhish-App)

## Quick Start Guide

### Prerequisites

- Python 3.8 or higher

### Installation & Setup

1. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```
2. **Run database migrations**

   ```bash
   alembic upgrade head
   ```
3. **Run the server**

   ```bash
   uvicorn main:app
   ```

   **[Optional] For development:**

   ```bash
   uvicorn main:app --reload
   ```
4. **Access the API**

   - API Base URL: `http://localhost:8000`
   - Interactive API Documentation: `http://localhost:8000/docs`
   - OpenAPI JSON Schema: `http://localhost:8000/openapi.json`

### Development Notes

- Use `--reload` flag only in development for auto-restart on file changes
- Default server runs on `localhost:8000`

## Tech Specification

### Architecture

- **Framework**: using `FastAPI` with `Pydantic`
- **Database**: `SQLite` with `SQLModel` ORM
- **Pagination**: FastAPI Pagination for large datasets
- **Migrations**: using `Alembic` for schema versioning

### API Endpoints

#### SMS Messages

- `POST /messages` - Upload SMS message data
- `GET /messages?page={page}&size={size}` - Get paginated list of all SMS messages
  - `page` (optional): Page number (default: 1)
  - `size` (optional): Items per page (default: 50)
- `GET /messages/{message_id}` - Get specific SMS message by ID
- `GET /messages/byNumber/{phone_number}?page={page}&size={size}` - Get paginated SMS messages by phone number
  - `page` (optional): Page number (default: 1)
  - `size` (optional): Items per page (default: 50)

#### Notifications

- `POST /notifications` - Upload notification data
- `GET /notifications?page={page}&size={size}` - Get paginated list of all notifications
  - `page` (optional): Page number (default: 1)
  - `size` (optional): Items per page (default: 50)

### Database Configuration

**Database Type**: SQLite

**Alembic Configuration:**

- **Config File**: `alembic.ini` - Contains Alembic settings and database URL
- **Environment**: `migrations/env.py` - Handles migration environment setup
- **Versions Folder**: `migrations/versions/` - Contains all migration scripts

**Migration Workflow:**

1. **Auto-generate migrations**: `alembic revision --autogenerate -m "description"`
2. **Apply migrations**: `alembic upgrade head`
3. **Check current version**: `alembic current`
4. **View migration history**: `alembic history`

## SQL Models Overview

### SMS Message Table

Stores SMS message data for phishing analysis.

| Column           | Type    | Constraints | Description           |
| ---------------- | ------- | ----------- | --------------------- |
| `id`           | STRING  | PRIMARY KEY | UUID v4 identifier    |
| `phone_number` | STRING  | NOT NULL    | Sender's phone number |
| `body`         | STRING  | NULLABLE    | SMS message content   |
| `timestamp`    | INTEGER | NULLABLE    | android sms timestamp |

**Purpose**: Tracks SMS messages received by users to analyze potential phishing attempts (in the future).

### Notification Table

Stores Android notification data for security monitoring.

| Column          | Type    | Constraints | Description                                              |
| --------------- | ------- | ----------- | -------------------------------------------------------- |
| `id`          | STRING  | PRIMARY KEY | UUID v4 identifier                                       |
| `title`       | STRING  | NOT NULL    | Notification title                                       |
| `body`        | STRING  | NULLABLE    | Notification content/message                             |
| `timestamp`   | INTEGER | NULLABLE    | notification reciving time Unix timestamp               |
| `packageName` | STRING  | NULLABLE    | Android app package name that generated the notification |

**Purpose**: Monitors Android notifications to detect suspicious app behavior and potential phishing notifications (in the future).

- Both models use UUID v4 for primary keys to ensure uniqueness across distributed systems

### Todo

- add an endpint to get notiffications by package name
- improving logic and security
