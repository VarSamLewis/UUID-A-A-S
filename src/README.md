# UUID Service API

A simple HTTP API that generates and tracks UUIDs.

## Endpoints

### POST /v1/signup

Create a new user account.

**Request:**
```bash
curl -X POST http://localhost:8080/v1/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com"}'
```

**Response:**
```json
{
  "id": 1,
  "email": "you@example.com",
  "name": "You",
  "api_key": "550e8400-e29b-41d4-a716-446655440000",
  "status": "active"
}
```

**Note:** The API key is shown once. Save it immediately.

### POST /v1/login

Validate an API key and return user info.

**Request:**
```bash
curl -X POST http://localhost:8080/v1/login \
  -H "Authorization: Bearer <your-api-key>"
```

**Response:**
```json
{
  "id": 1,
  "email": "you@example.com",
  "name": "You",
  "status": "active",
  "created_at": "2026-06-17T18:00:00Z"
}
```

### GET /v1/users/{id}

Get user information by ID.

**Request:**
```bash
curl http://localhost:8080/v1/users/1 \
  -H "Authorization: Bearer <your-api-key>"
```

**Response:**
```json
{
  "id": 1,
  "email": "you@example.com",
  "name": "You",
  "status": "active",
  "created_at": "2026-06-17T18:00:00Z"
}
```

### POST /v1/uuid

Generate a unique UUID.

**Request:**
```bash
curl -X POST http://localhost:8080/v1/uuid \
  -H "Authorization: Bearer <your-api-key>"
```

**Response:**
```json
{
  "uuid": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": 1,
  "email": "you@example.com",
  "timestamp": "2026-06-17T18:00:00Z"
}
```

## Authentication

All endpoints except `POST /v1/signup` require authentication.

**Header:** `Authorization: Bearer <your-api-key>`

## Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| POST /v1/signup | 3 requests per IP | 1 hour |
| POST /v1/uuid | 100 requests per API key | 1 minute |
| POST /v1/login (failed) | 10 failed attempts per IP | 1 minute |

## Running the Server

```bash
go build .
./v1/uuid_service
```

Server starts on port 8080.
