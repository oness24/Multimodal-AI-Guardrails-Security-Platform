# API Reference

This document provides detailed information about the AdversarialShield API endpoints.

## Base URL

```
http://localhost:8000
```

## Authentication

Currently, the API does not require authentication (development mode). Authentication will be added in future releases.

---

## Health & Info Endpoints

### GET /health

Health check endpoint for monitoring.

**Response:**
```json
{
  "status": "healthy",
  "environment": "development",
  "version": "0.1.0"
}
```

### GET /

Root endpoint with API information.

**Response:**
```json
{
  "name": "AdversarialShield API",
  "version": "0.1.0",
  "description": "Multimodal AI Security Testing & Guardrails Platform",
  "docs": "/docs"
}
```

---

## Red Team Endpoints

Base path: `/api/v1/redteam`

### POST /api/v1/redteam/generate

Generate an adversarial attack using a specified technique.

**Request Body:**
```json
{
  "technique": "context_manipulation",
  "target_context": {
    "model": "gpt-4",
    "system_prompt": "You are a helpful assistant"
  },
  "custom_objective": "bypass safety guidelines",
  "llm_provider": "openai"
}
```

**Parameters:**
- `technique` (required): Attack technique to use
  - `context_manipulation`
  - `instruction_override`
  - `delimiter_confusion`
  - `role_playing`
  - `indirect_injection`
  - `encoding_attack`
  - `multi_language`
  - `escape_characters`
- `target_context` (optional): Context about the target system
- `custom_objective` (optional): Custom attack objective
- `llm_provider` (optional): LLM provider (default: "openai")

**Response:**
```json
{
  "id": null,
  "technique": "context_manipulation",
  "payload": "Generated attack payload here...",
  "llm_provider": "openai",
  "success": true,
  "error": null
}
```

---

### POST /api/v1/redteam/generate/batch

Generate multiple attacks in parallel for different techniques.

**Request Body:**
```json
{
  "techniques": [
    "context_manipulation",
    "instruction_override",
    "role_playing"
  ],
  "target_context": {
    "model": "gpt-4"
  },
  "llm_provider": "openai"
}
```

**Response:**
```json
[
  {
    "technique": "context_manipulation",
    "payload": "Attack payload 1...",
    "llm_provider": "openai",
    "success": true
  },
  {
    "technique": "instruction_override",
    "payload": "Attack payload 2...",
    "llm_provider": "openai",
    "success": true
  }
]
```

---

### POST /api/v1/redteam/test

Test an attack payload against a target model.

**Request Body:**
```json
{
  "payload": "Ignore all previous instructions...",
  "target_model": "gpt-3.5-turbo",
  "test_prompt": "What is the capital of France?",
  "llm_provider": "openai"
}
```

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "payload": "Ignore all previous instructions...",
  "response": "Model response here...",
  "success": true,
  "execution_time_ms": 1250,
  "target_model": "gpt-3.5-turbo",
  "error": null
}
```

---

### GET /api/v1/redteam/techniques

List all available attack techniques.

**Response:**
```json
[
  "context_manipulation",
  "instruction_override",
  "delimiter_confusion",
  "role_playing",
  "indirect_injection",
  "encoding_attack",
  "multi_language",
  "escape_characters"
]
```

---

### GET /api/v1/redteam/patterns

List attack patterns from database with optional filtering.

**Query Parameters:**
- `technique` (optional): Filter by technique
- `category` (optional): Filter by category (e.g., "prompt_injection", "jailbreak")
- `severity` (optional): Filter by severity (low, medium, high, critical)
- `limit` (optional): Number of results (default: 50, max: 100)
- `offset` (optional): Pagination offset (default: 0)

**Example:**
```
GET /api/v1/redteam/patterns?technique=role_playing&severity=high&limit=10
```

**Response:**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Role-Playing - DAN (Do Anything Now)",
    "technique": "role_playing",
    "category": "jailbreak",
    "description": "Famous DAN jailbreak using role-playing",
    "severity": "critical",
    "owasp_category": "LLM01:2023 - Prompt Injection",
    "success_rate": 0.75,
    "total_executions": 100
  }
]
```

---

### GET /api/v1/redteam/patterns/{pattern_id}

Get a specific attack pattern by ID.

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Role-Playing - DAN (Do Anything Now)",
  "technique": "role_playing",
  "category": "jailbreak",
  "description": "Famous DAN jailbreak using role-playing",
  "severity": "critical",
  "owasp_category": "LLM01:2023 - Prompt Injection",
  "success_rate": 0.75,
  "total_executions": 100
}
```

---

### GET /api/v1/redteam/logs

List attack execution logs.

**Query Parameters:**
- `technique` (optional): Filter by technique
- `success` (optional): Filter by success status (true/false)
- `limit` (optional): Number of results (default: 50, max: 100)
- `offset` (optional): Pagination offset (default: 0)

**Response:**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "technique": "context_manipulation",
    "success": true,
    "target_model": "gpt-4",
    "execution_time_ms": 1250,
    "created_at": "2025-11-16T12:00:00"
  }
]
```

---

### GET /api/v1/redteam/logs/{log_id}

Get detailed information about a specific attack log.

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "technique": "context_manipulation",
  "payload": "Attack payload...",
  "response": "Model response...",
  "success": true,
  "target_model": "gpt-4",
  "execution_time_ms": 1250,
  "attack_type": "prompt_injection",
  "metadata": {
    "llm_provider": "openai"
  },
  "error_message": null,
  "created_at": "2025-11-16T12:00:00"
}
```

---

### GET /api/v1/redteam/stats

Get attack statistics and metrics.

**Response:**
```json
{
  "total_attacks": 150,
  "successful_attacks": 112,
  "overall_success_rate": 74.67,
  "technique_stats": {
    "context_manipulation": {
      "total": 50,
      "successful": 38,
      "success_rate": 76.0
    },
    "instruction_override": {
      "total": 45,
      "successful": 34,
      "success_rate": 75.56
    },
    "role_playing": {
      "total": 55,
      "successful": 40,
      "success_rate": 72.73
    }
  }
}
```

---

## Error Responses

### 400 Bad Request

Invalid request parameters.

```json
{
  "detail": "Invalid attack technique specified"
}
```

### 404 Not Found

Resource not found.

```json
{
  "detail": "Pattern not found"
}
```

### 500 Internal Server Error

Server error.

```json
{
  "detail": "Error message here"
}
```

---

## Rate Limiting

Currently, rate limiting is set to 100 requests per minute per user (configurable via environment variables).

---

## Interactive Documentation

Visit `/docs` (Swagger UI) or `/redoc` (ReDoc) for interactive API documentation when running in development mode.

**Swagger UI:** http://localhost:8000/docs
**ReDoc:** http://localhost:8000/redoc

---

## Code Examples

### Python

```python
import httpx
import asyncio

async def generate_attack():
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8000/api/v1/redteam/generate",
            json={
                "technique": "context_manipulation",
                "llm_provider": "openai"
            }
        )
        return response.json()

result = asyncio.run(generate_attack())
print(result["payload"])
```

### JavaScript

```javascript
fetch('http://localhost:8000/api/v1/redteam/generate', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    technique: 'context_manipulation',
    llm_provider: 'openai'
  })
})
.then(response => response.json())
.then(data => console.log(data.payload));
```

### cURL

```bash
curl -X POST "http://localhost:8000/api/v1/redteam/generate" \
  -H "Content-Type: application/json" \
  -d '{
    "technique": "context_manipulation",
    "llm_provider": "openai"
  }'
```

---

## Changelog

### v0.1.0 (2025-11-16)
- Initial API release
- Red team attack generation endpoints
- Attack pattern management
- Attack logging and statistics
