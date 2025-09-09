# ThreatX API Reference

This document provides comprehensive API documentation for the ThreatX AI-Powered Cybersecurity Threat Detector.

## Base URLs

- **AI Engine API**: `http://localhost:5000`
- **Dashboard API**: `http://localhost:8080`

## Authentication

Currently, the APIs use basic authentication. In production, implement proper JWT or OAuth2.

## AI Engine API

### Health Check

Check the health status of the AI Engine.

**Endpoint**: `GET /health`

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T14:30:00Z",
  "version": "1.0.0"
}
```

### Threat Detection

Analyze log data for potential threats.

**Endpoint**: `POST /api/detect-threat`

**Request Body**:
```json
{
  "timestamp": "2024-01-15T14:30:00Z",
  "ip_address": "192.168.1.100",
  "user_id": "alice.johnson",
  "event_type": "login",
  "failed_login_attempts": 0,
  "total_login_attempts": 1,
  "bytes_transferred": 1024,
  "session_count": 1,
  "unique_endpoints": 1,
  "geographic_anomaly": 0,
  "login_attempts_1h": 1,
  "login_attempts_24h": 3
}
```

**Response**:
```json
{
  "risk_score": 0.15,
  "risk_level": "NORMAL",
  "model_scores": {
    "isolation_forest": 0.1,
    "random_forest": 0.2,
    "autoencoder": 0.15
  },
  "threat_types": [],
  "recommendations": ["Continue monitoring"],
  "confidence": 0.85,
  "timestamp": "2024-01-15T14:30:05Z"
}
```

**Risk Levels**:
- `NORMAL`: Risk score 0.0 - 0.3
- `LOW`: Risk score 0.3 - 0.6
- `MEDIUM`: Risk score 0.6 - 0.8
- `HIGH`: Risk score 0.8 - 1.0

### User Risk Profile

Get risk profile for a specific user.

**Endpoint**: `GET /api/user-risk-profile/{user_id}`

**Response**:
```json
{
  "user_id": "alice.johnson",
  "current_risk_score": 0.15,
  "total_alerts": 2,
  "high_risk_alerts": 0,
  "medium_risk_alerts": 1,
  "last_suspicious_activity": "2024-01-10T09:15:00Z",
  "trust_score": 0.85,
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-15T14:30:00Z"
}
```

### Threat Statistics

Get aggregated threat statistics.

**Endpoint**: `GET /api/threat-statistics`

**Query Parameters**:
- `range`: Time range (`1h`, `24h`, `7d`, `30d`)

**Response**:
```json
{
  "time_range": "24h",
  "total_threats": 45,
  "threat_counts": {
    "HIGH": 5,
    "MEDIUM": 15,
    "LOW": 20,
    "NORMAL": 5
  },
  "timeline_data": {
    "2024-01-15T14:00:00Z": {
      "HIGH": 1,
      "MEDIUM": 3,
      "LOW": 5
    }
  },
  "top_suspicious_ips": [
    {
      "ip_address": "198.51.100.30",
      "threat_count": 15,
      "last_threat_time": "2024-01-15T14:25:00Z"
    }
  ],
  "top_threat_types": [
    {
      "threat_type": "Brute Force Attack",
      "count": 12
    },
    {
      "threat_type": "Failed Login",
      "count": 8
    }
  ],
  "generated_at": "2024-01-15T14:30:00Z"
}
```

### Suspicious IPs

Get list of suspicious IP addresses.

**Endpoint**: `GET /api/suspicious-ips`

**Query Parameters**:
- `limit`: Maximum number of results (default: 100)

**Response**:
```json
[
  {
    "ip_address": "198.51.100.30",
    "reputation_score": 0.2,
    "threat_count": 15,
    "last_threat_time": "2024-01-15T14:25:00Z",
    "country_code": "US",
    "is_blocked": false,
    "attack_types": ["Brute Force", "Credential Stuffing"]
  }
]
```

### Model Retraining

Trigger retraining of ML models.

**Endpoint**: `POST /api/retrain-models`

**Response**:
```json
{
  "status": "success",
  "message": "Model retraining initiated",
  "timestamp": "2024-01-15T14:30:00Z"
}
```

### Batch Analysis

Submit multiple log entries for batch processing.

**Endpoint**: `POST /api/analyze-batch`

**Request Body**:
```json
{
  "logs": [
    {
      "timestamp": "2024-01-15T14:30:00Z",
      "ip_address": "192.168.1.100",
      "user_id": "alice.johnson",
      "event_type": "login"
    },
    {
      "timestamp": "2024-01-15T14:31:00Z",
      "ip_address": "198.51.100.30",
      "user_id": "attacker",
      "event_type": "failed_login"
    }
  ]
}
```

**Response**:
```json
{
  "status": "success",
  "processed_count": 2,
  "results": [
    {
      "log_index": 0,
      "risk_score": 0.15,
      "risk_level": "NORMAL"
    },
    {
      "log_index": 1,
      "risk_score": 0.75,
      "risk_level": "MEDIUM"
    }
  ]
}
```

## Dashboard API

### Health Check

Check dashboard health status.

**Endpoint**: `GET /health`

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T14:30:00Z",
  "aiEngine": "online"
}
```

### Test Detection

Test threat detection with sample data.

**Endpoint**: `POST /test-detection`

**Request Body**:
```json
{
  "ip_address": "192.168.1.100",
  "user_id": "test_user",
  "event_type": "login",
  "failed_login_attempts": 0
}
```

**Response**: Same as AI Engine threat detection response.

### Get User Profile

Get user risk profile via dashboard.

**Endpoint**: `GET /api/user-profile/{user_id}`

**Response**: Same as AI Engine user risk profile response.

### Get Threat Statistics

Get threat statistics via dashboard.

**Endpoint**: `GET /api/threat-stats`

**Query Parameters**:
- `timeRange`: Time range (`1h`, `24h`, `7d`, `30d`)

**Response**: Same as AI Engine threat statistics response.

## Error Responses

All APIs return consistent error responses:

### 400 Bad Request
```json
{
  "error": "Invalid request data",
  "message": "Missing required field: ip_address",
  "timestamp": "2024-01-15T14:30:00Z"
}
```

### 404 Not Found
```json
{
  "error": "Resource not found",
  "message": "User profile not found for user_id: nonexistent_user",
  "timestamp": "2024-01-15T14:30:00Z"
}
```

### 500 Internal Server Error
```json
{
  "error": "Internal server error",
  "message": "Database connection failed",
  "timestamp": "2024-01-15T14:30:00Z"
}
```

## Rate Limiting

APIs implement rate limiting to prevent abuse:

- **Threat Detection**: 30 requests per minute per IP
- **User Profile**: 60 requests per minute per IP
- **Statistics**: 10 requests per minute per IP

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 30
X-RateLimit-Remaining: 25
X-RateLimit-Reset: 1642262400
```

## SDK Examples

### Python SDK Example

```python
import requests
import json

class ThreatXClient:
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
    
    def detect_threat(self, log_data):
        response = requests.post(
            f"{self.base_url}/api/detect-threat",
            json=log_data,
            headers={"Content-Type": "application/json"}
        )
        return response.json()
    
    def get_user_profile(self, user_id):
        response = requests.get(
            f"{self.base_url}/api/user-risk-profile/{user_id}"
        )
        return response.json()

# Usage example
client = ThreatXClient()

log_entry = {
    "timestamp": "2024-01-15T14:30:00Z",
    "ip_address": "192.168.1.100",
    "user_id": "alice.johnson",
    "event_type": "login",
    "failed_login_attempts": 0
}

result = client.detect_threat(log_entry)
print(f"Risk Level: {result['risk_level']}")
print(f"Risk Score: {result['risk_score']}")
```

### JavaScript SDK Example

```javascript
class ThreatXClient {
    constructor(baseUrl = 'http://localhost:5000') {
        this.baseUrl = baseUrl;
    }
    
    async detectThreat(logData) {
        const response = await fetch(`${this.baseUrl}/api/detect-threat`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(logData)
        });
        
        return await response.json();
    }
    
    async getUserProfile(userId) {
        const response = await fetch(`${this.baseUrl}/api/user-risk-profile/${userId}`);
        return await response.json();
    }
}

// Usage example
const client = new ThreatXClient();

const logEntry = {
    timestamp: '2024-01-15T14:30:00Z',
    ip_address: '192.168.1.100',
    user_id: 'alice.johnson',
    event_type: 'login',
    failed_login_attempts: 0
};

client.detectThreat(logEntry)
    .then(result => {
        console.log(`Risk Level: ${result.risk_level}`);
        console.log(`Risk Score: ${result.risk_score}`);
    })
    .catch(error => {
        console.error('Error:', error);
    });
```

### Java SDK Example

```java
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ThreatXClient {
    private final String baseUrl;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    
    public ThreatXClient(String baseUrl) {
        this.baseUrl = baseUrl;
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
    }
    
    public ThreatDetectionResult detectThreat(LogEntry logEntry) throws Exception {
        String json = objectMapper.writeValueAsString(logEntry);
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/api/detect-threat"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(json))
            .build();
        
        HttpResponse<String> response = httpClient.send(request, 
            HttpResponse.BodyHandlers.ofString());
        
        return objectMapper.readValue(response.body(), ThreatDetectionResult.class);
    }
}
```

## Webhooks

ThreatX supports webhooks for real-time threat notifications.

### Configure Webhook

**Endpoint**: `POST /api/webhooks`

**Request Body**:
```json
{
  "url": "https://your-endpoint.com/webhook",
  "events": ["HIGH_RISK_THREAT", "SUSPICIOUS_IP", "MODEL_RETRAINED"],
  "secret": "your-webhook-secret"
}
```

### Webhook Payload

```json
{
  "event": "HIGH_RISK_THREAT",
  "timestamp": "2024-01-15T14:30:00Z",
  "data": {
    "risk_score": 0.95,
    "risk_level": "HIGH",
    "ip_address": "198.51.100.30",
    "user_id": "suspicious_user",
    "threat_types": ["Brute Force Attack", "Malicious IP"],
    "recommendations": ["Block IP immediately", "Alert security team"]
  },
  "signature": "sha256=hash_of_payload_with_secret"
}
```

## OpenAPI Specification

Download the complete OpenAPI specification:
- [AI Engine API](../api/ai-engine-openapi.yaml)
- [Dashboard API](../api/dashboard-openapi.yaml)

## Support

For API support and questions:
- Documentation: [Installation Guide](installation.md)
- Issues: GitHub Issues
- Email: support@threatx.com