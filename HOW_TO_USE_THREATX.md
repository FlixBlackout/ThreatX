# 🛡️ ThreatX: How to Use for Threat Detection

## Overview
ThreatX is an AI-powered cybersecurity threat detection system that analyzes logs and network data to identify potential security threats using machine learning models trained on real cybersecurity datasets (NSL-KDD).

## 🚀 Quick Start

### 1. Start the ThreatX Server
```bash
cd e:\ThreatX
python test_server.py
```
Server will start on: http://localhost:5000

### 2. Access the Dashboard
Open your browser and go to: http://localhost:5000
- View real-time threat statistics
- Monitor recent threats
- Check system health
- Review user risk profiles

## 📡 API Usage Methods

### Method 1: Direct REST API
**Endpoint:** `POST http://localhost:5000/api/detect-threat`

**Headers:** `Content-Type: application/json`

**Example Request:**
```json
{
    "ip_address": "192.168.1.100",
    "user_id": "alice.smith",
    "event_type": "login",
    "failed_login_attempts": 0,
    "bytes_transferred": 2048,
    "timestamp": "2025-09-09T01:00:00.000Z"
}
```

**Example Response:**
```json
{
    "risk_score": 0.243,
    "risk_level": "NORMAL",
    "threat_category": "Normal",
    "threat_types": [],
    "recommendations": [],
    "confidence": 0.759,
    "dataset_informed": true,
    "timestamp": "2025-09-09T01:00:00.000Z"
}
```

### Method 2: Python Integration
```python
import requests

# Analyze a log entry
log_data = {
    "ip_address": "185.220.101.5",
    "event_type": "brute_force", 
    "failed_login_attempts": 25,
    "user_id": "admin"
}

response = requests.post(
    "http://localhost:5000/api/detect-threat",
    json=log_data
)

result = response.json()
print(f"Risk Level: {result['risk_level']}")
print(f"Threats: {result['threat_types']}")
```

### Method 3: PowerShell
```powershell
$body = '{"ip_address":"1.2.3.4","event_type":"login","failed_login_attempts":5}'
Invoke-RestMethod -Uri "http://localhost:5000/api/detect-threat" -Method POST -Body $body -ContentType "application/json"
```

### Method 4: Curl Command
```bash
curl -X POST http://localhost:5000/api/detect-threat \
     -H "Content-Type: application/json" \
     -d '{"ip_address":"1.2.3.4","event_type":"login","failed_login_attempts":5}'
```

## 🎯 Threat Detection Categories

ThreatX can detect these threat categories based on NSL-KDD dataset:

### 1. DoS (Denial of Service)
- **Indicators:** High connection count, bandwidth spikes, service flooding
- **Examples:** DDoS attacks, resource exhaustion
- **Risk Actions:** Implement rate limiting, activate DDoS protection

### 2. Probe (Network Reconnaissance)
- **Indicators:** Port scanning, service enumeration, network mapping
- **Examples:** nmap scans, vulnerability scanning
- **Risk Actions:** Block scanning IPs, review firewall rules

### 3. R2L (Remote to Local)
- **Indicators:** Multiple failed logins, credential stuffing, brute force
- **Examples:** Password attacks, unauthorized access attempts
- **Risk Actions:** Enable account lockout, require MFA

### 4. U2R (User to Root)
- **Indicators:** Privilege escalation, admin access attempts
- **Examples:** Buffer overflow, rootkit installation
- **Risk Actions:** Audit privileges, monitor admin accounts

### 5. Unknown Threats
- **Indicators:** Anomalous behavior patterns not in training data
- **Examples:** Zero-day attacks, novel attack vectors
- **Risk Actions:** Immediate investigation, forensic analysis

## 📊 Log Data Fields

### Required Fields
- `ip_address`: Source IP address
- `event_type`: Type of event (login, brute_force, ddos, etc.)

### Optional Fields
- `user_id`: Username involved
- `failed_login_attempts`: Number of failed attempts
- `bytes_transferred`: Data volume
- `timestamp`: Event timestamp
- `connection_count`: Number of connections
- `unique_endpoints`: Number of unique endpoints accessed
- `privilege_escalation`: Boolean for privilege escalation attempts
- `geographic_distance`: Distance from normal location
- `rapid_fire_requests`: Boolean for rapid requests
- `malformed_packets`: Boolean for malformed network packets

## 🏢 Real-World Integration Examples

### 1. Web Server Log Analysis
Monitor Apache/Nginx access logs:
```python
# Parse web server log
log_entry = {
    "ip_address": client_ip,
    "event_type": "web_request",
    "bytes_transferred": response_size,
    "failed_login_attempts": login_failures,
    "unique_endpoints": len(unique_urls)
}

# Analyze with ThreatX
threat_analysis = analyze_threat(log_entry)
```

### 2. SIEM Integration
Forward SIEM alerts to ThreatX:
```python
def process_siem_alert(siem_data):
    # Convert SIEM format to ThreatX format
    threatx_data = {
        "ip_address": siem_data["source_ip"],
        "event_type": siem_data["alert_type"],
        "failed_login_attempts": siem_data.get("attempts", 0)
    }
    
    # Get enhanced analysis
    analysis = requests.post(threatx_api, json=threatx_data)
    
    # Enrich SIEM alert with ThreatX intelligence
    enhanced_alert = {**siem_data, **analysis.json()}
    return enhanced_alert
```

### 3. Real-time Monitoring
```python
import time

def monitor_logs_realtime():
    for log_line in tail_log_file():
        parsed_log = parse_log_entry(log_line)
        
        threat_result = analyze_threat(parsed_log)
        
        if threat_result['risk_level'] in ['HIGH', 'MEDIUM']:
            send_alert(threat_result)
            
        time.sleep(0.1)  # Process continuously
```

### 4. Batch Processing
```python
def process_log_batch(log_file):
    high_risk_events = []
    
    with open(log_file) as f:
        for line in f:
            log_data = parse_log_line(line)
            result = analyze_threat(log_data)
            
            if result['risk_level'] in ['HIGH', 'MEDIUM']:
                high_risk_events.append((log_data, result))
    
    generate_security_report(high_risk_events)
```

## 🔧 Advanced Configuration

### Risk Thresholds
The system uses these risk score thresholds:
- **NORMAL:** 0.0 - 0.25
- **LOW:** 0.25 - 0.55  
- **MEDIUM:** 0.55 - 0.75
- **HIGH:** 0.75 - 1.0

### Model Ensemble
ThreatX uses multiple ML models:
- **Isolation Forest:** Anomaly detection (30% weight)
- **Random Forest:** Classification (35% weight)
- **Gradient Boosting:** Classification (35% weight)

## 📈 System Monitoring

### Health Check
```bash
GET http://localhost:5000/health
```

### Threat Statistics
```bash
GET http://localhost:5000/api/threat-statistics
```

### User Risk Profiles
```bash
GET http://localhost:5000/api/user-risk-profile/{user_id}
```

## 🚨 Alerting and Response

### Risk Level Actions

**HIGH Risk (0.75+):**
- Immediate security team alert
- Consider session termination
- Activate incident response
- Forensic evidence collection

**MEDIUM Risk (0.55-0.75):**
- Monitor user activity closely
- Secondary authentication
- Review access patterns
- Document for analysis

**LOW Risk (0.25-0.55):**
- Increased monitoring
- Log for trend analysis
- Review periodically

## 💡 Best Practices

1. **Real-time Analysis:** Process logs as they arrive for immediate threat detection
2. **Batch Processing:** Analyze historical data for trend identification
3. **Threshold Tuning:** Adjust risk thresholds based on your environment
4. **Alert Fatigue:** Focus on HIGH and MEDIUM risks for alerts
5. **False Positive Management:** Review and tune models regularly
6. **Integration:** Combine with existing security tools and SIEM systems
7. **Monitoring:** Regularly check system health and model performance

## 🛠️ Troubleshooting

### Common Issues:
1. **Connection Error:** Ensure ThreatX server is running on port 5000
2. **Low Accuracy:** Check if models are properly trained with dataset
3. **High False Positives:** Adjust risk thresholds or retrain models
4. **Missing Data:** Ensure required fields (ip_address, event_type) are provided

### Debug Commands:
```bash
# Check server status
curl http://localhost:5000/health

# Test API with sample data
python demo_threat_detection.py

# View server logs
# Check console output where test_server.py is running
```

## 📚 Additional Resources

- **Web Dashboard:** http://localhost:5000
- **API Documentation:** Available at the web interface
- **Integration Examples:** See `examples/threatx_integration_examples.py`
- **Demo Script:** Run `demo_threat_detection.py` for testing

---

🛡️ **ThreatX** - AI-Powered Cybersecurity Threat Detection System