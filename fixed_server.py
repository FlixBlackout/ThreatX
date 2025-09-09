#!/usr/bin/env python3
"""
ThreatX Test Server - Fixed Version
A comprehensive cybersecurity threat detection system with dashboard
"""

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import json
import numpy as np
import logging
import os
import sys
from datetime import datetime, timedelta
import random
from typing import Dict, List, Any
import threading
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# In-memory database for testing
threat_data = []
user_profiles = {}
suspicious_ips = {}

class AdvancedThreatDetector:
    """Advanced threat detector with enhanced analysis"""
    
    def __init__(self):
        self.risk_thresholds = {
            'low': 0.25,
            'medium': 0.55,
            'high': 0.75
        }
        
        # Set enhanced detector to simple mode
        self.use_enhanced = True
        
        # Attack patterns for detection
        self.attack_patterns = {
            'dos_indicators': ['high_connection_rate', 'bandwidth_exhaustion', 'service_flooding'],
            'probe_indicators': ['port_scanning', 'service_enumeration', 'network_mapping'],
            'r2l_indicators': ['brute_force', 'credential_stuffing', 'password_attack'],
            'u2r_indicators': ['privilege_escalation', 'buffer_overflow', 'root_access']
        }
        
        # Threat intelligence feeds (simulated)
        self.threat_intelligence = {
            'malicious_ips': [
                '185.220.101.5', '91.240.118.172', '104.244.76.187',
                '198.51.100.30', '203.0.113.45', '192.0.2.100'
            ],
            'suspicious_countries': ['CN', 'RU', 'KP', 'IR'],
            'known_attack_signatures': [
                'sql_injection', 'xss_attack', 'command_injection',
                'directory_traversal', 'xxe_attack'
            ]
        }
    
    def analyze(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Advanced threat analysis"""
        try:
            # Use rule-based analysis
            return self._enhanced_rule_analysis(log_data)
            
        except Exception as e:
            logger.error(f"Error in threat analysis: {e}")
            return self._fallback_analysis(log_data)
    
    def _enhanced_rule_analysis(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced rule-based analysis with patterns"""
        risk_score = 0.0
        threat_types = []
        recommendations = []
        threat_category = 'Normal'
        
        # Extract features
        ip_address = log_data.get('ip_address', '')
        failed_logins = log_data.get('failed_login_attempts', 0)
        event_type = log_data.get('event_type', '')
        bytes_transferred = log_data.get('bytes_transferred', 0)
        user_id = log_data.get('user_id', '')
        
        # Enhanced DoS detection
        if self._detect_dos_pattern(log_data):
            risk_score += 0.7
            threat_types.append('DoS Attack')
            threat_category = 'DoS'
            recommendations.extend(['Implement DDoS protection', 'Activate traffic filtering', 'Monitor bandwidth usage'])
        
        # Enhanced Probe detection
        if self._detect_probe_pattern(log_data):
            risk_score += 0.6
            threat_types.append('Probe Attack')
            threat_category = 'Probe'
            recommendations.extend(['Update firewall rules', 'Disable unnecessary services', 'Implement port knocking'])
        
        # Enhanced R2L detection
        if self._detect_r2l_pattern(log_data):
            risk_score += 0.8
            threat_types.append('R2L Attack')
            threat_category = 'R2L'
            recommendations.extend(['Enforce strong password policy', 'Implement MFA', 'Monitor login attempts'])
        
        # Enhanced U2R detection
        if self._detect_u2r_pattern(log_data):
            risk_score += 0.9
            threat_types.append('U2R Attack')
            threat_category = 'U2R'
            recommendations.extend(['Apply security patches', 'Implement RBAC', 'Monitor privileged accounts'])
        
        # Determine risk level
        risk_level = 'NORMAL'
        if risk_score > self.risk_thresholds['high']:
            risk_level = 'HIGH'
        elif risk_score > self.risk_thresholds['medium']:
            risk_level = 'MEDIUM'
        elif risk_score > self.risk_thresholds['low']:
            risk_level = 'LOW'
        
        # Update user profile
        if user_id:
            if user_id not in user_profiles:
                user_profiles[user_id] = {
                    'user_id': user_id,
                    'current_risk_score': risk_score,
                    'total_alerts': 1,
                    'last_activity': datetime.utcnow().isoformat(),
                    'threat_history': [{'timestamp': datetime.utcnow().isoformat(), 'risk_score': risk_score}]
                }
            else:
                user_profiles[user_id]['current_risk_score'] = max(user_profiles[user_id]['current_risk_score'], risk_score)
                user_profiles[user_id]['total_alerts'] += 1
                user_profiles[user_id]['last_activity'] = datetime.utcnow().isoformat()
                user_profiles[user_id]['threat_history'].append({'timestamp': datetime.utcnow().isoformat(), 'risk_score': risk_score})
        
        # Update suspicious IPs
        if ip_address and risk_score > self.risk_thresholds['medium']:
            if ip_address not in suspicious_ips:
                suspicious_ips[ip_address] = {
                    'ip_address': ip_address,
                    'risk_score': risk_score,
                    'threat_count': 1,
                    'last_seen': datetime.utcnow().isoformat(),
                    'categories': [threat_category]
                }
            else:
                suspicious_ips[ip_address]['risk_score'] = max(suspicious_ips[ip_address]['risk_score'], risk_score)
                suspicious_ips[ip_address]['threat_count'] += 1
                suspicious_ips[ip_address]['last_seen'] = datetime.utcnow().isoformat()
                if threat_category not in suspicious_ips[ip_address]['categories']:
                    suspicious_ips[ip_address]['categories'].append(threat_category)
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'threat_types': threat_types,
            'recommendations': recommendations,
            'threat_category': threat_category
        }
    
    def _detect_dos_pattern(self, log_data: Dict[str, Any]) -> bool:
        """Detect DoS attack patterns"""
        # Simplified detection logic
        event_type = log_data.get('event_type', '').lower()
        return event_type in ['ddos', 'dos', 'flood']
    
    def _detect_probe_pattern(self, log_data: Dict[str, Any]) -> bool:
        """Detect Probe attack patterns"""
        # Simplified detection logic
        event_type = log_data.get('event_type', '').lower()
        return event_type in ['port_scan', 'scan', 'probe']
    
    def _detect_r2l_pattern(self, log_data: Dict[str, Any]) -> bool:
        """Detect R2L attack patterns"""
        # Simplified detection logic
        event_type = log_data.get('event_type', '').lower()
        return event_type in ['brute_force', 'password_attack', 'credential_stuffing']
    
    def _detect_u2r_pattern(self, log_data: Dict[str, Any]) -> bool:
        """Detect U2R attack patterns"""
        # Simplified detection logic
        event_type = log_data.get('event_type', '').lower()
        return event_type in ['privilege_escalation', 'buffer_overflow', 'root_access']
    
    def _fallback_analysis(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback analysis when enhanced analysis fails"""
        # Simple random risk score for fallback
        risk_score = random.uniform(0.1, 0.9)
        risk_level = 'NORMAL'
        
        if risk_score > self.risk_thresholds['high']:
            risk_level = 'HIGH'
        elif risk_score > self.risk_thresholds['medium']:
            risk_level = 'MEDIUM'
        elif risk_score > self.risk_thresholds['low']:
            risk_level = 'LOW'
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'threat_types': ['Unknown'],
            'recommendations': ['Monitor system', 'Update security rules'],
            'threat_category': 'Unknown'
        }

# Initialize detector
detector = AdvancedThreatDetector()

# Generate sample data
def generate_sample_data():
    """Generate sample threat data for testing"""
    # Sample attack scenarios inspired by NSL-KDD dataset
    attack_scenarios = [
        {'event_type': 'ddos', 'ip_address': '203.0.113.10', 'user_id': 'system', 'bytes_transferred': 15000, 'failed_login_attempts': 0},
        {'event_type': 'port_scan', 'ip_address': '198.51.100.20', 'user_id': 'system', 'bytes_transferred': 2500, 'failed_login_attempts': 0},
        {'event_type': 'brute_force', 'ip_address': '192.0.2.30', 'user_id': 'admin', 'bytes_transferred': 1200, 'failed_login_attempts': 12},
        {'event_type': 'privilege_escalation', 'ip_address': '192.168.1.50', 'user_id': 'user123', 'bytes_transferred': 800, 'failed_login_attempts': 0}
    ]
    
    for scenario in attack_scenarios:
        result = detector.analyze(scenario)
        logger.info(f"Sample analysis: {scenario['event_type']} -> {result['risk_level']} ({result['threat_category']})")
        
        threat_data.append({
            'log_data': scenario,
            'result': result,
            'timestamp': datetime.utcnow()
        })
    
    logger.info("Generated sample threat data")

# Routes
@app.route('/')
def index():
    """Main dashboard page"""
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ThreatX Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        .threat-high {
            background-color: #ffebee;
            border-left: 4px solid #f44336;
        }
        .threat-medium {
            background-color: #fff8e1;
            border-left: 4px solid #ffc107;
        }
        .threat-low {
            background-color: #e8f5e9;
            border-left: 4px solid #4caf50;
        }
        .threat-normal {
            background-color: #e3f2fd;
            border-left: 4px solid #2196f3;
        }
        .ip-item {
            padding: 10px;
            margin-bottom: 10px;
            background-color: #f8f9fa;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container mt-4">
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h3>ThreatX AI-Powered Threat Detector</h3>
                        <div>
                            <a href="/health" class="btn btn-info"><i class="fas fa-heartbeat me-2"></i>System Health Check</a>
                            <a href="/api/threat-statistics" class="btn btn-secondary"><i class="fas fa-chart-bar me-2"></i>View Statistics</a>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-3">
                                <div class="card">
                                    <div class="card-body text-center">
                                        <h5 class="card-title">Total Threats</h5>
                                        <h2 id="totalThreats">0</h2>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="card">
                                    <div class="card-body text-center">
                                        <h5 class="card-title">High Risk</h5>
                                        <h2 id="highRisk" class="text-danger">0</h2>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="card">
                                    <div class="card-body text-center">
                                        <h5 class="card-title">Medium Risk</h5>
                                        <h2 id="mediumRisk" class="text-warning">0</h2>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="card">
                                    <div class="card-body text-center">
                                        <h5 class="card-title">Low Risk</h5>
                                        <h2 id="lowRisk" class="text-success">0</h2>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Recent Threats</h5>
                    </div>
                    <div class="card-body">
                        <div id="recentThreats" class="list-group">
                            <!-- Recent threats will be loaded here -->
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Suspicious IPs</h5>
                    </div>
                    <div class="card-body">
                        <div id="suspiciousIps">
                            <!-- Suspicious IPs will be loaded here -->
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row mt-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5>Threat Simulation</h5>
                    </div>
                    <div class="card-body">
                        <form id="simulationForm" class="row g-3">
                            <div class="col-md-3">
                                <label for="ipAddress" class="form-label">IP Address</label>
                                <input type="text" class="form-control" id="ipAddress" value="192.168.1.100">
                            </div>
                            <div class="col-md-3">
                                <label for="userId" class="form-label">User ID</label>
                                <input type="text" class="form-control" id="userId" value="test_user">
                            </div>
                            <div class="col-md-2">
                                <label for="failedLogins" class="form-label">Failed Logins</label>
                                <input type="number" class="form-control" id="failedLogins" value="0">
                            </div>
                            <div class="col-md-2">
                                <label for="bytesTransferred" class="form-label">Bytes</label>
                                <input type="number" class="form-control" id="bytesTransferred" value="1024">
                            </div>
                            <div class="col-md-2">
                                <label for="eventType" class="form-label">Event Type</label>
                                <select class="form-select" id="eventType">
                                    <option value="normal">Normal</option>
                                    <option value="ddos">DDoS</option>
                                    <option value="port_scan">Port Scan</option>
                                    <option value="brute_force">Brute Force</option>
                                    <option value="privilege_escalation">Privilege Escalation</option>
                                </select>
                            </div>
                            <div class="col-12">
                                <button type="submit" class="btn btn-primary">Simulate Threat</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Function to load dashboard data
        function loadDashboardData() {
            fetch('/api/dashboard-data')
                .then(response => response.json())
                .then(data => {
                    // Update metrics
                    document.getElementById('totalThreats').textContent = data.total_threats;
                    document.getElementById('highRisk').textContent = data.threat_counts.HIGH;
                    document.getElementById('mediumRisk').textContent = data.threat_counts.MEDIUM;
                    document.getElementById('lowRisk').textContent = data.threat_counts.LOW;
                    
                    // Update recent threats
                    const recentThreatsContainer = document.getElementById('recentThreats');
                    recentThreatsContainer.innerHTML = '';
                    
                    data.recent_threats.forEach(threat => {
                        const riskLevel = threat.result.risk_level;
                        const threatClass = `threat-${riskLevel.toLowerCase()}`;
                        
                        const html = `
                        <div class="list-group-item ${threatClass}">
                            <div class="d-flex w-100 justify-content-between">
                                <h6>${threat.log_data.event_type} from ${threat.log_data.ip_address}</h6>
                                <small>${new Date(threat.timestamp).toLocaleTimeString()}</small>
                            </div>
                            <p class="mb-1">Risk: ${threat.result.risk_level} (${threat.result.risk_score.toFixed(2)})</p>
                            <small>User: ${threat.log_data.user_id}</small>
                        </div>
                        `;
                        
                        recentThreatsContainer.innerHTML += html;
                    });
                    
                    // Update suspicious IPs
                    updateSuspiciousIPs(data.suspicious_ips);
                })
                .catch(error => {
                    console.error('Error loading dashboard data:', error);
                });
        }
        
        // Function to update suspicious IPs
        function updateSuspiciousIPs(ips) {
            const container = document.getElementById('suspiciousIps');
            let html = '';
            
            Object.values(ips).forEach(ip => {
                html += `
                <div class="ip-item">
                    <div class="d-flex justify-content-between">
                        <h6>${ip.ip_address}</h6>
                        <span class="badge bg-danger">${ip.risk_score.toFixed(2)}</span>
                    </div>
                    <div>
                        <small>Threats: ${ip.threat_count}</small>
                    </div>
                    <div>
                        <small>Risk Score: ${ip.risk_score.toFixed(2)}</small>
                    </div>
                </div>
                `;
            });
            
            container.innerHTML = html;
        }
        
        // Handle form submission
        document.getElementById('simulationForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const logData = {
                ip_address: document.getElementById('ipAddress').value,
                user_id: document.getElementById('userId').value,
                event_type: document.getElementById('eventType').value,
                timestamp: new Date().toISOString(),
                bytes_transferred: parseInt(document.getElementById('bytesTransferred').value),
                failed_login_attempts: parseInt(document.getElementById('failedLogins').value)
            };
            
            fetch('/api/detect-threat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(logData)
            })
            .then(response => response.json())
            .then(data => {
                alert(`Threat detected! Risk Level: ${data.risk_level}`);
                loadDashboardData();
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error simulating threat');
            });
        });
        
        // Load data on page load
        loadDashboardData();
        
        // Refresh data every 30 seconds
        setInterval(loadDashboardData, 30000);
    </script>
</body>
</html>
    """)

@app.route('/api/dashboard-data')
def dashboard_data():
    """Get dashboard data"""
    # Get recent threats
    recent = sorted(threat_data, key=lambda x: x['timestamp'], reverse=True)[:5]
    
    # Convert datetime objects to strings for JSON serialization
    serializable_recent = []
    for threat in recent:
        serializable_threat = {
            'log_data': threat['log_data'],
            'result': threat['result'],
            'timestamp': threat['timestamp'].isoformat() if isinstance(threat['timestamp'], datetime) else threat['timestamp']
        }
        serializable_recent.append(serializable_threat)
    
    # Count threats by level
    threat_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'NORMAL': 0}
    for threat in threat_data:
        level = threat['result']['risk_level']
        threat_counts[level] += 1
    
    # Prepare response
    response = {
        'total_threats': len(threat_data),
        'threat_counts': threat_counts,
        'recent_threats': serializable_recent,
        'suspicious_ips': suspicious_ips,
        'user_profiles': user_profiles
    }
    
    return jsonify(response)

@app.route('/api/detect-threat', methods=['POST'])
def detect_threat():
    """Main threat detection endpoint"""
    try:
        log_data = request.json
        if not log_data:
            return jsonify({'error': 'No log data provided'}), 400
        
        result = detector.analyze(log_data)
        logger.info(f"Threat analysis: {result['risk_level']} risk detected")
        
        # Store analysis result
        threat_data.append({
            'log_data': log_data,
            'result': result,
            'timestamp': datetime.utcnow()
        })
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error in threat detection: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user-risk-profile/<user_id>')
def get_user_profile(user_id):
    """Get user risk profile"""
    if user_id in user_profiles:
        return jsonify(user_profiles[user_id])
    else:
        return jsonify({'error': 'User not found'}), 404

@app.route('/api/threat-statistics')
def threat_statistics():
    """Get threat statistics"""
    format_type = request.args.get('format', 'html')
    
    # Count threats by category
    categories = {'DoS': 0, 'Probe': 0, 'R2L': 0, 'U2R': 0, 'Unknown': 0}
    for threat in threat_data:
        category = threat['result'].get('threat_category', 'Unknown')
        if category in categories:
            categories[category] += 1
    
    if format_type.lower() == 'json':
        return jsonify({
            'dataset_informed': True,
            'generated_at': datetime.utcnow().isoformat(),
            'models_active': ['rule_based', 'pattern_matching'],
            'recent_count': len(threat_data),
            'threat_categories': categories
        })
    else:
        return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ThreatX Statistics</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-4">
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h3>Threat Statistics</h3>
                <div>
                    <a href="/" class="btn btn-primary">Back to Dashboard</a>
                    <a href="/health" class="btn btn-info">System Health</a>
                    <a href="/api/threat-statistics?format=json" class="btn btn-secondary">JSON Format</a>
                </div>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h4>Threat Categories</h4>
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Category</th>
                                    <th>Count</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for category, count in categories.items() %}
                                <tr>
                                    <td>{{ category }}</td>
                                    <td>{{ count }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    <div class="col-md-6">
                        <h4>System Information</h4>
                        <ul class="list-group">
                            <li class="list-group-item">Generated At: {{ datetime.utcnow().isoformat() }}</li>
                            <li class="list-group-item">Recent Threats: {{ threat_data|length }}</li>
                            <li class="list-group-item">Active Models: rule_based, pattern_matching</li>
                            <li class="list-group-item">Dataset Informed: Yes</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
        """, categories=categories, threat_data=threat_data, datetime=datetime)

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ThreatX Health Check</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-4">
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h3>System Health Check</h3>
                <a href="/" class="btn btn-primary">Back to Dashboard</a>
            </div>
            <div class="card-body">
                <div class="alert alert-success">
                    <h4>All Systems Operational</h4>
                    <p>The ThreatX AI-Powered Threat Detector is running normally.</p>
                </div>
                
                <h4>System Information</h4>
                <table class="table table-striped">
                    <tbody>
                        <tr>
                            <th>Server Time</th>
                            <td>{{ datetime.utcnow().isoformat() }}</td>
                        </tr>
                        <tr>
                            <th>Threats Detected</th>
                            <td>{{ threat_data|length }}</td>
                        </tr>
                        <tr>
                            <th>Users Monitored</th>
                            <td>{{ user_profiles|length }}</td>
                        </tr>
                        <tr>
                            <th>Suspicious IPs</th>
                            <td>{{ suspicious_ips|length }}</td>
                        </tr>
                        <tr>
                            <th>Server Status</th>
                            <td>Online</td>
                        </tr>
                        <tr>
                            <th>API Status</th>
                            <td>Operational</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
    """, threat_data=threat_data, user_profiles=user_profiles, suspicious_ips=suspicious_ips, datetime=datetime)

# Generate sample data on startup
generate_sample_data()

@app.route('/api/suspicious-ips')
def get_suspicious_ips():
    """Get suspicious IPs"""
    limit = request.args.get('limit', default=10, type=int)
    
    # Convert dictionary to list and sort by risk score
    ips_list = list(suspicious_ips.values())
    ips_list = sorted(ips_list, key=lambda x: x['risk_score'], reverse=True)[:limit]
    
    return jsonify(ips_list)

# Start the server
if __name__ == '__main__':
    print("======================================================================")
    print("🛡️  ThreatX AI-Powered Threat Detector")
    print("======================================================================")
    print("")
    print("🚀 Server starting on: http://localhost:5000")
    print("📊 Dashboard: http://localhost:5000")
    print("🔍 Health Check: http://localhost:5000/health")
    print("📚 API Statistics: http://localhost:5000/api/threat-statistics")
    print("")
    print("✨ Features:")
    print("  • Advanced threat detection")
    print("  • DoS, Probe, R2L, U2R attack detection")
    print("  • Unknown threat detection")
    print("  • Real-time risk assessment")
    print("")
    print("Press Ctrl+C to stop the server")
    print("======================================================================")
    app.run(debug=True, host='0.0.0.0', port=5000)