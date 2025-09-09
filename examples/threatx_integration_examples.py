#!/usr/bin/env python3
"""
ThreatX API Usage Examples
Demonstrates how to integrate ThreatX threat detection into existing systems
"""

import requests
import json
from datetime import datetime

# ThreatX API Configuration
THREATX_BASE_URL = "http://localhost:5000"
API_ENDPOINTS = {
    'detect_threat': f"{THREATX_BASE_URL}/api/detect-threat",
    'health_check': f"{THREATX_BASE_URL}/health",
    'statistics': f"{THREATX_BASE_URL}/api/threat-statistics",
    'user_profile': f"{THREATX_BASE_URL}/api/user-risk-profile",
    'suspicious_ips': f"{THREATX_BASE_URL}/api/suspicious-ips"
}

class ThreatXClient:
    """Client for integrating with ThreatX threat detection system"""
    
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({'Content-Type': 'application/json'})
    
    def analyze_log_entry(self, log_data):
        """
        Analyze a single log entry for threats
        
        Args:
            log_data (dict): Log entry data
            
        Returns:
            dict: Threat analysis results
        """
        try:
            response = self.session.post(
                f"{self.base_url}/api/detect-threat",
                json=log_data
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error analyzing log entry: {e}")
            return None
    
    def check_system_health(self):
        """Check ThreatX system health"""
        try:
            response = self.session.get(f"{self.base_url}/health?format=json")
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error checking system health: {e}")
            return None
    
    def get_threat_statistics(self):
        """Get threat detection statistics"""
        try:
            response = self.session.get(f"{self.base_url}/api/threat-statistics?format=json")
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error getting statistics: {e}")
            return None
    
    def get_user_risk_profile(self, user_id):
        """Get risk profile for a specific user"""
        try:
            response = self.session.get(f"{self.base_url}/api/user-risk-profile/{user_id}")
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error getting user profile: {e}")
            return None

# Example Usage Scenarios

def example_1_real_time_log_analysis():
    """Example 1: Real-time log analysis from your application"""
    print("=== Example 1: Real-time Log Analysis ===")
    
    client = ThreatXClient()
    
    # Simulate incoming log data from your application
    incoming_logs = [
        {
            "ip_address": "192.168.1.100",
            "user_id": "alice.smith",
            "event_type": "login",
            "failed_login_attempts": 0,
            "bytes_transferred": 2048,
            "timestamp": datetime.now().isoformat()
        },
        {
            "ip_address": "185.220.101.5",
            "user_id": "unknown",
            "event_type": "brute_force",
            "failed_login_attempts": 15,
            "bytes_transferred": 512,
            "timestamp": datetime.now().isoformat()
        }
    ]
    
    for log_entry in incoming_logs:
        print(f"\nAnalyzing log from {log_entry['ip_address']}...")
        result = client.analyze_log_entry(log_entry)
        
        if result:
            print(f"Risk Level: {result['risk_level']}")
            print(f"Risk Score: {result['risk_score']}")
            print(f"Threat Category: {result.get('threat_category', 'N/A')}")
            print(f"Threats: {', '.join(result['threat_types'])}")
            
            # Take action based on risk level
            if result['risk_level'] in ['HIGH', 'MEDIUM']:
                print("🚨 ALERT: High/Medium risk detected!")
                print("Recommendations:")
                for rec in result['recommendations']:
                    print(f"  - {rec}")

def example_2_batch_log_processing():
    """Example 2: Batch processing of log files"""
    print("\n=== Example 2: Batch Log Processing ===")
    
    client = ThreatXClient()
    
    # Simulate reading from log file
    log_entries = [
        {"ip_address": "203.0.113.199", "event_type": "unknown_attack", "bytes_transferred": 150000000},
        {"ip_address": "91.240.118.172", "event_type": "port_scan", "failed_login_attempts": 0},
        {"ip_address": "104.244.76.187", "event_type": "buffer_overflow", "privilege_escalation": True}
    ]
    
    high_risk_events = []
    
    for i, log_entry in enumerate(log_entries, 1):
        print(f"\nProcessing log entry {i}/{len(log_entries)}...")
        result = client.analyze_log_entry(log_entry)
        
        if result and result['risk_level'] in ['HIGH', 'MEDIUM']:
            high_risk_events.append((log_entry, result))
    
    print(f"\n📊 Summary: {len(high_risk_events)} high-risk events detected")
    for log_entry, result in high_risk_events:
        print(f"  - {log_entry['ip_address']}: {result['risk_level']} ({result.get('threat_category', 'Unknown')})")

def example_3_security_monitoring():
    """Example 3: Security monitoring dashboard integration"""
    print("\n=== Example 3: Security Monitoring Dashboard ===")
    
    client = ThreatXClient()
    
    # Check system health
    health = client.check_system_health()
    if health:
        print(f"ThreatX Status: {health['status']}")
        print(f"Dataset Status: {health.get('dataset_status', 'Unknown')}")
        print(f"Models Trained: {health.get('models_trained', False)}")
    
    # Get threat statistics
    stats = client.get_threat_statistics()
    if stats:
        print(f"\nThreat Statistics (Last 24h):")
        print(f"  Total Threats: {stats['total_threats']}")
        print(f"  High Risk: {stats['threat_counts']['HIGH']}")
        print(f"  Medium Risk: {stats['threat_counts']['MEDIUM']}")
        print(f"  Dataset Informed: {stats.get('dataset_informed', False)}")

def example_4_user_risk_monitoring():
    """Example 4: User risk profile monitoring"""
    print("\n=== Example 4: User Risk Monitoring ===")
    
    client = ThreatXClient()
    
    # Monitor specific users
    users_to_monitor = ["alice.johnson", "charlie.brown", "suspicious_user"]
    
    for user_id in users_to_monitor:
        profile = client.get_user_risk_profile(user_id)
        if profile and 'current_risk_score' in profile:
            risk_score = profile['current_risk_score']
            total_alerts = profile.get('total_alerts', 0)
            
            print(f"\nUser: {user_id}")
            print(f"  Risk Score: {risk_score:.3f}")
            print(f"  Total Alerts: {total_alerts}")
            
            if risk_score > 0.6:
                print(f"  ⚠️  HIGH RISK USER - Requires attention!")

def example_5_integration_with_siem():
    """Example 5: Integration with SIEM systems"""
    print("\n=== Example 5: SIEM Integration ===")
    
    client = ThreatXClient()
    
    # Simulate SIEM log forwarding
    siem_log = {
        "source_ip": "198.51.100.30",
        "destination_ip": "10.0.0.100", 
        "user": "admin_user",
        "action": "login_attempt",
        "result": "failed",
        "attempts": 8,
        "data_size": 1024,
        "timestamp": datetime.now().isoformat()
    }
    
    # Convert SIEM format to ThreatX format
    threatx_format = {
        "ip_address": siem_log["source_ip"],
        "user_id": siem_log["user"],
        "event_type": "failed_login" if siem_log["result"] == "failed" else "login",
        "failed_login_attempts": siem_log["attempts"],
        "bytes_transferred": siem_log["data_size"],
        "timestamp": siem_log["timestamp"]
    }
    
    print("SIEM Log received:")
    print(json.dumps(siem_log, indent=2))
    
    result = client.analyze_log_entry(threatx_format)
    if result:
        print(f"\nThreatX Analysis:")
        print(f"Risk Assessment: {result['risk_level']} (Score: {result['risk_score']})")
        print(f"Threat Category: {result.get('threat_category', 'Unknown')}")
        
        # Send back to SIEM with enriched data
        enriched_log = {
            **siem_log,
            "threatx_risk_level": result['risk_level'],
            "threatx_risk_score": result['risk_score'],
            "threatx_threats": result['threat_types'],
            "threatx_recommendations": result['recommendations']
        }
        
        print(f"\nEnriched log for SIEM:")
        print(json.dumps(enriched_log, indent=2))

if __name__ == "__main__":
    print("🛡️ ThreatX Integration Examples")
    print("=" * 50)
    
    # Run examples
    try:
        example_1_real_time_log_analysis()
        example_2_batch_log_processing()
        example_3_security_monitoring()
        example_4_user_risk_monitoring()
        example_5_integration_with_siem()
        
    except Exception as e:
        print(f"Error running examples: {e}")
        print("Make sure ThreatX test server is running on http://localhost:5000")
        print("Start it with: python test_server.py")