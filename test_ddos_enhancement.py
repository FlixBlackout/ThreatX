#!/usr/bin/env python3
"""
Test DDoS Detection Enhancement
"""

import requests
import json
from datetime import datetime

def test_ddos_detection():
    """Test the enhanced DDoS detection"""
    
    api_url = "http://localhost:5000/api/detect-threat"
    
    print("🔍 Testing Enhanced DDoS Detection")
    print("=" * 50)
    
    # Test scenarios with proper DDoS indicators
    ddos_scenarios = [
        {
            "name": "🌊 Massive DDoS Attack (High Volume)",
            "data": {
                "ip_address": "203.0.113.199",
                "event_type": "ddos",
                "bytes_transferred": 800000000,  # 800MB - very high
                "connection_count": 2000,        # 2000 connections
                "request_frequency": 15000,      # 15k requests/sec
                "traffic_burst": True,
                "bandwidth_spike": True,
                "timestamp": datetime.now().isoformat()
            }
        },
        {
            "name": "🔥 Connection Flood Attack", 
            "data": {
                "ip_address": "198.51.100.50",
                "event_type": "flooding",
                "connection_count": 1500,        # 1500 connections
                "request_frequency": 8000,       # 8k requests/sec
                "bytes_transferred": 300000000,  # 300MB
                "timestamp": datetime.now().isoformat()
            }
        },
        {
            "name": "⚡ Request Rate Attack",
            "data": {
                "ip_address": "91.240.118.172",
                "event_type": "dos",
                "request_frequency": 25000,      # 25k requests/sec
                "connection_count": 800,
                "timestamp": datetime.now().isoformat()
            }
        },
        {
            "name": "✅ Normal Traffic (Should be LOW/NORMAL)",
            "data": {
                "ip_address": "192.168.1.100",
                "event_type": "login",
                "bytes_transferred": 2048,       # 2KB normal
                "connection_count": 1,
                "request_frequency": 5,
                "timestamp": datetime.now().isoformat()
            }
        }
    ]
    
    for i, scenario in enumerate(ddos_scenarios, 1):
        print(f"\n{scenario['name']}")
        print("-" * 60)
        
        try:
            response = requests.post(api_url, json=scenario['data'])
            response.raise_for_status()
            result = response.json()
            
            # Display results
            risk_level = result['risk_level']
            risk_score = result['risk_score']
            threat_category = result.get('threat_category', 'Unknown')
            threats = result.get('threat_types', [])
            
            print(f"Risk Level: {risk_level}")
            print(f"Risk Score: {risk_score}")
            print(f"Category: {threat_category}")
            
            if threats:
                print(f"Threats: {', '.join(threats)}")
            
            # Validation for DDoS scenarios
            if i <= 3:  # First 3 are DDoS scenarios
                if risk_level in ['HIGH', 'MEDIUM']:
                    print(f"✅ CORRECT: DDoS properly detected as {risk_level} risk!")
                else:
                    print(f"❌ ISSUE: DDoS should be HIGH/MEDIUM, got {risk_level}")
            else:  # Last one is normal traffic
                if risk_level in ['NORMAL', 'LOW']:
                    print(f"✅ CORRECT: Normal traffic properly classified as {risk_level}")
                else:
                    print(f"❌ ISSUE: Normal traffic should be NORMAL/LOW, got {risk_level}")
            
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    try:
        response = requests.get("http://localhost:5000/health", timeout=5)
        if response.status_code == 200:
            print("✅ ThreatX server is running\n")
            test_ddos_detection()
        else:
            print("❌ ThreatX server is not responding properly")
    except requests.ConnectionError:
        print("❌ Cannot connect to ThreatX server. Please start it with: python test_server.py")