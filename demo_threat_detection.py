#!/usr/bin/env python3
"""
ThreatX Demo: How to Use the System for Threat Detection
"""

import requests
import json
from datetime import datetime

def test_threat_detection():
    """Demonstrate real threat detection scenarios"""
    
    api_url = "http://localhost:5000/api/detect-threat"
    
    print("🛡️ ThreatX Threat Detection Demo")
    print("=" * 50)
    
    # Test scenarios with varying risk levels
    test_scenarios = [
        {
            "name": "Normal User Login",
            "data": {
                "ip_address": "192.168.1.100",
                "user_id": "alice.smith",
                "event_type": "login",
                "failed_login_attempts": 0,
                "bytes_transferred": 2048,
                "timestamp": datetime.now().isoformat()
            }
        },
        {
            "name": "Brute Force Attack",
            "data": {
                "ip_address": "185.220.101.5", # Known malicious IP
                "user_id": "admin",
                "event_type": "brute_force",
                "failed_login_attempts": 25,
                "bytes_transferred": 512,
                "timestamp": datetime.now().isoformat()
            }
        },
        {
            "name": "DDoS Attack Pattern",
            "data": {
                "ip_address": "203.0.113.199",
                "event_type": "ddos",
                "bytes_transferred": 150000000,  # 150MB - very high
                "connection_count": 1000,
                "timestamp": datetime.now().isoformat()
            }
        },
        {
            "name": "Port Scanning Activity",
            "data": {
                "ip_address": "91.240.118.172",
                "event_type": "port_scan",
                "unique_endpoints": 200,
                "failed_login_attempts": 0,
                "timestamp": datetime.now().isoformat()
            }
        },
        {
            "name": "Privilege Escalation",
            "data": {
                "ip_address": "104.244.76.187",
                "user_id": "regular_user",
                "event_type": "buffer_overflow",
                "privilege_escalation": True,
                "admin_escalation_attempt": True,
                "timestamp": datetime.now().isoformat()
            }
        },
        {
            "name": "Unknown Attack Pattern",
            "data": {
                "ip_address": "198.51.100.50",
                "event_type": "unknown_attack",
                "bytes_transferred": 200000000,  # 200MB
                "rapid_fire_requests": True,
                "malformed_packets": True,
                "geographic_distance": 15000,  # Impossible travel
                "ai_model_uncertainty": 0.9,
                "timestamp": datetime.now().isoformat()
            }
        }
    ]
    
    for i, scenario in enumerate(test_scenarios, 1):
        print(f"\n🔍 Test {i}: {scenario['name']}")
        print("-" * 40)
        
        try:
            response = requests.post(api_url, json=scenario['data'])
            response.raise_for_status()
            result = response.json()
            
            # Display results
            risk_level = result['risk_level']
            risk_score = result['risk_score']
            threat_category = result.get('threat_category', 'Unknown')
            threats = result.get('threat_types', [])
            recommendations = result.get('recommendations', [])
            
            # Color coding for risk levels
            risk_emoji = {
                'NORMAL': '✅',
                'LOW': '🟡',
                'MEDIUM': '🟠', 
                'HIGH': '🔴'
            }
            
            print(f"{risk_emoji.get(risk_level, '❓')} Risk Level: {risk_level}")
            print(f"📊 Risk Score: {risk_score}")
            print(f"🎯 Category: {threat_category}")
            
            if threats:
                print(f"⚠️  Threats Detected:")
                for threat in threats:
                    print(f"   • {threat}")
            
            if recommendations:
                print(f"💡 Recommendations:")
                for rec in recommendations[:3]:  # Show top 3
                    print(f"   • {rec}")
            
            # Alert for high-risk scenarios
            if risk_level in ['HIGH', 'MEDIUM']:
                print(f"🚨 SECURITY ALERT: {risk_level} risk threat detected!")
            
        except requests.RequestException as e:
            print(f"❌ Error: {e}")
        except Exception as e:
            print(f"❌ Unexpected error: {e}")

def demonstrate_api_usage():
    """Show different ways to use the API"""
    
    print("\n" + "=" * 50)
    print("📡 API Usage Methods")
    print("=" * 50)
    
    print("\n1. Direct REST API Call:")
    print("   POST http://localhost:5000/api/detect-threat")
    print("   Content-Type: application/json")
    print("   Body: { 'ip_address': '1.2.3.4', 'event_type': 'login', ... }")
    
    print("\n2. Python Requests:")
    print("   import requests")
    print("   response = requests.post('http://localhost:5000/api/detect-threat', json=log_data)")
    print("   result = response.json()")
    
    print("\n3. Curl Command:")
    print("   curl -X POST http://localhost:5000/api/detect-threat \\")
    print("        -H 'Content-Type: application/json' \\")
    print("        -d '{\"ip_address\":\"1.2.3.4\",\"event_type\":\"login\"}'")
    
    print("\n4. System Integration:")
    print("   • SIEM Systems: Forward logs via API")
    print("   • Log Aggregators: Real-time analysis")
    print("   • Security Tools: Batch processing")
    print("   • Monitoring: Automated alerts")

def show_practical_use_cases():
    """Show practical use cases"""
    
    print("\n" + "=" * 50)
    print("🏢 Practical Use Cases")
    print("=" * 50)
    
    use_cases = [
        {
            "scenario": "🌐 Web Application Security",
            "description": "Monitor web server logs for attacks",
            "integration": "Forward Apache/Nginx logs to ThreatX API",
            "benefits": "Detect SQL injection, XSS, brute force attempts"
        },
        {
            "scenario": "🔐 Identity & Access Management",
            "description": "Monitor login attempts and user behavior",
            "integration": "Connect to Active Directory, LDAP logs",
            "benefits": "Detect credential stuffing, account takeover"
        },
        {
            "scenario": "🌊 Network Security Monitoring",
            "description": "Analyze network traffic patterns",
            "integration": "Process firewall, IDS/IPS logs",
            "benefits": "Detect DDoS, port scans, lateral movement"
        },
        {
            "scenario": "☁️ Cloud Security",
            "description": "Monitor cloud infrastructure",
            "integration": "AWS CloudTrail, Azure Security Center",
            "benefits": "Detect privilege escalation, data exfiltration"
        },
        {
            "scenario": "📧 Email Security",
            "description": "Analyze email server logs",
            "integration": "Exchange, Office 365 logs",
            "benefits": "Detect phishing campaigns, spam attacks"
        }
    ]
    
    for case in use_cases:
        print(f"\n{case['scenario']}")
        print(f"   📝 {case['description']}")
        print(f"   🔗 Integration: {case['integration']}")
        print(f"   ✨ Benefits: {case['benefits']}")

if __name__ == "__main__":
    print("Starting ThreatX Detection Demo...")
    print("Make sure ThreatX server is running on http://localhost:5000\n")
    
    try:
        # Test if server is running
        response = requests.get("http://localhost:5000/health", timeout=5)
        if response.status_code == 200:
            print("✅ ThreatX server is running and healthy\n")
            
            # Run the demo
            test_threat_detection()
            demonstrate_api_usage()
            show_practical_use_cases()
            
            print(f"\n🎉 Demo completed! Visit http://localhost:5000 for the web dashboard.")
            
        else:
            print("❌ ThreatX server is not responding properly")
            
    except requests.ConnectionError:
        print("❌ Cannot connect to ThreatX server. Please start it with:")
        print("   python test_server.py")
    except Exception as e:
        print(f"❌ Error: {e}")