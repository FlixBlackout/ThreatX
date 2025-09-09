#!/usr/bin/env python3
"""
Comprehensive Test of All Attack Types - Before and After Fix
"""

import requests
import json
from datetime import datetime

def test_all_attack_types():
    """Test all NSL-KDD attack categories with proper data"""
    
    api_url = "http://localhost:5000/api/detect-threat"
    
    print("🔍 Comprehensive Attack Type Testing")
    print("=" * 60)
    
    # Comprehensive test scenarios for all NSL-KDD attack types
    test_scenarios = [
        {
            "category": "NORMAL",
            "name": "✅ Normal User Activity",
            "data": {
                "ip_address": "192.168.1.100",
                "user_id": "alice.smith",
                "event_type": "login",
                "failed_login_attempts": 0,
                "bytes_transferred": 2048,
                "connection_count": 1,
                "duration": 120,
                "timestamp": datetime.now().isoformat()
            },
            "expected": "NORMAL"
        },
        {
            "category": "DOS",
            "name": "🌊 DDoS Attack (neptune-style)",
            "data": {
                "ip_address": "203.0.113.199",
                "event_type": "ddos",
                "bytes_transferred": 800000000,  # 800MB
                "connection_count": 2000,
                "request_frequency": 15000,
                "traffic_burst": True,
                "bandwidth_spike": True,
                "duration": 5,
                "timestamp": datetime.now().isoformat()
            },
            "expected": "HIGH"
        },
        {
            "category": "DOS", 
            "name": "💥 SYN Flood Attack",
            "data": {
                "ip_address": "198.51.100.50",
                "event_type": "syn_flood",
                "connection_count": 10000,
                "request_frequency": 50000,
                "duration": 1,
                "bytes_transferred": 500000,
                "timestamp": datetime.now().isoformat()
            },
            "expected": "HIGH"
        },
        {
            "category": "PROBE",
            "name": "🔍 Port Scan (nmap-style)",
            "data": {
                "ip_address": "91.240.118.172",
                "event_type": "port_scan",
                "unique_endpoints": 200,
                "scan_duration": 300,
                "connection_count": 250,
                "failed_login_attempts": 0,
                "bytes_transferred": 50000,
                "timestamp": datetime.now().isoformat()
            },
            "expected": "MEDIUM"
        },
        {
            "category": "PROBE",
            "name": "🕵️ Network Reconnaissance",
            "data": {
                "ip_address": "185.220.101.6",
                "event_type": "reconnaissance",
                "unique_endpoints": 500,
                "scan_duration": 600,
                "connection_count": 100,
                "bytes_transferred": 25000,
                "timestamp": datetime.now().isoformat()
            },
            "expected": "MEDIUM"
        },
        {
            "category": "R2L",
            "name": "🔓 Brute Force Attack",
            "data": {
                "ip_address": "185.220.101.5",
                "user_id": "admin",
                "event_type": "brute_force",
                "failed_login_attempts": 25,
                "connection_count": 50,
                "duration": 1800,
                "bytes_transferred": 10000,
                "timestamp": datetime.now().isoformat()
            },
            "expected": "HIGH"
        },
        {
            "category": "R2L",
            "name": "🎯 Password Attack",
            "data": {
                "ip_address": "104.244.76.188",
                "user_id": "root",
                "event_type": "password_attack",
                "failed_login_attempts": 100,
                "connection_count": 20,
                "duration": 3600,
                "bytes_transferred": 5000,
                "timestamp": datetime.now().isoformat()
            },
            "expected": "HIGH"
        },
        {
            "category": "U2R",
            "name": "⬆️ Buffer Overflow",
            "data": {
                "ip_address": "104.244.76.187",
                "user_id": "regular_user",
                "event_type": "buffer_overflow",
                "privilege_escalation": True,
                "admin_escalation_attempt": True,
                "bytes_transferred": 4096,
                "duration": 30,
                "timestamp": datetime.now().isoformat()
            },
            "expected": "HIGH"
        },
        {
            "category": "U2R",
            "name": "👑 Privilege Escalation",
            "data": {
                "ip_address": "198.51.100.60",
                "user_id": "guest",
                "event_type": "privilege_escalation",
                "privilege_escalation": True,
                "root_access_attempt": True,
                "admin_escalation_attempt": True,
                "bytes_transferred": 8192,
                "duration": 60,
                "timestamp": datetime.now().isoformat()
            },
            "expected": "HIGH"
        },
        {
            "category": "UNKNOWN",
            "name": "🔮 Unknown Zero-Day Attack",
            "data": {
                "ip_address": "203.0.113.250",
                "event_type": "unknown_attack",
                "bytes_transferred": 200000000,
                "rapid_fire_requests": True,
                "malformed_packets": True,
                "protocol_violation": True,
                "encrypted_suspicious_traffic": True,
                "ai_model_uncertainty": 0.9,
                "geographic_distance": 15000,
                "duration": 10,
                "timestamp": datetime.now().isoformat()
            },
            "expected": "HIGH"
        }
    ]
    
    results = []
    correct_predictions = 0
    
    for i, scenario in enumerate(test_scenarios, 1):
        print(f"\n{i:2d}. {scenario['name']}")
        print("-" * 50)
        
        try:
            response = requests.post(api_url, json=scenario['data'])
            response.raise_for_status()
            result = response.json()
            
            risk_level = result['risk_level']
            risk_score = result['risk_score']
            threat_category = result.get('threat_category', 'Unknown')
            threats = result.get('threat_types', [])
            confidence = result.get('confidence', 0)
            dataset_informed = result.get('dataset_informed', False)
            
            # Store result
            results.append({
                'scenario': scenario,
                'result': result,
                'correct': risk_level in ['HIGH', 'MEDIUM'] if scenario['expected'] != 'NORMAL' else risk_level == 'NORMAL'
            })
            
            # Display results
            risk_emoji = {'NORMAL': '✅', 'LOW': '🟡', 'MEDIUM': '🟠', 'HIGH': '🔴'}
            print(f"Risk Level: {risk_emoji.get(risk_level, '❓')} {risk_level}")
            print(f"Risk Score: {risk_score}")
            print(f"Category: {threat_category}")
            print(f"Dataset Informed: {'✅' if dataset_informed else '❌'}")
            print(f"Confidence: {confidence}")
            
            if threats:
                print(f"Threats: {', '.join(threats[:3])}")
            
            # Check if prediction is correct
            if scenario['expected'] == 'NORMAL':
                is_correct = risk_level == 'NORMAL'
            else:
                is_correct = risk_level in ['HIGH', 'MEDIUM']
            
            if is_correct:
                print("✅ CORRECT PREDICTION")
                correct_predictions += 1
            else:
                print(f"❌ INCORRECT: Expected {scenario['expected']}, got {risk_level}")
                
        except Exception as e:
            print(f"❌ Error: {e}")
            results.append({
                'scenario': scenario,
                'result': {'error': str(e)},
                'correct': False
            })
    
    # Summary
    print(f"\n{'='*60}")
    print(f"📊 SUMMARY")
    print(f"{'='*60}")
    print(f"Total Tests: {len(test_scenarios)}")
    print(f"Correct Predictions: {correct_predictions}")
    print(f"Accuracy: {(correct_predictions/len(test_scenarios)*100):.1f}%")
    
    # Category breakdown
    print(f"\n📋 Category Breakdown:")
    categories = {}
    for result in results:
        cat = result['scenario']['category']
        if cat not in categories:
            categories[cat] = {'total': 0, 'correct': 0}
        categories[cat]['total'] += 1
        if result['correct']:
            categories[cat]['correct'] += 1
    
    for cat, stats in categories.items():
        accuracy = (stats['correct']/stats['total']*100) if stats['total'] > 0 else 0
        print(f"  {cat}: {stats['correct']}/{stats['total']} ({accuracy:.1f}%)")
    
    return results

if __name__ == "__main__":
    try:
        response = requests.get("http://localhost:5000/health", timeout=5)
        if response.status_code == 200:
            print("✅ ThreatX server is running\n")
            test_all_attack_types()
        else:
            print("❌ ThreatX server is not responding properly")
    except requests.ConnectionError:
        print("❌ Cannot connect to ThreatX server. Please start it with: python test_server.py")