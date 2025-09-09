import requests
import json
import sys

def test_ai_engine_connection():
    """Test connection to AI Engine"""
    try:
        # Test health endpoint
        health_response = requests.get('http://localhost:5000/health')
        health_response.raise_for_status()
        health_data = health_response.json()
        
        print("\n✅ AI Engine Health Check Successful")
        print(f"Status: {health_data.get('status')}")
        print(f"Timestamp: {health_data.get('timestamp')}")
        print(f"Version: {health_data.get('version')}")
        
        # Test threat statistics endpoint
        stats_response = requests.get('http://localhost:5000/api/threat-statistics')
        stats_response.raise_for_status()
        stats_data = stats_response.json()
        
        print("\n✅ AI Engine Threat Statistics Successful")
        print(f"Total Threats: {stats_data.get('total_threats')}")
        print(f"Threat Types: {json.dumps(stats_data.get('threat_types'), indent=2)}")
        
        # Test suspicious IPs endpoint
        ips_response = requests.get('http://localhost:5000/api/suspicious-ips')
        ips_response.raise_for_status()
        ips_data = ips_response.json()
        
        print("\n✅ AI Engine Suspicious IPs Successful")
        print(f"Number of Suspicious IPs: {len(ips_data)}")
        for ip in ips_data:
            print(f"IP: {ip.get('ip_address')}, Risk Score: {ip.get('risk_score')}")
        
        print("\n🎉 All AI Engine connection tests passed!")
        print("The dashboard should now be able to connect to the AI Engine.")
        return True
        
    except requests.exceptions.RequestException as e:
        print(f"\n❌ Error connecting to AI Engine: {e}")
        return False
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    print("Testing connection to AI Engine...")
    success = test_ai_engine_connection()
    sys.exit(0 if success else 1)