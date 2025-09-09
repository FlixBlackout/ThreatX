import requests
import json

# Test the communication between Java dashboard and Python AI engine
def test_integration():
    # Test 1: Check if AI engine is running
    try:
        response = requests.get("http://localhost:5000/health")
        print("AI Engine Health Check:")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text[:200]}...")
        print()
    except Exception as e:
        print(f"Error connecting to AI Engine: {e}")
        return
    
    # Test 2: Check if dashboard is running
    try:
        response = requests.get("http://localhost:8084/")
        print("Dashboard Home Page:")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text[:200]}...")
        print()
    except Exception as e:
        print(f"Error connecting to Dashboard: {e}")
        return
    
    # Test 3: Test the threat statistics API endpoint
    try:
        response = requests.get("http://localhost:8084/api/threat-statistics")
        print("Dashboard Threat Statistics API:")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        print()
    except Exception as e:
        print(f"Error calling Dashboard Threat Statistics API: {e}")
        return
    
    # Test 4: Test direct AI engine threat statistics API
    try:
        response = requests.get("http://localhost:5000/api/threat-statistics?format=json")
        print("Direct AI Engine Threat Statistics API:")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        print()
    except Exception as e:
        print(f"Error calling Direct AI Engine Threat Statistics API: {e}")
        return

if __name__ == "__main__":
    test_integration()