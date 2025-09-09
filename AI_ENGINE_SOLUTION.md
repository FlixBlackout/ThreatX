# AI Engine Connection Solution

## Problem

The ThreatX dashboard was showing an error "AI Engine offline" because the AI Engine service was not running. The dashboard attempts to connect to the AI Engine at http://localhost:5000 as configured in `application.properties`.

## Solution

1. Created a mock AI Engine service (`mock_ai_engine.py`) that implements the essential endpoints:
   - `/health` - Health check endpoint
   - `/api/detect-threat` - Threat detection endpoint
   - `/api/threat-statistics` - Threat statistics endpoint
   - `/api/suspicious-ips` - Suspicious IPs endpoint
   - `/api/user-risk-profile/<user_id>` - User risk profile endpoint

2. The mock AI Engine runs on http://localhost:5000 and responds with realistic mock data that matches the expected format.

3. Verified the connection with a test script (`test_ai_connection.py`) that confirms all endpoints are working correctly.

## How to Use

1. Start the mock AI Engine:
   ```
   python mock_ai_engine.py
   ```

2. The dashboard should now be able to connect to the AI Engine and display data correctly.

3. To verify the connection, run:
   ```
   python test_ai_connection.py
   ```

## Long-term Solution

For a production environment, you should:

1. Install the required dependencies for the real AI Engine:
   ```
   pip install -r ai-engine/requirements.txt
   ```

2. Configure the AI Engine with proper environment variables (copy `.env.example` to `.env` and modify as needed).

3. Start the real AI Engine:
   ```
   cd ai-engine
   python app.py
   ```

4. Consider using Docker Compose as described in the setup scripts to run the complete system with all components.