from flask import Flask, jsonify
from flask_cors import CORS
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
CORS(app)

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })

@app.route('/api/detect-threat', methods=['POST'])
def detect_threat():
    """Mock threat detection endpoint"""
    return jsonify({
        'risk_score': 0.15,
        'risk_level': 'NORMAL',
        'model_scores': {
            'isolation_forest': 0.1,
            'random_forest': 0.2,
            'autoencoder': 0.15
        },
        'threat_types': [],
        'recommendations': ["Continue monitoring"],
        'confidence': 0.85,
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/api/threat-statistics', methods=['GET'])
def get_threat_statistics():
    """Mock threat statistics endpoint"""
    return jsonify({
        'total_threats': 125,
        'threat_types': {
            'DoS': 45,
            'Probe': 30,
            'R2L': 25,
            'U2R': 15,
            'Unknown': 10
        },
        'risk_levels': {
            'HIGH': 20,
            'MEDIUM': 35,
            'LOW': 70
        },
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/api/suspicious-ips', methods=['GET'])
def get_suspicious_ips():
    """Mock suspicious IPs endpoint"""
    return jsonify([
        {
            'ip_address': '203.0.113.45',
            'risk_score': 0.85,
            'country': 'Unknown',
            'threat_types': ['DoS'],
            'last_seen': datetime.utcnow().isoformat()
        },
        {
            'ip_address': '198.51.100.30',
            'risk_score': 0.75,
            'country': 'Unknown',
            'threat_types': ['Probe'],
            'last_seen': datetime.utcnow().isoformat()
        }
    ])

@app.route('/api/user-risk-profile/<user_id>', methods=['GET'])
def get_user_risk_profile(user_id):
    """Mock user risk profile endpoint"""
    return jsonify({
        'user_id': user_id,
        'risk_score': 0.25,
        'risk_level': 'LOW',
        'recent_activities': [
            {
                'timestamp': datetime.utcnow().isoformat(),
                'event_type': 'login',
                'risk_score': 0.1
            }
        ],
        'recommendations': ['No action needed']
    })

if __name__ == '__main__':
    print("Starting Mock AI Engine on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)