from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
import os
from datetime import datetime

from config import Config
from src.threat_detector import ThreatDetector
from src.data_preprocessor import DataPreprocessor
from src.database_manager import DatabaseManager

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
CORS(app)

# Initialize components
threat_detector = ThreatDetector()
data_preprocessor = DataPreprocessor()
db_manager = DatabaseManager()

# Setup logging
logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

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
    """Main threat detection endpoint"""
    try:
        # Get log data from request
        log_data = request.json
        
        if not log_data:
            return jsonify({'error': 'No log data provided'}), 400
        
        # Preprocess the log data
        processed_data = data_preprocessor.process_log_entry(log_data)
        
        # Detect threats using ML models
        threat_result = threat_detector.analyze(processed_data)
        
        # Store results in database
        db_manager.store_threat_analysis(log_data, threat_result)
        
        logger.info(f"Threat analysis completed. Risk level: {threat_result['risk_level']}")
        
        return jsonify(threat_result)
        
    except Exception as e:
        logger.error(f"Error in threat detection: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/user-risk-profile/<user_id>', methods=['GET'])
def get_user_risk_profile(user_id):
    """Get user risk profile"""
    try:
        profile = db_manager.get_user_risk_profile(user_id)
        return jsonify(profile)
    except Exception as e:
        logger.error(f"Error getting user risk profile: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/threat-statistics', methods=['GET'])
def get_threat_statistics():
    """Get threat statistics for dashboard"""
    try:
        # Get query parameters
        time_range = request.args.get('range', '24h')
        
        stats = db_manager.get_threat_statistics(time_range)
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting threat statistics: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/suspicious-ips', methods=['GET'])
def get_suspicious_ips():
    """Get list of suspicious IP addresses"""
    try:
        limit = request.args.get('limit', 100, type=int)
        suspicious_ips = db_manager.get_suspicious_ips(limit)
        return jsonify(suspicious_ips)
    except Exception as e:
        logger.error(f"Error getting suspicious IPs: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/retrain-models', methods=['POST'])
def retrain_models():
    """Trigger model retraining"""
    try:
        # This would typically be called by a scheduled job
        threat_detector.retrain_models()
        return jsonify({'status': 'success', 'message': 'Model retraining initiated'})
    except Exception as e:
        logger.error(f"Error retraining models: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Ensure log directory exists
    os.makedirs(os.path.dirname(Config.LOG_FILE), exist_ok=True)
    
    logger.info("Starting ThreatX AI Engine...")
    app.run(
        host=Config.API_HOST,
        port=Config.API_PORT,
        debug=Config.DEBUG
    )