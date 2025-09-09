import unittest
import json
from datetime import datetime
import sys
import os

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_preprocessor import DataPreprocessor
from src.threat_detector import ThreatDetector

class TestThreatDetection(unittest.TestCase):
    """Test cases for threat detection system"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.preprocessor = DataPreprocessor()
        self.detector = ThreatDetector()
    
    def test_data_preprocessing(self):
        """Test data preprocessing functionality"""
        # Sample log entry
        log_data = {
            'timestamp': '2024-01-15 14:30:00',
            'ip_address': '192.168.1.100',
            'user_id': 'test_user',
            'event_type': 'login',
            'failed_login_attempts': 0,
            'total_login_attempts': 1,
            'bytes_transferred': 1024,
            'session_count': 1
        }
        
        # Process log entry
        features = self.preprocessor.process_log_entry(log_data)
        
        # Verify expected features are present
        expected_features = [
            'hour_of_day', 'day_of_week', 'is_weekend',
            'login_attempts_last_hour', 'login_attempts_last_day',
            'ip_reputation_score', 'is_private_ip', 'country_risk_score',
            'user_session_count', 'bytes_transferred', 'unique_endpoints_accessed',
            'failed_login_ratio', 'geographic_anomaly', 'time_since_last_activity'
        ]
        
        for feature in expected_features:
            self.assertIn(feature, features)
            self.assertIsInstance(features[feature], (int, float))
    
    def test_threat_detection_normal(self):
        """Test threat detection with normal activity"""
        # Normal activity features
        features = {
            'hour_of_day': 14.0,
            'day_of_week': 1.0,
            'is_weekend': 0.0,
            'login_attempts_last_hour': 1.0,
            'login_attempts_last_day': 3.0,
            'ip_reputation_score': 0.8,
            'is_private_ip': 1.0,
            'country_risk_score': 0.1,
            'user_session_count': 1.0,
            'bytes_transferred': 1024.0,
            'unique_endpoints_accessed': 1.0,
            'failed_login_ratio': 0.0,
            'geographic_anomaly': 0.0,
            'time_since_last_activity': 2.0
        }
        
        result = self.detector.analyze(features)
        
        # Verify result structure
        self.assertIn('risk_score', result)
        self.assertIn('risk_level', result)
        self.assertIn('threat_types', result)
        self.assertIn('recommendations', result)
        
        # Normal activity should have low risk
        self.assertLessEqual(result['risk_score'], 0.5)
    
    def test_threat_detection_suspicious(self):
        """Test threat detection with suspicious activity"""
        # Suspicious activity features
        features = {
            'hour_of_day': 2.0,  # Late night
            'day_of_week': 1.0,
            'is_weekend': 0.0,
            'login_attempts_last_hour': 15.0,  # Many attempts
            'login_attempts_last_day': 50.0,
            'ip_reputation_score': 0.2,  # Bad reputation
            'is_private_ip': 0.0,
            'country_risk_score': 0.8,  # High risk country
            'user_session_count': 1.0,
            'bytes_transferred': 1024.0,
            'unique_endpoints_accessed': 1.0,
            'failed_login_ratio': 0.7,  # Many failures
            'geographic_anomaly': 0.8,  # Geographic anomaly
            'time_since_last_activity': 0.1
        }
        
        result = self.detector.analyze(features)
        
        # Suspicious activity should have higher risk
        self.assertGreaterEqual(result['risk_score'], 0.3)
        self.assertIn(result['risk_level'], ['MEDIUM', 'HIGH'])
    
    def test_ip_reputation_calculation(self):
        """Test IP reputation scoring"""
        # Test private IP
        features_private = self.preprocessor._extract_ip_features('192.168.1.1')
        self.assertEqual(features_private['is_private_ip'], 1.0)
        self.assertGreaterEqual(features_private['ip_reputation_score'], 0.5)
        
        # Test public IP
        features_public = self.preprocessor._extract_ip_features('8.8.8.8')
        self.assertEqual(features_public['is_private_ip'], 0.0)
    
    def test_time_feature_extraction(self):
        """Test time-based feature extraction"""
        # Test weekend detection
        weekend_time = datetime(2024, 1, 14, 14, 30)  # Sunday
        features = self.preprocessor._extract_time_features(weekend_time)
        self.assertEqual(features['is_weekend'], 1.0)
        
        # Test weekday
        weekday_time = datetime(2024, 1, 15, 14, 30)  # Monday
        features = self.preprocessor._extract_time_features(weekday_time)
        self.assertEqual(features['is_weekend'], 0.0)
    
    def test_threat_type_identification(self):
        """Test threat type identification"""
        # Test brute force detection
        features_brute_force = {
            'failed_login_ratio': 0.8,
            'login_attempts_last_hour': 25,
            'ip_reputation_score': 0.3,
            'geographic_anomaly': 0.2,
            'bytes_transferred': 1024
        }
        
        threats = self.detector._identify_threat_types(features_brute_force, 0.8)
        self.assertIn('Brute Force Attack', threats)
        self.assertIn('Credential Stuffing', threats)

if __name__ == '__main__':
    # Create logs directory if it doesn't exist
    os.makedirs('../logs', exist_ok=True)
    
    # Run tests
    unittest.main(verbosity=2)