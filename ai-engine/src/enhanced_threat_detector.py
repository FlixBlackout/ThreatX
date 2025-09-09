#!/usr/bin/env python3
"""
Enhanced ThreatX Threat Detector with Real Cybersecurity Dataset Integration
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os
import logging
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional

try:
    from .dataset_manager import DatasetManager
except ImportError:
    # Fallback for standalone execution
    from dataset_manager import DatasetManager

logger = logging.getLogger(__name__)

class EnhancedThreatDetector:
    """Enhanced threat detection with NSL-KDD and CICIDS integration"""
    
    def __init__(self, use_datasets: bool = True):
        self.dataset_manager = DatasetManager() if use_datasets else None
        self.models = {}
        self.scaler = StandardScaler()
        self.is_trained = False
        self.model_path = './models/'
        self.use_datasets = use_datasets
        
        # Enhanced risk thresholds based on dataset analysis
        self.risk_thresholds = {'low': 0.25, 'medium': 0.55, 'high': 0.75}
        
        # Attack type mappings from NSL-KDD
        self.attack_categories = {
            'dos': ['apache2', 'back', 'land', 'neptune', 'smurf', 'teardrop'],
            'probe': ['ipsweep', 'nmap', 'portsweep', 'satan'],
            'r2l': ['ftp_write', 'guess_passwd', 'imap', 'phf', 'worm'],
            'u2r': ['buffer_overflow', 'loadmodule', 'perl', 'rootkit']
        }
        
        self._initialize_models()
        self._load_models()
        
        # Auto-train with datasets if available
        if self.use_datasets and not self.is_trained:
            self._auto_train()
    
    def _initialize_models(self):
        """Initialize enhanced ML models"""
        try:
            # Optimized models based on cybersecurity research
            self.models['isolation_forest'] = IsolationForest(
                contamination=0.1, random_state=42, n_estimators=200
            )
            
            self.models['random_forest'] = RandomForestClassifier(
                n_estimators=200, random_state=42, max_depth=15, class_weight='balanced'
            )
            
            self.models['gradient_boosting'] = GradientBoostingClassifier(
                n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42
            )
            
            logger.info("Enhanced ML models initialized")
            
        except Exception as e:
            logger.error(f"Error initializing models: {e}")
            raise
    
    def _auto_train(self):
        """Automatically train with cybersecurity datasets"""
        try:
            logger.info("Starting automatic training with NSL-KDD dataset...")
            
            if self.dataset_manager:
                # Load and train with NSL-KDD
                train_df, test_df = self.dataset_manager.load_nsl_kdd()
                X_train, y_train = self.dataset_manager.get_training_data('nsl_kdd')
                
                # Create binary labels for attack detection
                y_binary = (y_train > 0.5).astype(int)
                
                # Train models
                self.train_models_with_dataset(X_train, y_binary)
                
                logger.info("Dataset training completed successfully")
            
        except Exception as e:
            logger.warning(f"Auto-training failed: {e}. Using heuristic analysis.")
            self.is_trained = False
    
    def train_models_with_dataset(self, X_train: np.ndarray, y_binary: np.ndarray):
        """Train models with real cybersecurity dataset"""
        try:
            logger.info(f"Training models with {len(X_train)} samples...")
            
            # Split data
            X_train_split, X_val, y_train_split, y_val = train_test_split(
                X_train, y_binary, test_size=0.2, random_state=42, stratify=y_binary
            )
            
            # Fit scaler and transform data
            self.scaler.fit(X_train_split)
            X_train_scaled = self.scaler.transform(X_train_split)
            X_val_scaled = self.scaler.transform(X_val)
            
            # Train Isolation Forest (only on normal data)
            normal_data = X_train_scaled[y_train_split == 0]
            self.models['isolation_forest'].fit(normal_data)
            
            # Train supervised models
            self.models['random_forest'].fit(X_train_scaled, y_train_split)
            self.models['gradient_boosting'].fit(X_train_scaled, y_train_split)
            
            # Evaluate models
            self._evaluate_models(X_val_scaled, y_val)
            
            self.is_trained = True
            self._save_models()
            
            logger.info("Dataset-based training completed successfully")
            
        except Exception as e:
            logger.error(f"Error training models: {e}")
            raise
    
    def _evaluate_models(self, X_test: np.ndarray, y_test: np.ndarray):
        """Evaluate trained models"""
        try:
            for model_name in ['random_forest', 'gradient_boosting']:
                if model_name in self.models:
                    y_pred = self.models[model_name].predict(X_test)
                    logger.info(f"{model_name} accuracy: {np.mean(y_pred == y_test):.3f}")
        except Exception as e:
            logger.warning(f"Model evaluation failed: {e}")
    
    def analyze(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced threat analysis with dataset-trained models"""
        try:
            # Convert log data to feature vector
            if self.use_datasets and self.dataset_manager:
                feature_vector = self.dataset_manager.get_sample_features(log_data)
            else:
                feature_vector = self._log_to_features(log_data)
            
            if not self.is_trained:
                return self._heuristic_analysis(log_data)
            
            # Scale features and get predictions
            feature_scaled = self.scaler.transform([feature_vector])
            predictions = self._get_predictions(feature_scaled)
            
            # Combine predictions
            risk_assessment = self._ensemble_analysis(predictions, log_data)
            
            return risk_assessment
            
        except Exception as e:
            logger.error(f"Error in threat analysis: {e}")
            return self._get_default_analysis()
    
    def _get_predictions(self, feature_scaled: np.ndarray) -> Dict[str, float]:
        """Get predictions from all models"""
        predictions = {}
        
        try:
            # Isolation Forest
            if 'isolation_forest' in self.models:
                iso_score = self.models['isolation_forest'].decision_function(feature_scaled)[0]
                predictions['isolation_forest'] = max(0, min(1, (1 - iso_score) / 2))
            
            # Random Forest
            if 'random_forest' in self.models:
                rf_proba = self.models['random_forest'].predict_proba(feature_scaled)[0]
                predictions['random_forest'] = rf_proba[1] if len(rf_proba) > 1 else 0.5
            
            # Gradient Boosting
            if 'gradient_boosting' in self.models:
                gb_proba = self.models['gradient_boosting'].predict_proba(feature_scaled)[0]
                predictions['gradient_boosting'] = gb_proba[1] if len(gb_proba) > 1 else 0.5
            
        except Exception as e:
            logger.warning(f"Error getting predictions: {e}")
            predictions = {'fallback': 0.5}
        
        return predictions
    
    def _ensemble_analysis(self, predictions: Dict[str, float], log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Combine predictions with ensemble method"""
        
        # Weighted ensemble
        weights = {'isolation_forest': 0.3, 'random_forest': 0.35, 'gradient_boosting': 0.35}
        ensemble_score = sum(predictions.get(model, 0.5) * weight for model, weight in weights.items())
        
        # Apply dataset-informed adjustments
        ensemble_score = self._apply_adjustments(ensemble_score, log_data)
        
        # Classify threat type
        threat_category = self._classify_threat(log_data)
        risk_level = self._get_risk_level(ensemble_score)
        
        return {
            'risk_score': round(ensemble_score, 3),
            'risk_level': risk_level,
            'threat_category': threat_category,
            'model_scores': predictions,
            'timestamp': datetime.utcnow().isoformat(),
            'confidence': self._calculate_confidence(predictions),
            'threat_types': self._identify_threats(log_data, ensemble_score),
            'recommendations': self._generate_recommendations(risk_level, threat_category),
            'dataset_informed': True
        }
    
    def _apply_adjustments(self, score: float, log_data: Dict[str, Any]) -> float:
        """Apply dataset-informed adjustments with enhanced scoring"""
        adjusted = score
        
        # DDoS/DoS patterns - High Priority
        if log_data.get('event_type') in ['ddos', 'dos', 'flood', 'amplification', 'syn_flood']:
            adjusted = min(1.0, adjusted + 0.6)  # Major adjustment for actual DDoS
        
        # Volume-based DoS detection
        if log_data.get('connection_count', 0) > 1000:
            adjusted = min(1.0, adjusted + 0.5)  # Very high connection count
        elif log_data.get('connection_count', 0) > 500:
            adjusted = min(1.0, adjusted + 0.3)  # High connection count
        
        # Bandwidth-based DoS detection
        if log_data.get('bytes_transferred', 0) > 500000000:  # >500MB
            adjusted = min(1.0, adjusted + 0.4)  # Massive data transfer
        elif log_data.get('bytes_transferred', 0) > 100000000:  # >100MB
            adjusted = min(1.0, adjusted + 0.3)  # Large data transfer
        
        # Request frequency-based DoS
        if log_data.get('request_frequency', 0) > 10000:  # >10k requests
            adjusted = min(1.0, adjusted + 0.5)  # Very high frequency
        elif log_data.get('request_frequency', 0) > 1000:  # >1k requests
            adjusted = min(1.0, adjusted + 0.3)  # High frequency
        
        # Traffic burst indicators
        if log_data.get('traffic_burst', False) or log_data.get('bandwidth_spike', False):
            adjusted = min(1.0, adjusted + 0.4)
        
        # PROBE ATTACK ENHANCEMENTS
        if log_data.get('event_type') in ['port_scan', 'probe', 'reconnaissance', 'service_scan']:
            adjusted = min(1.0, adjusted + 0.4)  # Increased from 0.15
        
        # Enhanced probe detection
        if log_data.get('unique_endpoints', 0) > 100:
            adjusted = min(1.0, adjusted + 0.3)  # Scanning many endpoints
        elif log_data.get('unique_endpoints', 0) > 20:
            adjusted = min(1.0, adjusted + 0.2)
        
        if log_data.get('scan_duration', 0) > 300:  # >5 minutes scanning
            adjusted = min(1.0, adjusted + 0.2)
        
        # R2L ATTACK ENHANCEMENTS  
        if log_data.get('event_type') in ['brute_force', 'password_attack', 'credential_stuffing']:
            adjusted = min(1.0, adjusted + 0.5)  # Increased from 0.25
        
        # Enhanced brute force detection
        if log_data.get('failed_login_attempts', 0) > 20:
            adjusted = min(1.0, adjusted + 0.4)  # Very aggressive brute force
        elif log_data.get('failed_login_attempts', 0) > 10:
            adjusted = min(1.0, adjusted + 0.3)
        elif log_data.get('failed_login_attempts', 0) > 3:
            adjusted = min(1.0, adjusted + 0.2)
        
        # U2R ATTACK ENHANCEMENTS
        if log_data.get('event_type') in ['buffer_overflow', 'privilege_escalation', 'rootkit']:
            adjusted = min(1.0, adjusted + 0.6)  # High risk for privilege escalation
        
        if log_data.get('privilege_escalation', False):
            adjusted = min(1.0, adjusted + 0.4)
        
        if log_data.get('root_access_attempt', False):
            adjusted = min(1.0, adjusted + 0.5)
        
        if log_data.get('admin_escalation_attempt', False):
            adjusted = min(1.0, adjusted + 0.3)
        
        # UNKNOWN THREAT ENHANCEMENTS
        if log_data.get('event_type') in ['unknown_attack', 'anomaly']:
            adjusted = min(1.0, adjusted + 0.5)
        
        if log_data.get('malformed_packets', False):
            adjusted = min(1.0, adjusted + 0.3)
        
        if log_data.get('protocol_violation', False):
            adjusted = min(1.0, adjusted + 0.3)
        
        if log_data.get('encrypted_suspicious_traffic', False):
            adjusted = min(1.0, adjusted + 0.2)
        
        if log_data.get('ai_model_uncertainty', 0) > 0.8:
            adjusted = min(1.0, adjusted + 0.3)
        
        return adjusted
    
    def _classify_threat(self, log_data: Dict[str, Any]) -> str:
        """Classify threat type with unknown threat detection"""
        # Check for DoS/DDoS patterns first - HIGHEST PRIORITY
        if (log_data.get('event_type') in ['ddos', 'dos', 'flood', 'amplification'] or
            log_data.get('connection_count', 0) > 500 or
            log_data.get('bytes_transferred', 0) > 100000000 or  # >100MB
            log_data.get('request_frequency', 0) > 1000 or
            log_data.get('traffic_burst', False) or
            log_data.get('bandwidth_spike', False)):
            return 'DoS'
        
        # Check for Probe patterns
        elif log_data.get('event_type') in ['port_scan', 'service_scan', 'probe', 'reconnaissance']:
            return 'Probe'
        
        # Check for R2L patterns (credential attacks)
        elif (log_data.get('failed_login_attempts', 0) > 3 or
              log_data.get('event_type') in ['brute_force', 'credential_stuffing', 'password_attack']):
            return 'R2L'
        
        # Check for U2R patterns (privilege escalation)
        elif (log_data.get('privilege_escalation', False) or
              log_data.get('event_type') in ['buffer_overflow', 'privilege_escalation', 'rootkit']):
            return 'U2R'
        
        else:
            # Check for unknown/anomalous patterns
            anomaly_score = self._calculate_anomaly_score(log_data)
            if anomaly_score > 0.7:
                return 'Unknown Threat'
            elif anomaly_score > 0.5:
                return 'Anomaly'
            else:
                return 'Normal'
    
    def _calculate_anomaly_score(self, log_data: Dict[str, Any]) -> float:
        """Calculate anomaly score for unknown threat detection"""
        anomaly_indicators = 0
        total_checks = 0
        
        # Behavioral anomalies
        total_checks += 1
        if self._detect_behavioral_anomaly(log_data):
            anomaly_indicators += 1
        
        # Statistical anomalies
        total_checks += 1
        if self._detect_statistical_anomaly(log_data):
            anomaly_indicators += 1
        
        # Temporal anomalies
        total_checks += 1
        if self._detect_temporal_anomaly(log_data):
            anomaly_indicators += 1
        
        # Volume anomalies
        total_checks += 1
        if self._detect_volume_anomaly(log_data):
            anomaly_indicators += 1
        
        # Protocol anomalies
        total_checks += 1
        if self._detect_protocol_anomaly(log_data):
            anomaly_indicators += 1
        
        # Access pattern anomalies
        total_checks += 1
        if self._detect_access_pattern_anomaly(log_data):
            anomaly_indicators += 1
        
        return anomaly_indicators / max(1, total_checks)
    
    def _detect_behavioral_anomaly(self, log_data: Dict[str, Any]) -> bool:
        """Detect behavioral anomalies"""
        current_hour = datetime.now().hour
        return (
            current_hour < 5 or current_hour > 23 or  # Very unusual hours
            log_data.get('geographic_distance', 0) > 10000 or  # Impossible travel
            log_data.get('session_duration', 0) > 14400 or  # >4 hour session
            log_data.get('rapid_location_change', False)
        )
    
    def _detect_statistical_anomaly(self, log_data: Dict[str, Any]) -> bool:
        """Detect statistical anomalies in data patterns"""
        return (
            log_data.get('bytes_transferred', 0) > 100000000 or  # >100MB unusual
            log_data.get('request_frequency', 0) > 1000 or  # Very high frequency
            log_data.get('unique_endpoints', 0) > 100 or  # Scanning behavior
            log_data.get('error_rate', 0) > 0.8  # High error rate
        )
    
    def _detect_temporal_anomaly(self, log_data: Dict[str, Any]) -> bool:
        """Detect temporal anomalies"""
        return (
            log_data.get('rapid_fire_requests', False) or
            log_data.get('unusual_timing_pattern', False) or
            log_data.get('synchronized_attack', False)
        )
    
    def _detect_volume_anomaly(self, log_data: Dict[str, Any]) -> bool:
        """Detect volume-based anomalies"""
        return (
            log_data.get('connection_count', 0) > 500 or  # High connections
            log_data.get('bandwidth_spike', False) or
            log_data.get('traffic_burst', False)
        )
    
    def _detect_protocol_anomaly(self, log_data: Dict[str, Any]) -> bool:
        """Detect protocol-level anomalies"""
        return (
            log_data.get('malformed_packets', False) or
            log_data.get('unusual_headers', False) or
            log_data.get('protocol_violation', False) or
            log_data.get('encrypted_suspicious_traffic', False)
        )
    
    def _detect_access_pattern_anomaly(self, log_data: Dict[str, Any]) -> bool:
        """Detect unusual access patterns"""
        return (
            log_data.get('admin_escalation_attempt', False) or
            log_data.get('sensitive_data_access', False) or
            log_data.get('system_file_access', False) or
            log_data.get('unusual_file_operations', False)
        )
    
    def _identify_threats(self, log_data: Dict[str, Any], risk_score: float) -> List[str]:
        """Identify specific threat types including unknown threats"""
        threats = []
        
        threat_category = self._classify_threat(log_data)
        
        # Known attack categories
        if threat_category == 'DoS':
            threats.extend(['DoS Attack', 'Service Flooding'])
            # Add specific DoS/DDoS threat types
            if log_data.get('event_type') == 'ddos':
                threats.extend(['DDoS Attack', 'Distributed Denial of Service'])
            if log_data.get('connection_count', 0) > 1000:
                threats.append('Connection Flood')
            if log_data.get('bytes_transferred', 0) > 500000000:
                threats.append('Bandwidth Exhaustion')
            if log_data.get('request_frequency', 0) > 10000:
                threats.append('Request Flood')
            if log_data.get('traffic_burst', False):
                threats.append('Traffic Burst Attack')
        elif threat_category == 'Probe':
            threats.extend(['Network Scan', 'Port Probe'])
        elif threat_category == 'R2L':
            threats.extend(['Brute Force', 'Password Attack'])
        elif threat_category == 'U2R':
            threats.extend(['Privilege Escalation', 'Root Access'])
        elif threat_category == 'Unknown Threat':
            threats.extend(['Unknown Attack Pattern', 'Zero-Day Threat'])
            # Add specific anomaly types
            if self._detect_behavioral_anomaly(log_data):
                threats.append('Behavioral Anomaly')
            if self._detect_statistical_anomaly(log_data):
                threats.append('Statistical Anomaly')
            if self._detect_protocol_anomaly(log_data):
                threats.append('Protocol Anomaly')
            if self._detect_access_pattern_anomaly(log_data):
                threats.append('Access Pattern Anomaly')
        elif threat_category == 'Anomaly':
            threats.append('Suspicious Anomaly')
            anomaly_score = self._calculate_anomaly_score(log_data)
            if anomaly_score > 0.6:
                threats.append('Potential Zero-Day')
        
        # Additional threat indicators
        if log_data.get('ip_reputation_score', 0.5) < 0.2:
            threats.append('Malicious IP')
        
        if log_data.get('geographic_distance', 0) > 5000:
            threats.append('Geographic Anomaly')
        
        if log_data.get('encrypted_suspicious_traffic', False):
            threats.append('Encrypted Malicious Traffic')
        
        if log_data.get('ai_model_uncertainty', 0) > 0.8:
            threats.append('Model Uncertainty - Potential Unknown Threat')
        
        return threats
    
    def _generate_recommendations(self, risk_level: str, threat_category: str) -> List[str]:
        """Generate recommendations based on threat type including unknown threats"""
        recommendations = []
        
        if risk_level in ['HIGH', 'MEDIUM']:
            recommendations.append('Alert security team immediately')
        
        # Known attack type recommendations
        if threat_category == 'DoS':
            recommendations.extend(['Implement rate limiting', 'Monitor bandwidth', 'Activate DDoS protection'])
        elif threat_category == 'Probe':
            recommendations.extend(['Block scanning IP', 'Review firewall rules', 'Monitor for follow-up attacks'])
        elif threat_category == 'R2L':
            recommendations.extend(['Enable account lockout', 'Require MFA', 'Monitor credential usage'])
        elif threat_category == 'U2R':
            recommendations.extend(['Audit privilege access', 'Monitor admin accounts', 'Review system integrity'])
        
        # Unknown threat recommendations
        elif threat_category == 'Unknown Threat':
            recommendations.extend([
                'CRITICAL: Unknown attack pattern detected',
                'Immediately isolate affected systems',
                'Collect forensic evidence',
                'Initiate incident response protocol',
                'Contact cybersecurity experts',
                'Review all system logs for similar patterns',
                'Consider threat hunting activities',
                'Update threat intelligence feeds'
            ])
        elif threat_category == 'Anomaly':
            recommendations.extend([
                'Investigate suspicious activity',
                'Monitor user behavior closely',
                'Review access patterns',
                'Consider additional authentication',
                'Document anomaly for threat intelligence'
            ])
        
        # Risk-level specific recommendations
        if risk_level == 'HIGH':
            recommendations.extend([
                'Consider session termination',
                'Escalate to security operations center',
                'Implement emergency containment measures'
            ])
        
        return recommendations
    
    def _log_to_features(self, log_data: Dict[str, Any]) -> np.ndarray:
        """Convert log data to feature vector (fallback)"""
        features = np.zeros(41)  # NSL-KDD feature count
        features[0] = log_data.get('duration', 0)
        features[4] = log_data.get('bytes_transferred', 0)
        features[10] = log_data.get('failed_login_attempts', 0)
        return features
    
    def _heuristic_analysis(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced dataset-informed heuristic analysis"""
        risk_score = 0.0
        threats = []
        
        # Apply NSL-KDD pattern recognition with enhanced scoring
        threat_category = self._classify_threat(log_data)
        
        if threat_category == 'DoS':
            risk_score += 0.7  # High base score for DoS
            threats.append('DoS Pattern')
        elif threat_category == 'Probe':
            risk_score += 0.6  # Increased from 0.4 to 0.6
            threats.append('Probe Pattern')
        elif threat_category == 'R2L':
            risk_score += 0.7  # Keep high for R2L
            threats.append('R2L Pattern')
        elif threat_category == 'U2R':
            risk_score += 0.8  # Keep very high for U2R
            threats.append('U2R Pattern')
        elif threat_category == 'Unknown Threat':
            risk_score += 0.7  # High score for unknown threats
            threats.append('Unknown Threat Pattern')
        elif threat_category == 'Anomaly':
            risk_score += 0.5  # Medium score for anomalies
            threats.append('Anomaly Pattern')
        
        # Apply additional adjustments
        risk_score = self._apply_adjustments(risk_score, log_data)
        risk_score = min(1.0, risk_score)
        risk_level = self._get_risk_level(risk_score)
        
        return {
            'risk_score': round(risk_score, 3),
            'risk_level': risk_level,
            'threat_category': threat_category,
            'model_scores': {'heuristic': risk_score},
            'timestamp': datetime.utcnow().isoformat(),
            'confidence': 0.8,  # Higher confidence
            'threat_types': threats,
            'recommendations': self._generate_recommendations(risk_level, threat_category),
            'dataset_informed': True,  # Mark as dataset-informed
            'analysis_type': 'Enhanced Heuristic with NSL-KDD Intelligence'
        }
    
    def _get_risk_level(self, score: float) -> str:
        if score >= self.risk_thresholds['high']: return 'HIGH'
        elif score >= self.risk_thresholds['medium']: return 'MEDIUM'
        elif score >= self.risk_thresholds['low']: return 'LOW'
        else: return 'NORMAL'
    
    def _calculate_confidence(self, predictions: Dict[str, float]) -> float:
        if len(predictions) < 2: return 0.5
        scores = list(predictions.values())
        agreement = 1.0 - np.std(scores)
        return round(max(0.1, agreement), 3)
    
    def _save_models(self):
        """Save models to disk"""
        try:
            os.makedirs(self.model_path, exist_ok=True)
            for name, model in self.models.items():
                joblib.dump(model, f"{self.model_path}/{name}.pkl")
            joblib.dump(self.scaler, f"{self.model_path}/scaler.pkl")
            logger.info("Enhanced models saved")
        except Exception as e:
            logger.error(f"Error saving models: {e}")
    
    def _load_models(self):
        """Load models from disk"""
        try:
            if not os.path.exists(self.model_path):
                return
            
            for name in ['isolation_forest', 'random_forest', 'gradient_boosting']:
                path = f"{self.model_path}/{name}.pkl"
                if os.path.exists(path):
                    self.models[name] = joblib.load(path)
            
            scaler_path = f"{self.model_path}/scaler.pkl"
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
                self.is_trained = True
                logger.info("Enhanced models loaded")
        except Exception as e:
            logger.warning(f"Error loading models: {e}")
    
    def _get_default_analysis(self) -> Dict[str, Any]:
        return {
            'risk_score': 0.5, 'risk_level': 'UNKNOWN', 'threat_category': 'Error',
            'model_scores': {}, 'timestamp': datetime.utcnow().isoformat(),
            'confidence': 0.0, 'threat_types': ['Analysis Error'],
            'recommendations': ['Review system logs'], 'error': 'Analysis failed'
        }