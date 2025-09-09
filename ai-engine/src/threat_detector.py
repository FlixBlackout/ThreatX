import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Model, Sequential
from tensorflow.keras.layers import Dense, Input
from tensorflow.keras.optimizers import Adam
import joblib
import os
import logging
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional

from config import Config

logger = logging.getLogger(__name__)

class ThreatDetector:
    """
    Main threat detection engine using multiple ML models
    """
    
    def __init__(self):
        self.models = {}
        self.scaler = StandardScaler()
        self.is_trained = False
        self.model_path = './models/'
        
        # Risk thresholds
        self.risk_thresholds = {
            'low': 0.3,
            'medium': 0.6,
            'high': 0.8
        }
        
        # Initialize models
        self._initialize_models()
        self._load_models()
    
    def _initialize_models(self):
        """Initialize ML models"""
        try:
            # Isolation Forest for anomaly detection
            self.models['isolation_forest'] = IsolationForest(
                contamination=Config.ANOMALY_THRESHOLD,
                random_state=42,
                n_estimators=100
            )
            
            # Random Forest for classification
            self.models['random_forest'] = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                max_depth=10
            )
            
            # Autoencoder for deep anomaly detection
            self.models['autoencoder'] = self._create_autoencoder()
            
            logger.info("ML models initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing models: {str(e)}")
            raise
    
    def _create_autoencoder(self, input_dim: int = 14) -> Model:
        """Create autoencoder model for anomaly detection"""
        # Encoder
        input_layer = Input(shape=(input_dim,))
        encoded = Dense(8, activation='relu')(input_layer)
        encoded = Dense(4, activation='relu')(encoded)
        
        # Decoder
        decoded = Dense(8, activation='relu')(encoded)
        decoded = Dense(input_dim, activation='sigmoid')(decoded)
        
        # Autoencoder
        autoencoder = Model(input_layer, decoded)
        autoencoder.compile(optimizer=Adam(learning_rate=0.001), loss='mse')
        
        return autoencoder
    
    def analyze(self, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Analyze features and detect threats
        
        Args:
            features: Processed feature dictionary
            
        Returns:
            Threat analysis results
        """
        try:
            # Convert features to array
            feature_array = self._dict_to_array(features)
            
            if not self.is_trained:
                # Use simple heuristic rules if models aren't trained
                return self._heuristic_analysis(features)
            
            # Scale features
            feature_scaled = self.scaler.transform([feature_array])
            
            # Get predictions from each model
            predictions = self._get_model_predictions(feature_scaled)
            
            # Combine predictions into final risk assessment
            risk_assessment = self._combine_predictions(predictions, features)
            
            return risk_assessment
            
        except Exception as e:
            logger.error(f"Error in threat analysis: {str(e)}")
            return self._get_default_analysis()
    
    def _dict_to_array(self, features: Dict[str, float]) -> np.ndarray:
        """Convert feature dictionary to numpy array"""
        # Expected feature order
        feature_order = [
            'hour_of_day', 'day_of_week', 'is_weekend',
            'login_attempts_last_hour', 'login_attempts_last_day',
            'ip_reputation_score', 'is_private_ip', 'country_risk_score',
            'user_session_count', 'bytes_transferred', 'unique_endpoints_accessed',
            'failed_login_ratio', 'geographic_anomaly', 'time_since_last_activity'
        ]
        
        return np.array([features.get(key, 0.0) for key in feature_order])
    
    def _get_model_predictions(self, feature_scaled: np.ndarray) -> Dict[str, float]:
        """Get predictions from all models"""
        predictions = {}
        
        try:
            # Isolation Forest (anomaly score)
            iso_score = self.models['isolation_forest'].decision_function(feature_scaled)[0]
            # Convert to 0-1 scale (higher = more anomalous)
            predictions['isolation_forest'] = max(0, (1 - iso_score) / 2)
            
            # Random Forest (if trained with labels)
            if hasattr(self.models['random_forest'], 'predict_proba'):
                rf_proba = self.models['random_forest'].predict_proba(feature_scaled)
                predictions['random_forest'] = rf_proba[0][1] if rf_proba.shape[1] > 1 else 0.5
            else:
                predictions['random_forest'] = 0.5
            
            # Autoencoder (reconstruction error)
            reconstruction = self.models['autoencoder'].predict(feature_scaled, verbose=0)
            mse = np.mean((feature_scaled - reconstruction) ** 2)
            # Normalize reconstruction error (higher = more anomalous)
            predictions['autoencoder'] = min(1.0, mse * 10)
            
        except Exception as e:
            logger.warning(f"Error getting model predictions: {str(e)}")
            predictions = {
                'isolation_forest': 0.5,
                'random_forest': 0.5,
                'autoencoder': 0.5
            }
        
        return predictions
    
    def _combine_predictions(self, predictions: Dict[str, float], features: Dict[str, float]) -> Dict[str, Any]:
        """Combine model predictions into final risk assessment"""
        
        # Weighted average of model predictions
        weights = {
            'isolation_forest': 0.4,
            'random_forest': 0.3,
            'autoencoder': 0.3
        }
        
        combined_score = sum(
            predictions[model] * weight 
            for model, weight in weights.items()
            if model in predictions
        )
        
        # Apply feature-based adjustments
        combined_score = self._apply_feature_adjustments(combined_score, features)
        
        # Determine risk level
        risk_level = self._get_risk_level(combined_score)
        
        # Generate detailed analysis
        analysis = {
            'risk_score': round(combined_score, 3),
            'risk_level': risk_level,
            'model_scores': predictions,
            'timestamp': datetime.utcnow().isoformat(),
            'confidence': self._calculate_confidence(predictions),
            'threat_types': self._identify_threat_types(features, combined_score),
            'recommendations': self._generate_recommendations(risk_level, features)
        }
        
        return analysis
    
    def _apply_feature_adjustments(self, base_score: float, features: Dict[str, float]) -> float:
        """Apply rule-based adjustments based on specific features"""
        adjusted_score = base_score
        
        # High failed login ratio
        if features.get('failed_login_ratio', 0) > 0.5:
            adjusted_score += 0.2
        
        # Suspicious IP reputation
        if features.get('ip_reputation_score', 0.5) < 0.3:
            adjusted_score += 0.15
        
        # High country risk
        if features.get('country_risk_score', 0.5) > 0.7:
            adjusted_score += 0.1
        
        # Unusual time access
        hour = features.get('hour_of_day', 12)
        if hour < 6 or hour > 22:  # Outside business hours
            adjusted_score += 0.05
        
        # Multiple login attempts
        if features.get('login_attempts_last_hour', 1) > 10:
            adjusted_score += 0.15
        
        # Geographic anomaly
        if features.get('geographic_anomaly', 0) > 0.5:
            adjusted_score += 0.1
        
        return min(1.0, adjusted_score)
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Determine risk level from score"""
        if risk_score >= self.risk_thresholds['high']:
            return 'HIGH'
        elif risk_score >= self.risk_thresholds['medium']:
            return 'MEDIUM'
        elif risk_score >= self.risk_thresholds['low']:
            return 'LOW'
        else:
            return 'NORMAL'
    
    def _calculate_confidence(self, predictions: Dict[str, float]) -> float:
        """Calculate confidence in the prediction"""
        # Higher agreement between models = higher confidence
        scores = list(predictions.values())
        if len(scores) < 2:
            return 0.5
        
        # Calculate standard deviation (lower = more agreement)
        std = np.std(scores)
        confidence = max(0.1, 1.0 - std)
        
        return round(confidence, 3)
    
    def _identify_threat_types(self, features: Dict[str, float], risk_score: float) -> List[str]:
        """Identify specific threat types based on features"""
        threats = []
        
        if features.get('failed_login_ratio', 0) > 0.3:
            threats.append('Brute Force Attack')
        
        if features.get('login_attempts_last_hour', 1) > 20:
            threats.append('Credential Stuffing')
        
        if features.get('ip_reputation_score', 0.5) < 0.2:
            threats.append('Malicious IP')
        
        if features.get('geographic_anomaly', 0) > 0.7:
            threats.append('Geographic Anomaly')
        
        if features.get('bytes_transferred', 0) > 1000000:  # >1MB
            threats.append('Data Exfiltration')
        
        if risk_score > 0.8 and not threats:
            threats.append('Unknown Anomaly')
        
        return threats
    
    def _generate_recommendations(self, risk_level: str, features: Dict[str, float]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if risk_level in ['HIGH', 'MEDIUM']:
            recommendations.append('Monitor user activity closely')
            
            if features.get('failed_login_ratio', 0) > 0.3:
                recommendations.append('Consider temporary account lockout')
            
            if features.get('ip_reputation_score', 0.5) < 0.3:
                recommendations.append('Block or rate-limit IP address')
            
            if features.get('geographic_anomaly', 0) > 0.5:
                recommendations.append('Verify user identity via secondary authentication')
        
        if risk_level == 'HIGH':
            recommendations.append('Alert security team immediately')
            recommendations.append('Consider session termination')
        
        return recommendations
    
    def _heuristic_analysis(self, features: Dict[str, float]) -> Dict[str, Any]:
        """Fallback heuristic analysis when models aren't trained"""
        risk_score = 0.0
        
        # Simple rule-based scoring
        if features.get('failed_login_ratio', 0) > 0.5:
            risk_score += 0.4
        
        if features.get('ip_reputation_score', 0.5) < 0.3:
            risk_score += 0.3
        
        if features.get('login_attempts_last_hour', 1) > 10:
            risk_score += 0.2
        
        if features.get('country_risk_score', 0.5) > 0.7:
            risk_score += 0.1
        
        risk_level = self._get_risk_level(risk_score)
        
        return {
            'risk_score': round(risk_score, 3),
            'risk_level': risk_level,
            'model_scores': {'heuristic': risk_score},
            'timestamp': datetime.utcnow().isoformat(),
            'confidence': 0.6,
            'threat_types': self._identify_threat_types(features, risk_score),
            'recommendations': self._generate_recommendations(risk_level, features),
            'note': 'Analysis based on heuristic rules (models not trained)'
        }
    
    def train_models(self, training_data: pd.DataFrame, labels: Optional[np.ndarray] = None):
        """Train ML models with historical data"""
        try:
            logger.info("Starting model training...")
            
            # Fit scaler
            self.scaler.fit(training_data)
            scaled_data = self.scaler.transform(training_data)
            
            # Train Isolation Forest (unsupervised)
            self.models['isolation_forest'].fit(scaled_data)
            
            # Train Random Forest (supervised, if labels available)
            if labels is not None:
                self.models['random_forest'].fit(scaled_data, labels)
            
            # Train Autoencoder (unsupervised)
            self.models['autoencoder'].fit(
                scaled_data, scaled_data,
                epochs=50,
                batch_size=32,
                shuffle=True,
                verbose=0
            )
            
            self.is_trained = True
            self._save_models()
            
            logger.info("Model training completed successfully")
            
        except Exception as e:
            logger.error(f"Error training models: {str(e)}")
            raise
    
    def _save_models(self):
        """Save trained models to disk"""
        try:
            os.makedirs(self.model_path, exist_ok=True)
            
            # Save sklearn models
            joblib.dump(self.models['isolation_forest'], f"{self.model_path}/isolation_forest.pkl")
            joblib.dump(self.models['random_forest'], f"{self.model_path}/random_forest.pkl")
            joblib.dump(self.scaler, f"{self.model_path}/scaler.pkl")
            
            # Save Keras model
            self.models['autoencoder'].save(f"{self.model_path}/autoencoder.h5")
            
            logger.info("Models saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving models: {str(e)}")
    
    def _load_models(self):
        """Load trained models from disk"""
        try:
            if not os.path.exists(self.model_path):
                logger.info("No saved models found, using untrained models")
                return
            
            # Load sklearn models
            if os.path.exists(f"{self.model_path}/isolation_forest.pkl"):
                self.models['isolation_forest'] = joblib.load(f"{self.model_path}/isolation_forest.pkl")
            
            if os.path.exists(f"{self.model_path}/random_forest.pkl"):
                self.models['random_forest'] = joblib.load(f"{self.model_path}/random_forest.pkl")
            
            if os.path.exists(f"{self.model_path}/scaler.pkl"):
                self.scaler = joblib.load(f"{self.model_path}/scaler.pkl")
            
            # Load Keras model
            if os.path.exists(f"{self.model_path}/autoencoder.h5"):
                from tensorflow.keras.models import load_model
                self.models['autoencoder'] = load_model(f"{self.model_path}/autoencoder.h5")
            
            self.is_trained = True
            logger.info("Models loaded successfully")
            
        except Exception as e:
            logger.warning(f"Error loading models: {str(e)}")
            self.is_trained = False
    
    def retrain_models(self):
        """Retrain models with new data (called by scheduler)"""
        # In production, this would fetch new training data from database
        logger.info("Model retraining triggered (placeholder implementation)")
        # Implementation would go here
    
    def _get_default_analysis(self) -> Dict[str, Any]:
        """Return default analysis when error occurs"""
        return {
            'risk_score': 0.5,
            'risk_level': 'UNKNOWN',
            'model_scores': {},
            'timestamp': datetime.utcnow().isoformat(),
            'confidence': 0.0,
            'threat_types': ['Analysis Error'],
            'recommendations': ['Review system logs', 'Contact administrator'],
            'error': 'Failed to analyze threat'
        }