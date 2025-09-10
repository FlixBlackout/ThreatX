import pandas as pd
import numpy as np
import re
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)

class DataPreprocessor:
    """
    Preprocesses raw log data into structured features for ML models
    """
    
    def __init__(self):
        self.feature_columns = [
            'hour_of_day', 'day_of_week', 'is_weekend',
            'login_attempts_last_hour', 'login_attempts_last_day',
            'ip_reputation_score', 'is_private_ip', 'country_risk_score',
            'user_session_count', 'bytes_transferred', 'unique_endpoints_accessed',
            'failed_login_ratio', 'geographic_anomaly', 'time_since_last_activity'
        ]
        
        # Initialize IP reputation cache
        self.ip_reputation_cache = {}
        
        # Country risk scores (simplified - in production, use threat intelligence feeds)
        self.country_risk_scores = {
            'US': 0.1, 'CA': 0.1, 'GB': 0.1, 'DE': 0.1, 'FR': 0.1,
            'CN': 0.7, 'RU': 0.8, 'KP': 0.9, 'IR': 0.8, 'SY': 0.8,
            'Unknown': 0.5
        }
    
    def process_log_entry(self, log_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Process a single log entry into ML features
        
        Args:
            log_data: Raw log data dictionary
            
        Returns:
            Dictionary of processed features
        """
        try:
            features = {}
            
            # Extract timestamp features
            timestamp = self._parse_timestamp(log_data.get('timestamp', datetime.utcnow()))
            features.update(self._extract_time_features(timestamp))
            
            # Extract IP-based features
            ip_address = log_data.get('ip_address', '127.0.0.1')
            features.update(self._extract_ip_features(ip_address))
            
            # Extract user behavior features
            user_id = log_data.get('user_id')
            features.update(self._extract_user_features(user_id, log_data))
            
            # Extract network features
            features.update(self._extract_network_features(log_data))
            
            # Extract authentication features
            features.update(self._extract_auth_features(log_data))
            
            logger.debug(f"Processed features for log entry: {features}")
            return features
            
        except Exception as e:
            logger.error(f"Error processing log entry: {str(e)}")
            return self._get_default_features()
    
    def process_batch(self, log_batch: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Process a batch of log entries
        
        Args:
            log_batch: List of log entry dictionaries
            
        Returns:
            DataFrame with processed features
        """
        processed_entries = []
        for log_entry in log_batch:
            features = self.process_log_entry(log_entry)
            processed_entries.append(features)
        
        # Handle empty batch case
        if not processed_entries:
            # Create empty DataFrame with correct columns
            df = pd.DataFrame({col: [] for col in self.feature_columns})
        else:
            # Create DataFrame ensuring it's always a DataFrame, not Series
            df = pd.DataFrame(processed_entries)
            
            # Ensure all required columns are present
            for col in self.feature_columns:
                if col not in df.columns:
                    df[col] = 0.0
        
        # Return as DataFrame with correct column order, ensuring it's always a DataFrame
        result = df[self.feature_columns].copy()
        # Ensure result is always a DataFrame (not Series) by checking type and converting if needed
        if isinstance(result, pd.Series):
            result = result.to_frame().T
        elif not isinstance(result, pd.DataFrame):
            result = pd.DataFrame(result)
        return result
    
    def _parse_timestamp(self, timestamp) -> datetime:
        """Parse timestamp from various formats"""
        if isinstance(timestamp, datetime):
            return timestamp
        elif isinstance(timestamp, str):
            try:
                # Try ISO format first
                return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                # Try common log formats
                formats = [
                    '%Y-%m-%d %H:%M:%S',
                    '%Y-%m-%d %H:%M:%S.%f',
                    '%d/%b/%Y:%H:%M:%S %z'
                ]
                for fmt in formats:
                    try:
                        return datetime.strptime(timestamp, fmt)
                    except:
                        continue
        
        # Default to current time if parsing fails
        return datetime.utcnow()
    
    def _extract_time_features(self, timestamp: datetime) -> Dict[str, float]:
        """Extract time-based features"""
        return {
            'hour_of_day': float(timestamp.hour),
            'day_of_week': float(timestamp.weekday()),
            'is_weekend': float(timestamp.weekday() >= 5)
        }
    
    def _extract_ip_features(self, ip_address: str) -> Dict[str, float]:
        """Extract IP-based features"""
        features = {
            'ip_reputation_score': 0.5,  # Default neutral score
            'is_private_ip': 0.0,
            'country_risk_score': 0.5
        }
        
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Check if private IP
            features['is_private_ip'] = float(ip.is_private)
            
            # Get IP reputation (cached or lookup)
            features['ip_reputation_score'] = self._get_ip_reputation(ip_address)
            
            # Get country risk score (would use GeoIP in production)
            country = self._get_ip_country(ip_address)
            features['country_risk_score'] = self.country_risk_scores.get(country, 0.5)
            
        except Exception as e:
            logger.warning(f"Error processing IP {ip_address}: {str(e)}")
        
        return features
    
    def _extract_user_features(self, user_id: Optional[str], log_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract user behavior features"""
        features = {
            'user_session_count': 1.0,
            'failed_login_ratio': 0.0,
            'time_since_last_activity': 0.0
        }
        
        if user_id:
            # In production, these would query the database
            # For now, extract from current log entry
            features['user_session_count'] = float(log_data.get('session_count', 1))
            
            # Calculate failed login ratio
            total_attempts = log_data.get('total_login_attempts', 1)
            failed_attempts = log_data.get('failed_login_attempts', 0)
            features['failed_login_ratio'] = failed_attempts / max(total_attempts, 1)
            
            # Time since last activity (in hours)
            last_activity = log_data.get('last_activity_time')
            if last_activity:
                last_time = self._parse_timestamp(last_activity)
                current_time = self._parse_timestamp(log_data.get('timestamp', datetime.utcnow()))
                features['time_since_last_activity'] = (current_time - last_time).total_seconds() / 3600
        
        return features
    
    def _extract_network_features(self, log_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract network-related features"""
        return {
            'bytes_transferred': float(log_data.get('bytes_transferred', 0)),
            'unique_endpoints_accessed': float(log_data.get('unique_endpoints', 1)),
            'geographic_anomaly': float(log_data.get('geographic_anomaly', 0))
        }
    
    def _extract_auth_features(self, log_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract authentication-related features"""
        features = {
            'login_attempts_last_hour': 1.0,
            'login_attempts_last_day': 1.0
        }
        
        # These would typically query a database for historical data
        features['login_attempts_last_hour'] = float(log_data.get('login_attempts_1h', 1))
        features['login_attempts_last_day'] = float(log_data.get('login_attempts_24h', 1))
        
        return features
    
    def _get_ip_reputation(self, ip_address: str) -> float:
        """Get IP reputation score (0.0 = malicious, 1.0 = trusted)"""
        if ip_address in self.ip_reputation_cache:
            return self.ip_reputation_cache[ip_address]
        
        # In production, this would query threat intelligence APIs
        # For now, simulate based on IP patterns
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Private IPs get higher trust
            if ip.is_private:
                score = 0.8
            # Common cloud provider ranges get medium trust
            elif str(ip).startswith(('52.', '54.', '34.', '35.')):  # AWS, GCP examples
                score = 0.6
            # Unknown IPs get lower trust
            else:
                score = 0.4
            
            self.ip_reputation_cache[ip_address] = score
            return score
            
        except:
            return 0.5  # Default neutral score
    
    def _get_ip_country(self, ip_address: str) -> str:
        """Get country for IP address"""
        # In production, use GeoIP2 database
        # For now, return Unknown
        return 'Unknown'
    
    def _get_default_features(self) -> Dict[str, float]:
        """Return default features when processing fails"""
        return {col: 0.0 for col in self.feature_columns}