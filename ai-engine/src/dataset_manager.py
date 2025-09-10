#!/usr/bin/env python3
"""
ThreatX Dataset Manager
Handles loading and preprocessing of cybersecurity datasets (NSL-KDD, CICIDS)
"""

import pandas as pd
import numpy as np
import logging
import os
import requests
import zipfile
import pickle
from typing import Dict, List, Tuple, Any, Optional
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import joblib

logger = logging.getLogger(__name__)

class DatasetManager:
    """Manages cybersecurity datasets for threat detection training"""
    
    def __init__(self, data_dir: str = "datasets"):
        self.data_dir = data_dir
        self.datasets = {}
        self.preprocessors = {}
        self.label_encoders = {}
        
        # Create datasets directory
        os.makedirs(data_dir, exist_ok=True)
        
        # Dataset configurations
        self.dataset_configs = {
            'nsl_kdd': {
                'train_url': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt',
                'test_url': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt',
                'columns': [
                    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
                    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
                    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
                    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
                    'num_access_files', 'num_outbound_cmds', 'is_host_login',
                    'is_guest_login', 'count', 'srv_count', 'serror_rate',
                    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
                    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
                    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
                    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
                    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
                    'dst_host_srv_rerror_rate', 'attack_type', 'difficulty'
                ],
                'target_column': 'attack_type',
                'attack_categories': {
                    'normal': 'Normal',
                    'dos': ['apache2', 'back', 'land', 'neptune', 'mailbomb', 'pod', 'processtable', 'smurf', 'teardrop', 'udpstorm'],
                    'probe': ['ipsweep', 'mscan', 'nmap', 'portsweep', 'saint', 'satan'],
                    'r2l': ['ftp_write', 'guess_passwd', 'imap', 'multihop', 'named', 'phf', 'sendmail', 'snmpgetattack', 'snmpguess', 'worm', 'xlock', 'xsnoop'],
                    'u2r': ['buffer_overflow', 'httptunnel', 'loadmodule', 'perl', 'ps', 'rootkit', 'sqlattack', 'xterm']
                }
            }
        }
    
    def download_dataset(self, dataset_name: str) -> bool:
        """Download dataset if not exists"""
        try:
            if dataset_name == 'nsl_kdd':
                return self._download_nsl_kdd()
            elif dataset_name == 'cicids':
                logger.warning("CICIDS dataset requires manual download due to size. Please download from: https://www.unb.ca/cic/datasets/ids-2017.html")
                return False
            else:
                logger.error(f"Unknown dataset: {dataset_name}")
                return False
        except Exception as e:
            logger.error(f"Error downloading dataset {dataset_name}: {e}")
            return False
    
    def _download_nsl_kdd(self) -> bool:
        """Download NSL-KDD dataset"""
        try:
            config = self.dataset_configs['nsl_kdd']
            
            # Download training data
            train_path = os.path.join(self.data_dir, 'nsl_kdd_train.txt')
            if not os.path.exists(train_path):
                logger.info("Downloading NSL-KDD training data...")
                response = requests.get(config['train_url'])
                response.raise_for_status()
                with open(train_path, 'w') as f:
                    f.write(response.text)
            
            # Download test data
            test_path = os.path.join(self.data_dir, 'nsl_kdd_test.txt')
            if not os.path.exists(test_path):
                logger.info("Downloading NSL-KDD test data...")
                response = requests.get(config['test_url'])
                response.raise_for_status()
                with open(test_path, 'w') as f:
                    f.write(response.text)
            
            logger.info("NSL-KDD dataset downloaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error downloading NSL-KDD: {e}")
            return False
    
    def load_nsl_kdd(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Load and preprocess NSL-KDD dataset"""
        try:
            config = self.dataset_configs['nsl_kdd']
            
            # Load training data
            train_path = os.path.join(self.data_dir, 'nsl_kdd_train.txt')
            test_path = os.path.join(self.data_dir, 'nsl_kdd_test.txt')
            
            if not os.path.exists(train_path) or not os.path.exists(test_path):
                logger.info("Dataset files not found, downloading...")
                if not self.download_dataset('nsl_kdd'):
                    raise Exception("Failed to download NSL-KDD dataset")
            
            # Read datasets
            train_df = pd.read_csv(train_path, names=config['columns'])
            test_df = pd.read_csv(test_path, names=config['columns'])
            
            # Preprocess datasets
            train_df = self._preprocess_nsl_kdd(train_df)
            test_df = self._preprocess_nsl_kdd(test_df)
            
            self.datasets['nsl_kdd'] = {
                'train': train_df,
                'test': test_df,
                'config': config
            }
            
            logger.info(f"NSL-KDD dataset loaded: {len(train_df)} training samples, {len(test_df)} test samples")
            return train_df, test_df
            
        except Exception as e:
            logger.error(f"Error loading NSL-KDD dataset: {e}")
            raise
    
    def _preprocess_nsl_kdd(self, df: pd.DataFrame) -> pd.DataFrame:
        """Preprocess NSL-KDD dataset"""
        try:
            # Remove difficulty column if exists
            if 'difficulty' in df.columns:
                df = df.drop('difficulty', axis=1)
            
            # Map attack types to categories
            config = self.dataset_configs['nsl_kdd']
            attack_categories = config['attack_categories']
            
            def categorize_attack(attack_type):
                attack_type = attack_type.strip()
                if attack_type == 'normal':
                    return 'normal'
                for category, attacks in attack_categories.items():
                    if category != 'normal' and attack_type in attacks:
                        return category
                return 'unknown'
            
            df['attack_category'] = df['attack_type'].apply(categorize_attack)
            
            # Handle categorical variables
            categorical_cols = ['protocol_type', 'service', 'flag']
            for col in categorical_cols:
                if col not in self.label_encoders:
                    self.label_encoders[col] = LabelEncoder()
                    df[col] = self.label_encoders[col].fit_transform(df[col].astype(str))
                else:
                    # Handle unseen categories
                    df[col] = df[col].astype(str)
                    mask = df[col].isin(self.label_encoders[col].classes_)
                    df.loc[~mask, col] = 'unknown'
                    
                    # Add unknown class if not exists
                    if 'unknown' not in self.label_encoders[col].classes_:
                        self.label_encoders[col].classes_ = np.append(self.label_encoders[col].classes_, 'unknown')
                    
                    df[col] = self.label_encoders[col].transform(df[col])
            
            # Create binary labels for anomaly detection
            df['is_attack'] = (df['attack_category'] != 'normal').astype(int)
            
            # Create risk scores based on attack category
            risk_mapping: Dict[str, float] = {
                'normal': 0.1,
                'probe': 0.3,
                'dos': 0.7,
                'r2l': 0.8,
                'u2r': 0.9,
                'unknown': 0.5
            }
            df['risk_score'] = df['attack_category'].map(lambda x: risk_mapping.get(x, 0.5))
            
            return df
            
        except Exception as e:
            logger.error(f"Error preprocessing NSL-KDD data: {e}")
            raise
    
    def load_cicids_sample(self) -> Optional[pd.DataFrame]:
        """Load CICIDS sample data (if available)"""
        try:
            # Check for CICIDS files in datasets directory
            cicids_files = [f for f in os.listdir(self.data_dir) if 'cicids' in f.lower() and f.endswith('.csv')]
            
            if not cicids_files:
                logger.warning("No CICIDS dataset files found. Please download from: https://www.unb.ca/cic/datasets/ids-2017.html")
                return None
            
            # Load first available file as sample
            sample_file = os.path.join(self.data_dir, cicids_files[0])
            df = pd.read_csv(sample_file)
            
            # Basic preprocessing for CICIDS
            df = self._preprocess_cicids(df)
            
            logger.info(f"CICIDS sample loaded: {len(df)} samples from {cicids_files[0]}")
            return df
            
        except Exception as e:
            logger.error(f"Error loading CICIDS data: {e}")
            return None
    
    def _preprocess_cicids(self, df: pd.DataFrame) -> pd.DataFrame:
        """Preprocess CICIDS dataset"""
        try:
            # Common CICIDS preprocessing
            
            # Handle infinite values
            df = df.replace([np.inf, -np.inf], np.nan)
            df = df.fillna(0)
            
            # Identify label column (usually 'Label' or similar)
            label_columns = [col for col in df.columns if 'label' in col.lower()]
            if label_columns:
                label_col = label_columns[0]
                df['attack_type'] = df[label_col]
                
                # Create binary labels
                df['is_attack'] = (df[label_col].str.lower() != 'benign').astype(int)
                
                # Create risk scores
                unique_attacks = df[label_col].unique()
                risk_mapping: Dict[str, float] = {}
                for attack in unique_attacks:
                    if 'benign' in attack.lower():
                        risk_mapping[attack] = 0.1
                    elif any(x in attack.lower() for x in ['ddos', 'dos']):
                        risk_mapping[attack] = 0.8
                    elif 'brute' in attack.lower():
                        risk_mapping[attack] = 0.7
                    elif 'bot' in attack.lower():
                        risk_mapping[attack] = 0.9
                    else:
                        risk_mapping[attack] = 0.6
                
                df['risk_score'] = df[label_col].map(lambda x: risk_mapping.get(x, 0.6))
            
            return df
            
        except Exception as e:
            logger.error(f"Error preprocessing CICIDS data: {e}")
            raise
    
    def get_training_data(self, dataset_name: str = 'nsl_kdd') -> Tuple[np.ndarray, np.ndarray]:
        """Get preprocessed training data for ML models"""
        try:
            if dataset_name == 'nsl_kdd':
                if 'nsl_kdd' not in self.datasets:
                    self.load_nsl_kdd()
                
                df = self.datasets['nsl_kdd']['train']
                
                # Select feature columns (exclude target and derived columns)
                feature_cols = [col for col in df.columns if col not in 
                               ['attack_type', 'attack_category', 'is_attack', 'risk_score']]
                
                X = df[feature_cols].values
                y = df['risk_score'].values
                
                # Scale features
                if 'nsl_kdd_scaler' not in self.preprocessors:
                    self.preprocessors['nsl_kdd_scaler'] = StandardScaler()
                    X = self.preprocessors['nsl_kdd_scaler'].fit_transform(X)
                else:
                    X = self.preprocessors['nsl_kdd_scaler'].transform(X)
                
                return X, y
                
            else:
                raise ValueError(f"Dataset {dataset_name} not supported")
                
        except Exception as e:
            logger.error(f"Error getting training data: {e}")
            raise
    
    def save_preprocessors(self, filepath: str):
        """Save preprocessors and encoders"""
        try:
            data = {
                'preprocessors': self.preprocessors,
                'label_encoders': self.label_encoders
            }
            joblib.dump(data, filepath)
            logger.info(f"Preprocessors saved to {filepath}")
        except Exception as e:
            logger.error(f"Error saving preprocessors: {e}")
    
    def load_preprocessors(self, filepath: str):
        """Load preprocessors and encoders"""
        try:
            if os.path.exists(filepath):
                data = joblib.load(filepath)
                self.preprocessors = data.get('preprocessors', {})
                self.label_encoders = data.get('label_encoders', {})
                logger.info(f"Preprocessors loaded from {filepath}")
            else:
                logger.warning(f"Preprocessor file not found: {filepath}")
        except Exception as e:
            logger.error(f"Error loading preprocessors: {e}")
    
    def get_sample_features(self, log_data: Dict[str, Any]) -> np.ndarray:
        """Convert log data to feature vector for prediction with comprehensive NSL-KDD mapping"""
        try:
            # NSL-KDD has 41 features - create comprehensive mapping
            features = np.zeros(41)
            
            # 0: duration - Connection duration in seconds
            features[0] = log_data.get('duration', 1)
            
            # 1: protocol_type - Encoded as: tcp=2, udp=1, icmp=0
            protocol_map = {'tcp': 2, 'udp': 1, 'icmp': 0}
            features[1] = protocol_map.get(log_data.get('protocol', 'tcp'), 2)
            
            # 2: service - Encoded service type (simplified mapping)
            service_map = {
                'http': 28, 'ftp': 14, 'ssh': 59, 'smtp': 56, 'dns': 11,
                'login': 35, 'telnet': 62, 'pop3': 44, 'imap': 29, 'unknown': 0
            }
            event_type = log_data.get('event_type', 'http')
            features[2] = service_map.get(event_type, service_map.get('unknown', 0))
            
            # 3: flag - Connection status (simplified)
            flag_map = {'SF': 10, 'S0': 0, 'REJ': 5, 'RSTR': 6, 'SH': 9}
            if log_data.get('failed_login_attempts', 0) > 0:
                features[3] = flag_map['REJ']  # Rejected
            elif log_data.get('connection_count', 1) > 1000:
                features[3] = flag_map['S0']   # No response
            else:
                features[3] = flag_map['SF']   # Normal
            
            # 4: src_bytes - Source bytes
            features[4] = log_data.get('bytes_transferred', 0) / 2  # Split between src/dst
            
            # 5: dst_bytes - Destination bytes
            features[5] = log_data.get('bytes_transferred', 0) / 2
            
            # 6: land - 1 if connection is from/to same host/port
            features[6] = 1 if log_data.get('same_host_connection', False) else 0
            
            # 7: wrong_fragment - Number of wrong fragments
            features[7] = log_data.get('wrong_fragments', 0)
            
            # 8: urgent - Number of urgent packets
            features[8] = log_data.get('urgent_packets', 0)
            
            # 9: hot - Number of hot indicators
            hot_indicators = 0
            if log_data.get('admin_escalation_attempt', False): hot_indicators += 1
            if log_data.get('privilege_escalation', False): hot_indicators += 1
            if log_data.get('root_access_attempt', False): hot_indicators += 1
            features[9] = hot_indicators
            
            # 10: num_failed_logins - Number of failed login attempts
            features[10] = log_data.get('failed_login_attempts', 0)
            
            # 11: logged_in - 1 if successfully logged in
            features[11] = 1 if log_data.get('failed_login_attempts', 0) == 0 and log_data.get('event_type') == 'login' else 0
            
            # 12: num_compromised - Number of compromised conditions
            compromised = 0
            if log_data.get('privilege_escalation', False): compromised += 1
            if log_data.get('malformed_packets', False): compromised += 1
            if log_data.get('protocol_violation', False): compromised += 1
            features[12] = compromised
            
            # 13: root_shell - 1 if root shell obtained
            features[13] = 1 if log_data.get('root_access_attempt', False) else 0
            
            # 14: su_attempted - 1 if su root attempted
            features[14] = 1 if log_data.get('privilege_escalation', False) else 0
            
            # 15: num_root - Number of root accesses
            features[15] = 1 if log_data.get('root_access_attempt', False) else 0
            
            # 16: num_file_creations - Number of file creation operations
            features[16] = log_data.get('file_creations', 0)
            
            # 17: num_shells - Number of shell prompts
            features[17] = 1 if log_data.get('shell_access', False) else 0
            
            # 18: num_access_files - Number of operations on access control files
            features[18] = log_data.get('access_file_operations', 0)
            
            # 19: num_outbound_cmds - Number of outbound commands
            features[19] = log_data.get('outbound_commands', 0)
            
            # 20: is_host_login - 1 if login belongs to host list
            features[20] = 1 if log_data.get('host_login', False) else 0
            
            # 21: is_guest_login - 1 if login is guest
            features[21] = 1 if log_data.get('user_id', '').lower() in ['guest', 'anonymous'] else 0
            
            # 22: count - Number of connections to same host in past 2 seconds
            features[22] = log_data.get('connection_count', 1)
            
            # 23: srv_count - Number of connections to same service in past 2 seconds
            features[23] = log_data.get('service_connections', 1)
            
            # 24: serror_rate - % of connections with SYN errors
            features[24] = log_data.get('syn_error_rate', 0.0)
            
            # 25: srv_serror_rate - % of connections to same service with SYN errors
            features[25] = log_data.get('service_syn_error_rate', 0.0)
            
            # 26: rerror_rate - % of connections with REJ errors
            features[26] = log_data.get('rejection_error_rate', 0.0)
            
            # 27: srv_rerror_rate - % of connections to same service with REJ errors  
            features[27] = log_data.get('service_rejection_error_rate', 0.0)
            
            # 28: same_srv_rate - % of connections to same service
            features[28] = log_data.get('same_service_rate', 1.0)
            
            # 29: diff_srv_rate - % of connections to different services
            features[29] = log_data.get('different_service_rate', 0.0)
            
            # 30: srv_diff_host_rate - % of connections to different hosts
            features[30] = log_data.get('service_different_host_rate', 0.0)
            
            # 31: dst_host_count - Count of connections to destination host
            features[31] = log_data.get('destination_host_count', 1)
            
            # 32: dst_host_srv_count - Count of connections to destination host/service
            features[32] = log_data.get('destination_host_service_count', 1)
            
            # 33: dst_host_same_srv_rate - % same service on destination host
            features[33] = log_data.get('destination_same_service_rate', 1.0)
            
            # 34: dst_host_diff_srv_rate - % different services on destination host
            features[34] = log_data.get('destination_different_service_rate', 0.0)
            
            # 35: dst_host_same_src_port_rate - % same source port on destination host
            features[35] = log_data.get('destination_same_source_port_rate', 1.0)
            
            # 36: dst_host_srv_diff_host_rate - % different host rate for service
            features[36] = log_data.get('destination_service_different_host_rate', 0.0)
            
            # 37: dst_host_serror_rate - % SYN errors on destination host
            features[37] = log_data.get('destination_syn_error_rate', 0.0)
            
            # 38: dst_host_srv_serror_rate - % SYN errors for service on destination host
            features[38] = log_data.get('destination_service_syn_error_rate', 0.0)
            
            # 39: dst_host_rerror_rate - % REJ errors on destination host
            features[39] = log_data.get('destination_rejection_error_rate', 0.0)
            
            # 40: dst_host_srv_rerror_rate - % REJ errors for service on destination host
            features[40] = log_data.get('destination_service_rejection_error_rate', 0.0)
            
            # Apply intelligent feature derivation based on attack patterns
            self._apply_attack_pattern_features(features, log_data)
            
            # Scale features if scaler is available
            if 'nsl_kdd_scaler' in self.preprocessors:
                features = self.preprocessors['nsl_kdd_scaler'].transform([features])
                return features[0]
            
            return features
            
        except Exception as e:
            logger.error(f"Error creating feature vector: {e}")
            return np.zeros(41)
    
    def _apply_attack_pattern_features(self, features: np.ndarray, log_data: Dict[str, Any]):
        """Apply attack-specific feature derivations based on NSL-KDD patterns"""
        
        event_type = log_data.get('event_type', '')
        
        # DoS attack patterns
        if event_type in ['ddos', 'dos', 'syn_flood', 'flood']:
            features[22] = max(features[22], log_data.get('connection_count', 1000))  # High connection count
            features[4] = max(features[4], 100000)  # High bytes
            features[5] = max(features[5], 100000)
            features[24] = 0.9  # High SYN error rate
            features[26] = 0.8  # High rejection rate
        
        # Probe attack patterns
        elif event_type in ['port_scan', 'probe', 'reconnaissance', 'service_scan']:
            features[22] = log_data.get('unique_endpoints', 50)  # Multiple connection attempts
            features[29] = 0.9  # High different service rate
            features[30] = 0.8  # High different host rate
            features[4] = 100   # Small data packets
            features[5] = 100
            features[3] = 0     # Many failed connections (S0)
        
        # R2L attack patterns (brute force, password attacks)
        elif event_type in ['brute_force', 'password_attack', 'credential_stuffing']:
            features[10] = max(features[10], 10)  # High failed logins
            features[11] = 0   # Not logged in
            features[22] = log_data.get('failed_login_attempts', 20)  # Multiple attempts
            features[3] = 5    # REJ flag
            features[26] = 0.8 # High rejection rate
        
        # U2R attack patterns (privilege escalation)
        elif event_type in ['buffer_overflow', 'privilege_escalation', 'rootkit']:
            features[9] = 3     # High hot indicators
            features[12] = 2    # Compromised conditions
            features[13] = 1    # Root shell obtained
            features[14] = 1    # SU attempted
            features[15] = 1    # Root accesses
            features[17] = 1    # Shell prompts
        
        # Unknown/anomalous patterns
        elif event_type in ['unknown_attack', 'anomaly']:
            # Apply mixed patterns that don't fit standard categories
            features[12] = 1    # Some compromise indicators
            features[7] = 5     # Wrong fragments
            features[8] = 2     # Urgent packets
            if log_data.get('malformed_packets', False):
                features[7] = 10
            if log_data.get('protocol_violation', False):
                features[12] += 1
    
    def get_dataset_stats(self) -> Dict[str, Any]:
        """Get statistics about loaded datasets"""
        stats = {}
        
        for name, dataset in self.datasets.items():
            if name == 'nsl_kdd':
                train_df = dataset['train']
                test_df = dataset['test']
                
                stats[name] = {
                    'train_samples': len(train_df),
                    'test_samples': len(test_df),
                    'features': len([col for col in train_df.columns if col not in 
                                   ['attack_type', 'attack_category', 'is_attack', 'risk_score']]),
                    'attack_distribution': train_df['attack_category'].value_counts().to_dict(),
                    'normal_ratio': (train_df['attack_category'] == 'normal').mean()
                }
        
        return stats

if __name__ == "__main__":
    # Test the dataset manager
    logging.basicConfig(level=logging.INFO)
    
    manager = DatasetManager()
    
    try:
        # Load NSL-KDD dataset
        train_df, test_df = manager.load_nsl_kdd()
        print(f"Loaded NSL-KDD: {len(train_df)} train, {len(test_df)} test samples")
        
        # Get training data
        X, y = manager.get_training_data('nsl_kdd')
        print(f"Training data shape: X={X.shape}, y={y.shape}")
        
        # Show dataset statistics
        stats = manager.get_dataset_stats()
        print("Dataset statistics:", stats)
        
    except Exception as e:
        print(f"Error: {e}")