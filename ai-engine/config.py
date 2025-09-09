import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    """Application configuration class"""
    
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Database configuration
    DATABASE_URL = os.environ.get('DATABASE_URL') or 'postgresql://threatx:password@localhost:5432/threatx_db'
    
    # ML Model configuration
    MODEL_UPDATE_INTERVAL = int(os.environ.get('MODEL_UPDATE_INTERVAL', '7'))  # days
    ANOMALY_THRESHOLD = float(os.environ.get('ANOMALY_THRESHOLD', '0.1'))
    
    # API configuration
    API_HOST = os.environ.get('API_HOST', '0.0.0.0')
    API_PORT = int(os.environ.get('API_PORT', '5000'))
    
    # Security configuration
    MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', '5'))
    SUSPICIOUS_IP_THRESHOLD = int(os.environ.get('SUSPICIOUS_IP_THRESHOLD', '10'))
    
    # GeoIP configuration
    GEOIP_DATABASE_PATH = os.environ.get('GEOIP_DATABASE_PATH', './data/GeoLite2-City.mmdb')
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'logs/threatx.log')