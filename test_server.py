#!/usr/bin/env python3
"""
ThreatX Test Server - Enhanced Version with Real Dataset Integration
A comprehensive cybersecurity threat detection system using NSL-KDD and CICIDS datasets
"""

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import json
import numpy as np
import logging
import os
import sys
from datetime import datetime, timedelta
import random
from typing import Dict, List, Any
import threading
import time

# Configure logging immediately after imports (before any logger usage)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add the ai-engine source directory to Python path for proper module resolution
# More robust path resolution that works with both runtime and static analysis
current_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in globals() else os.getcwd()
ai_engine_path = os.path.join(current_dir, 'ai-engine', 'src')
ai_engine_root = os.path.join(current_dir, 'ai-engine')

# Add both paths to ensure proper module resolution
for path in [ai_engine_path, ai_engine_root]:
    if os.path.exists(path) and path not in sys.path:
        sys.path.insert(0, path)

# Fallback: try relative path from current working directory
fallback_src_path = os.path.join(os.getcwd(), 'ai-engine', 'src')
fallback_root_path = os.path.join(os.getcwd(), 'ai-engine')
for path in [fallback_src_path, fallback_root_path]:
    if os.path.exists(path) and path not in sys.path:
        sys.path.insert(0, path)

# Initialize EnhancedThreatDetector to None by default
EnhancedThreatDetector = None
ENHANCED_DETECTOR_AVAILABLE = False

try:
    # Primary import strategy: Direct import from src directory
    # This works best with both runtime and static analysis
    # IDE Note: Configure extra paths in pyrightconfig.json for static analysis
    from enhanced_threat_detector import EnhancedThreatDetector
    ENHANCED_DETECTOR_AVAILABLE = True
    logger.info("Enhanced threat detector imported successfully (direct import)")
except ImportError as e:
    try:
        # Fallback: try alternative import methods
        import importlib.util
        import sys
        
        # Dynamic module loading as last resort
        enhanced_detector_path = os.path.join(ai_engine_path, 'enhanced_threat_detector.py')
        if os.path.exists(enhanced_detector_path):
            spec = importlib.util.spec_from_file_location("enhanced_threat_detector", enhanced_detector_path)
            if spec and spec.loader:
                enhanced_module = importlib.util.module_from_spec(spec)
                sys.modules["enhanced_threat_detector"] = enhanced_module
                spec.loader.exec_module(enhanced_module)
                EnhancedThreatDetector = enhanced_module.EnhancedThreatDetector
                ENHANCED_DETECTOR_AVAILABLE = True
            else:
                raise ImportError("Could not create module spec")
        else:
            raise ImportError(f"Enhanced detector file not found at {enhanced_detector_path}")
    except ImportError as fallback_error:
        ENHANCED_DETECTOR_AVAILABLE = False
        EnhancedThreatDetector = None  # Explicitly set to None if import fails
        logging.warning(f"Enhanced threat detector not available: {fallback_error}. Using simple detector.")

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# In-memory database for testing
threat_data = []
user_profiles = {}
suspicious_ips = {}

class AdvancedThreatDetector:
    """Advanced threat detector with dataset integration and enhanced analysis"""
    
    def __init__(self):
        self.risk_thresholds = {
            'low': 0.25,
            'medium': 0.55,
            'high': 0.75
        }
        
        # Initialize enhanced detector if available
        if ENHANCED_DETECTOR_AVAILABLE and EnhancedThreatDetector is not None:
            try:
                self.enhanced_detector = EnhancedThreatDetector(use_datasets=True)  
                self.use_enhanced = True
                logger.info("Enhanced threat detector with dataset integration initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize enhanced detector: {e}")
                self.use_enhanced = False
        else:
            self.use_enhanced = False
        
        # NSL-KDD attack patterns for enhanced detection
        self.attack_patterns = {
            'dos_indicators': ['high_connection_rate', 'bandwidth_exhaustion', 'service_flooding'],
            'probe_indicators': ['port_scanning', 'service_enumeration', 'network_mapping'],
            'r2l_indicators': ['brute_force', 'credential_stuffing', 'password_attack'],
            'u2r_indicators': ['privilege_escalation', 'buffer_overflow', 'root_access']
        }
        
        # Threat intelligence feeds (simulated)
        self.threat_intelligence = {
            'malicious_ips': [
                '185.220.101.5', '91.240.118.172', '104.244.76.187',
                '198.51.100.30', '203.0.113.45', '192.0.2.100'
            ],
            'suspicious_countries': ['CN', 'RU', 'KP', 'IR'],
            'known_attack_signatures': [
                'sql_injection', 'xss_attack', 'command_injection',
                'directory_traversal', 'xxe_attack'
            ]
        }
    
    def analyze(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Advanced threat analysis using enhanced models and dataset intelligence"""
        try:
            # Use enhanced detector if available
            if self.use_enhanced and hasattr(self, 'enhanced_detector'):
                return self.enhanced_detector.analyze(log_data)
            
            # Fallback to enhanced rule-based analysis
            return self._enhanced_rule_analysis(log_data)
            
        except Exception as e:
            logger.error(f"Error in threat analysis: {e}")
            return self._fallback_analysis(log_data)
    
    def _enhanced_rule_analysis(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced rule-based analysis with dataset patterns"""
        risk_score = 0.0
        threat_types = []
        recommendations = []
        threat_category = 'Normal'
        
        # Extract features
        ip_address = log_data.get('ip_address', '')
        failed_logins = log_data.get('failed_login_attempts', 0)
        event_type = log_data.get('event_type', '')
        bytes_transferred = log_data.get('bytes_transferred', 0)
        user_id = log_data.get('user_id', '')
        
        # Enhanced DoS detection (NSL-KDD inspired)
        if self._detect_dos_pattern(log_data):
            risk_score += 0.7  # Increased from 0.4 to 0.7 for DDoS
            threat_types.append('DoS Attack')
            threat_category = 'DoS'
            recommendations.extend(['Implement DDoS protection', 'Activate traffic filtering', 'Monitor bandwidth usage'])
            
            # Add specific DDoS sub-types
            if log_data.get('event_type') == 'ddos':
                threat_types.append('DDoS Attack')
                risk_score += 0.2  # Additional risk for confirmed DDoS
            if log_data.get('bytes_transferred', 0) > 500000000:  # >500MB
                threat_types.append('Bandwidth Exhaustion')
            if log_data.get('connection_count', 0) > 1000:
                threat_types.append('Connection Flood')
        
        # Enhanced Probe detection
        if self._detect_probe_pattern(log_data):
            risk_score += 0.3
            threat_types.append('Network Probe')
            threat_category = 'Probe'
            recommendations.append('Block scanning IP')
        
        # Enhanced R2L detection (Remote-to-Local)
        if self._detect_r2l_pattern(log_data):
            risk_score += 0.5
            threat_types.append('Brute Force Attack')
            threat_category = 'R2L'
            recommendations.append('Enable account lockout')
        
        # Enhanced U2R detection (User-to-Root)
        if self._detect_u2r_pattern(log_data):
            risk_score += 0.6
            threat_types.append('Privilege Escalation')
            threat_category = 'U2R'
            recommendations.append('Audit privilege access')
        
        # Unknown threat detection
        if self._detect_unknown_threat_pattern(log_data):
            risk_score += 0.8
            threat_types.append('Unknown Threat Pattern')
            threat_category = 'Unknown Threat'
            recommendations.extend([
                'CRITICAL: Unknown attack detected',
                'Isolate affected systems immediately',
                'Initiate incident response protocol'
            ])
        
        # Anomaly detection
        anomaly_score = self._calculate_simple_anomaly_score(log_data)
        if anomaly_score > 0.6:
            risk_score += anomaly_score * 0.4
            threat_types.append('Behavioral Anomaly')
            if threat_category == 'Normal':
                threat_category = 'Anomaly'
            recommendations.append('Investigate suspicious behavior')
        
        # Threat intelligence checks
        if ip_address in self.threat_intelligence['malicious_ips']:
            risk_score += 0.3
            threat_types.append('Known Malicious IP')
            recommendations.append('Block IP immediately')
        
        # Geographic risk assessment
        country_code = self._get_country_from_ip(ip_address)
        if country_code in self.threat_intelligence['suspicious_countries']:
            risk_score += 0.1
            threat_types.append('High-Risk Geographic Location')
            recommendations.append('Verify user identity')
        
        # Behavioral analysis
        if self._detect_behavioral_anomaly(log_data):
            risk_score += 0.2
            threat_types.append('Behavioral Anomaly')
            recommendations.append('Monitor user behavior')
        
        # Data exfiltration detection
        if bytes_transferred > 10000000:  # >10MB
            risk_score += 0.3
            threat_types.append('Potential Data Exfiltration')
            recommendations.append('Review data access permissions')
        
        # Cap risk score
        risk_score = min(1.0, risk_score)
        
        # Determine risk level
        if risk_score >= self.risk_thresholds['high']:
            risk_level = 'HIGH'
        elif risk_score >= self.risk_thresholds['medium']:
            risk_level = 'MEDIUM'
        elif risk_score >= self.risk_thresholds['low']:
            risk_level = 'LOW'
        else:
            risk_level = 'NORMAL'
        
        # Add default recommendations
        if not recommendations:
            recommendations = ['Continue monitoring']
        
        # Enhanced result structure
        result = {
            'risk_score': round(risk_score, 3),
            'risk_level': risk_level,
            'threat_category': threat_category,
            'model_scores': {
                'enhanced_rules': risk_score,
                'confidence': 0.85
            },
            'threat_types': threat_types,
            'recommendations': recommendations,
            'timestamp': datetime.utcnow().isoformat(),
            'confidence': 0.85,
            'analysis_type': 'Enhanced Rule-Based with Dataset Intelligence',
            'dataset_informed': True,
            'threat_intelligence_hits': len([t for t in threat_types if 'Known' in t or 'Malicious' in t])
        }
        
        # Store analysis result
        threat_data.append({
            'log_data': log_data,
            'result': result,
            'timestamp': datetime.utcnow()
        })
        
        # Update profiles
        if user_id:
            self._update_user_profile(user_id, result)
        
        if risk_level in ['HIGH', 'MEDIUM']:
            self._update_suspicious_ip(ip_address, result)
        
        return result
    
    def _detect_dos_pattern(self, log_data: Dict[str, Any]) -> bool:
        """Detect DoS attack patterns based on NSL-KDD research"""
        failed_logins = log_data.get('failed_login_attempts', 0)
        bytes_transferred = log_data.get('bytes_transferred', 0)
        connection_count = log_data.get('connection_count', 0)
        request_frequency = log_data.get('request_frequency', 0)
        
        # DDoS/DoS indicators
        ddos_indicators = [
            log_data.get('event_type') in ['ddos', 'dos', 'flooding', 'syn_flood', 'amplification'],
            bytes_transferred > 100000000,  # >100MB transfer
            connection_count > 500,  # High connection count
            request_frequency > 1000,  # High request rate
            failed_logins > 20,  # Extreme failed login rate (login flooding)
            log_data.get('traffic_burst', False),
            log_data.get('bandwidth_spike', False)
        ]
        
        # Return True if any strong DDoS indicator is present
        return any(ddos_indicators)
    
    def _detect_probe_pattern(self, log_data: Dict[str, Any]) -> bool:
        """Detect probe/scan patterns based on NSL-KDD research"""
        return (
            log_data.get('event_type') in ['port_scan', 'service_scan', 'network_scan'] or
            log_data.get('unique_ports_accessed', 0) > 20 or
            log_data.get('scan_duration', 0) > 0
        )
    
    def _detect_r2l_pattern(self, log_data: Dict[str, Any]) -> bool:
        """Detect Remote-to-Local attack patterns (brute force, password attacks)"""
        failed_logins = log_data.get('failed_login_attempts', 0)
        return (
            failed_logins > 5 or
            log_data.get('event_type') in ['brute_force', 'password_attack', 'credential_stuffing'] or
            log_data.get('dictionary_attack', False)
        )
    
    def _detect_u2r_pattern(self, log_data: Dict[str, Any]) -> bool:
        """Detect User-to-Root attack patterns (privilege escalation)"""
        return (
            log_data.get('privilege_escalation', False) or
            log_data.get('root_access_attempt', False) or
            log_data.get('event_type') in ['buffer_overflow', 'privilege_escalation', 'rootkit'] or
            log_data.get('admin_access_attempt', False)
        )
    
    def _detect_behavioral_anomaly(self, log_data: Dict[str, Any]) -> bool:
        """Detect behavioral anomalies"""
        current_hour = datetime.now().hour
        return (
            current_hour < 6 or current_hour > 22 or  # After hours
            log_data.get('geographic_distance', 0) > 5000 or  # Unusual location
            log_data.get('session_duration', 0) > 3600  # Long session
        )
    
    def _get_country_from_ip(self, ip_address: str) -> str:
        """Get country code from IP (simplified mapping)"""
        # Simplified IP-to-country mapping for demonstration
        ip_country_map = {
            '185.220.': 'RU',  # Russia
            '91.240.': 'CN',   # China
            '104.244.': 'KP',  # North Korea
            '198.51.': 'IR',   # Iran
            '192.168.': 'US',  # Local/US
            '10.': 'US',       # Local
            '172.': 'US'       # Local
        }
        
        for prefix, country in ip_country_map.items():
            if ip_address.startswith(prefix):
                return country
        
        return 'US'  # Default to US
    
    def _fallback_analysis(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback analysis when enhanced detection fails"""
        return {
            'risk_score': 0.5,
            'risk_level': 'MEDIUM',
            'threat_category': 'Unknown',
            'model_scores': {'fallback': 0.5},
            'threat_types': ['Analysis Error'],
            'recommendations': ['Review system logs', 'Contact administrator'],
            'timestamp': datetime.utcnow().isoformat(),
            'confidence': 0.3,
            'analysis_type': 'Fallback Analysis',
            'error': 'Enhanced analysis failed'
        }
    
    def _detect_unknown_threat_pattern(self, log_data: Dict[str, Any]) -> bool:
        """Detect unknown/novel threat patterns"""
        event_type = log_data.get('event_type', '')
        bytes_transferred = log_data.get('bytes_transferred', 0)
        
        # Unknown event type with high data transfer
        if event_type == 'unknown_attack':
            return True
        
        # Combination of unusual indicators
        unusual_indicators = 0
        
        # Very large data transfer (>100MB)
        if bytes_transferred > 100000000:
            unusual_indicators += 1
        
        # Multiple protocol violations or unusual patterns
        if log_data.get('protocol_violation', False):
            unusual_indicators += 1
        
        if log_data.get('encrypted_suspicious_traffic', False):
            unusual_indicators += 1
        
        # High error rates with data exfiltration
        if log_data.get('error_rate', 0) > 0.5 and bytes_transferred > 10000000:
            unusual_indicators += 1
        
        # Unknown user patterns
        if log_data.get('unknown_user_agent', False):
            unusual_indicators += 1
        
        # If multiple unusual indicators are present, consider it unknown threat
        return unusual_indicators >= 3
    
    def _calculate_simple_anomaly_score(self, log_data: Dict[str, Any]) -> float:
        """Calculate a simple anomaly score for unknown threat detection"""
        anomaly_factors = 0
        total_factors = 6
        
        # Time-based anomaly
        current_hour = datetime.now().hour
        if current_hour < 5 or current_hour > 23:
            anomaly_factors += 1
        
        # Volume anomaly
        if log_data.get('bytes_transferred', 0) > 50000000:  # >50MB
            anomaly_factors += 1
        
        # Geographic anomaly  
        if log_data.get('geographic_distance', 0) > 5000:
            anomaly_factors += 1
        
        # Frequency anomaly
        if log_data.get('request_frequency', 0) > 100:
            anomaly_factors += 1
        
        # Session anomaly
        if log_data.get('session_duration', 0) > 7200:  # >2 hours
            anomaly_factors += 1
        
        # Connection anomaly
        if log_data.get('connection_count', 0) > 200:
            anomaly_factors += 1
        
        return anomaly_factors / total_factors
    
    def _update_user_profile(self, user_id: str, result: Dict[str, Any]):
        """Update user risk profile"""
        if user_id not in user_profiles:
            user_profiles[user_id] = {
                'user_id': user_id,
                'current_risk_score': 0.5,
                'total_alerts': 0,
                'high_risk_alerts': 0,
                'medium_risk_alerts': 0,
                'last_suspicious_activity': None,
                'created_at': datetime.utcnow().isoformat()
            }
        
        profile = user_profiles[user_id]
        profile['current_risk_score'] = result['risk_score']
        profile['updated_at'] = datetime.utcnow().isoformat()
        
        if result['risk_level'] != 'NORMAL':
            profile['total_alerts'] += 1
            profile['last_suspicious_activity'] = datetime.utcnow().isoformat()
            
            if result['risk_level'] == 'HIGH':
                profile['high_risk_alerts'] += 1
            elif result['risk_level'] == 'MEDIUM':
                profile['medium_risk_alerts'] += 1
    
    def _update_suspicious_ip(self, ip_address: str, result: Dict[str, Any]):
        """Update suspicious IP tracking"""
        if ip_address not in suspicious_ips:
            suspicious_ips[ip_address] = {
                'ip_address': ip_address,
                'threat_count': 0,
                'reputation_score': 0.5,
                'last_threat_time': None,
                'is_blocked': False
            }
        
        ip_info = suspicious_ips[ip_address]
        ip_info['threat_count'] += 1
        ip_info['reputation_score'] = 1.0 - result['risk_score']
        ip_info['last_threat_time'] = datetime.utcnow().isoformat()
        
        # Auto-block high-risk IPs
        if result['risk_level'] == 'HIGH' and ip_info['threat_count'] >= 3:
            ip_info['is_blocked'] = True

# Initialize enhanced threat detector
detector = AdvancedThreatDetector()

# Routes
@app.route('/')
def home():
    """Home page with basic dashboard"""
    dashboard_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ThreatX AI Security Dashboard</title>
    
    <!-- Modern CSS Libraries -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet">
    
    <!-- Enhanced Font Loading Strategy -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Source+Sans+Pro:wght@300;400;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/particles.js@2.0.0/particles.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.158.0/build/three.min.js"></script>
    <!-- Fetch API polyfill for older browsers -->
    <script src="https://cdn.jsdelivr.net/npm/whatwg-fetch@3.6.20/fetch.min.js"></script>
    
    <style>
        /* Font Loading CSS Reset and Enhancement */
        @font-face {
            font-family: 'Inter Fallback';
            src: local('Arial'), local('Helvetica'), local('sans-serif');
            font-display: swap;
        }
        
        /* Critical CSS for immediate font loading */
        body, html {
            font-family: 'Inter', 'Roboto', 'Source Sans Pro', 'Inter Fallback', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif !important;
        }
        
        :root {
            --primary-color: #2563eb;
            --primary-dark: #1d4ed8;
            --secondary-color: #64748b;
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --danger-color: #ef4444;
            --dark-bg: #0f172a;
            --card-bg: #1e293b;
            --card-border: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #cbd5e1;
            --gradient-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --gradient-secondary: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            --gradient-success: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
            --gradient-warning: linear-gradient(135deg, #fdbb2d 0%, #22c1c3 100%);
            --gradient-danger: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', 'Roboto', 'Source Sans Pro', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
            background: var(--dark-bg);
            color: var(--text-primary);
            line-height: 1.6;
            overflow-x: hidden;
        }
        
        /* Enhanced font loading and fallback strategy */
        *, *::before, *::after {
            font-family: inherit !important;
        }
        
        /* FIX: Ensure Font Awesome icons maintain their required font settings */
        /* Enhanced Font Awesome Icon Fix with maximum specificity */
        .fa, .fas, .far, .fal, .fad, .fab, .fa-solid, .fa-regular, .fa-brands, .fa-sharp,
        i[class*="fa-"] {
            font-family: 'Font Awesome 6 Free' !important;
            font-weight: 900 !important;
            font-style: normal !important;
            font-variant: normal !important;
            text-rendering: auto !important;
            line-height: 1 !important;
            -webkit-font-smoothing: antialiased !important;
            -moz-osx-font-smoothing: grayscale !important;
            display: inline-block !important;
        }
        .metric-value {
            font-size: 2.5rem;
            font-weight: 800;
            color: #10b981;
            font-family: 'Inter', 'Roboto', 'Source Sans Pro', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
            line-height: 1;
        }
        .metric-label {
            color: #cbd5e1;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-size: 0.875rem;
            margin-bottom: 0.5rem;
            font-family: 'Inter', 'Roboto', 'Source Sans Pro', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
        }

        
        .fa-brands, .fab {
            font-family: 'Font Awesome 6 Brands' !important;
            font-weight: 400 !important;
        }
        
        .fa-sharp, .fass {
            font-family: 'Font Awesome 6 Sharp' !important;
        }
        
        /* Ensure specific icons mentioned in the issue are visible */
        .fa-bolt, .fa-vial, .fa-shield-virus,
        .fa-bolt.me-2, .fa-vial.me-2, .fa-shield-virus.me-3 {
            color: var(--text-primary) !important;
            display: inline-block !important;
        }
        
        /* Additional fixes for icon visibility */
        i[class*="fa-"] {
            display: inline-block !important;
            font-style: normal !important;
            font-variant: normal !important;
            text-rendering: auto !important;
            line-height: 1 !important;
        }
        
        /* Ensure icons in buttons and nav links are visible */
        .btn .fa, .btn .fas, .btn .far, .btn .fab,
        .nav-link .fa, .nav-link .fas, .nav-link .far, .nav-link .fab,
        .card .fa, .card .fas, .card .far, .card .fab,
        button .fa, button .fas, button .far, button .fab {
            color: inherit !important;
        }
        
        /* Fix for margin classes that might be used with icons */
        .me-2 {
            margin-right: 0.5rem !important;
        }
        
        .me-3 {
            margin-right: 1rem !important;
        }
        
        /* Ensure all text elements have proper contrast */
        .text-muted, .text-gray-300 {
            color: var(--text-secondary) !important;
        }
        
        .text-gray-800 {
            color: var(--text-primary) !important;
        }
        
        /* Ensure all text elements inherit fonts properly with enhanced specificity */
        html, body, h1, h2, h3, h4, h5, h6, p, span, div, a, button, input, select, textarea, label, strong, em, .card, .card-header, .card-body, .navbar, .btn, .form-control, .form-select {
            font-family: inherit !important;
        }
        
        /* Form controls font inheritance with priority */
        .form-control, .form-select, .btn, input, select, textarea {
            font-family: inherit !important;
        }
        
        /* Bootstrap overrides for consistent font loading */
        .navbar-brand, .nav-link, .btn, .card-title, .badge {
            font-family: inherit !important;
        }
        
        /* Animated Background */
        #particles-js {
            position: fixed;
            width: 100%;
            height: 100%;
            top: 0;
            left: 0;
            z-index: -1;
            opacity: 0.3;
        }
        
        /* Enhanced Navbar */
        .navbar {
            background: rgba(15, 23, 42, 0.95) !important;
            backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--card-border);
            padding: 1rem 0;
            transition: all 0.3s ease;
        }
        
        .navbar.scrolled {
            background: rgba(15, 23, 42, 0.98) !important;
            box-shadow: 0 2px 20px rgba(0, 0, 0, 0.3);
        }
        
        /* Text colors and visibility fixes */
        h1, h2, h3, h4, h5, h6 {
            color: #ffffff !important;
            font-family: inherit !important;
            font-weight: 700;
        }
        
        .navbar-brand {
            color: #ffffff !important;
            font-weight: 700;
            font-size: 1.5rem;
        }
        
        /* Card headers and content */
        .card-header h1, .card-header h2, .card-header h3, .card-header h4, .card-header h5, .card-header h6 {
            color: #ffffff !important;
        }
        
        .card-title {
            color: #ffffff !important;
        }
        
        /* General text visibility */
        p, span, div, label {
            color: #f8fafc !important;
        }
        
        /* Button text */
        .btn {
            color: #ffffff !important;
        }
        
        /* Badge text */
        .badge {
            color: #ffffff !important;
            font-family: inherit !important;
        }
        
        /* Navbar links */
        .navbar-nav .nav-link, .nav-link {
            color: #ffffff !important;
        }
        
        .status-badge {
            background: var(--gradient-success);
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 50px;
            font-weight: 600;
            box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.05); opacity: 0.8; }
        }
        
        /* Hero Section */
        .hero-section {
            background: var(--dark-bg);
            position: relative;
            overflow: hidden;
        }
        
        .hero-title {
            font-size: 3.5rem;
            font-weight: 800;
            margin-bottom: 2rem;
            line-height: 1.2;
            color: #ffffff !important;
        }
        
        .hero-subtitle {
            font-size: 1.25rem;
            color: var(--text-secondary);
            font-weight: 400;
            max-width: 600px;
            margin: 0 auto;
        }
        
        /* Section Styling */
        .section-title {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 1rem;
            color: #ffffff !important;
        }
        
        .section-subtitle {
            font-size: 1.1rem;
            color: var(--text-secondary);
            margin-bottom: 2rem;
        }
        
        .stats-section {
            background: linear-gradient(135deg, var(--dark-bg) 0%, #1a202c 100%);
        }
        
        .bg-section {
            background: linear-gradient(135deg, #1a202c 0%, var(--dark-bg) 100%);
        }
        .card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 20px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
            backdrop-filter: blur(10px);
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
            border-color: var(--primary-color);
        }
        
        .card-header {
            background: linear-gradient(135deg, var(--card-bg) 0%, rgba(37, 99, 235, 0.1) 100%);
            border-bottom: 1px solid var(--card-border);
            border-radius: 20px 20px 0 0 !important;
            padding: 1.5rem;
        }
        
        .card-title {
            font-weight: 600;
            margin: 0;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        
        /* Card Variants */
        .test-card {
            background: linear-gradient(135deg, var(--card-bg) 0%, rgba(37, 99, 235, 0.05) 100%);
        }
        
        .result-card {
            background: linear-gradient(135deg, var(--card-bg) 0%, rgba(16, 185, 129, 0.05) 100%);
        }
        
        .dashboard-card {
            background: linear-gradient(135deg, var(--card-bg) 0%, rgba(100, 116, 139, 0.05) 100%);
        }
        
        .action-card {
            background: linear-gradient(135deg, var(--card-bg) 0%, rgba(245, 158, 11, 0.05) 100%);
        }
            font-size: 1.2rem;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        /* Enhanced Form Controls */
        .form-control, .form-select {
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            color: var(--text-primary);
            padding: 0.75rem 1rem;
            transition: all 0.3s ease;
        }
        
        .form-control:focus, .form-select:focus {
            background: rgba(30, 41, 59, 0.9);
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.2rem rgba(37, 99, 235, 0.25);
            color: var(--text-primary);
        }
        
        .form-label {
            color: var(--text-secondary);
            font-weight: 500;
            margin-bottom: 0.5rem;
        }
        
        /* Enhanced Buttons */
        .btn {
            border-radius: 12px;
            padding: 0.75rem 1.5rem;
            font-weight: 600;
            transition: all 0.3s ease;
            border: none;
            position: relative;
            overflow: hidden;
        }
        
        .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.5s;
        }
        
        .btn:hover::before {
            left: 100%;
        }
        
        .btn-primary {
            background: var(--gradient-primary);
            box-shadow: 0 4px 15px rgba(37, 99, 235, 0.3);
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(37, 99, 235, 0.4);
        }
        
        .btn-success {
            background: var(--gradient-success);
            box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
        }
        
        .btn-warning {
            background: var(--gradient-warning);
            box-shadow: 0 4px 15px rgba(245, 158, 11, 0.3);
        }
        
        .btn-danger {
            background: var(--gradient-danger);
            box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
        }
        
        .btn-outline-success, .btn-outline-warning, .btn-outline-danger, .btn-outline-info, .btn-outline-secondary {
            background: rgba(30, 41, 59, 0.5);
            border: 2px solid;
            backdrop-filter: blur(10px);
        }
        
        /* Threat Level Styling */
        .threat-high { 
            color: #ef4444;
            font-weight: 700;
            text-shadow: 0 0 10px rgba(239, 68, 68, 0.5);
        }
        .threat-medium { 
            color: #f59e0b;
            font-weight: 700;
            text-shadow: 0 0 10px rgba(245, 158, 11, 0.5);
        }
        .threat-low { 
            color: #06b6d4;
            font-weight: 700;
            text-shadow: 0 0 10px rgba(6, 182, 212, 0.5);
        }
        .threat-normal { 
            color: #10b981;
            font-weight: 700;
            text-shadow: 0 0 10px rgba(16, 185, 129, 0.5);
        }
        
        /* Alert Enhancements */
        .alert {
            border-radius: 15px;
            border: none;
            backdrop-filter: blur(10px);
        }
        
        .alert-light {
            background: rgba(248, 250, 252, 0.1);
            color: var(--text-primary);
            border: 1px solid var(--card-border);
        }
        
        /* Stats Cards */
        .stats-card {
            background: var(--card-bg);
            border-radius: 20px;
            padding: 1.5rem;
            border: 1px solid var(--card-border);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .stats-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: var(--gradient-primary);
        }
        
        .stats-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.3);
        }
        
        .stats-icon {
            width: 60px;
            height: 60px;
            border-radius: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            margin-bottom: 1rem;
        }
        
        .stats-icon.danger {
            background: var(--gradient-danger);
            box-shadow: 0 8px 20px rgba(239, 68, 68, 0.3);
        }
        
        .stats-icon.warning {
            background: var(--gradient-warning);
            box-shadow: 0 8px 20px rgba(245, 158, 11, 0.3);
        }
        
        .stats-icon.info {
            background: var(--gradient-success);
            box-shadow: 0 8px 20px rgba(6, 182, 212, 0.3);
        }
        
        .stats-icon.success {
            background: var(--gradient-success);
            box-shadow: 0 8px 20px rgba(16, 185, 129, 0.3);
        }
        
        .stats-value {
            font-size: 2.5rem;
            font-weight: 700;
            line-height: 1;
            margin-bottom: 0.5rem;
        }
        
        
        /* Stats Card Enhancements */
        .stats-trend {
            font-size: 0.8rem;
            color: var(--text-secondary);
            margin-top: 0.5rem;
        }
        
        /* Smooth Scrolling */
        html {
            scroll-behavior: smooth;
        }
            color: var(--text-secondary);
            font-size: 0.9rem;
            font-weight: 500;
        }
        
        
        /* Time Display */
        #current-time {
            font-family: 'Courier New', monospace;
            font-weight: 600;
        }
        .loading-spinner {
            width: 40px;
            height: 40px;
            border: 4px solid var(--card-border);
            border-top: 4px solid var(--primary-color);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        /* Responsive Design */
        @media (max-width: 768px) {
            .container {
                padding: 0 1rem;
            }
            
            .card {
                margin-bottom: 1rem;
            }
            
            .stats-value {
                font-size: 2rem;
            }
        }
        
        /* Scrollbar Styling */
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: var(--dark-bg);
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--card-border);
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: var(--primary-color);
        }
        
        /* Glowing Effects */
        .glow {
            box-shadow: 0 0 20px rgba(37, 99, 235, 0.5);
        }
        
        .text-gradient {
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: white;
            background-clip: text;
            color: white !important;
        }
        
        /* Hero Section */
        .hero-section {
            background: var(--dark-bg);
            position: relative;
            overflow: hidden;
            padding-top: 100px;
        }
        
        .hero-title {
            font-size: 3.5rem;
            font-weight: 800;
            margin-bottom: 2rem;
            line-height: 1.2;
        }
        
        .hero-subtitle {
            font-size: 1.25rem;
            color: var(--text-secondary);
            font-weight: 400;
            max-width: 600px;
            margin: 0 auto;
        }
        
        /* Section Styling */
        .section-title {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 1rem;
        }
        
        .section-subtitle {
            font-size: 1.1rem;
            color: var(--text-secondary);
            margin-bottom: 2rem;
        }
        
        .stats-section {
            background: linear-gradient(135deg, var(--dark-bg) 0%, #1a202c 100%);
        }
        
        .bg-section {
            background: linear-gradient(135deg, #1a202c 0%, var(--dark-bg) 100%);
        }
        
        /* Card Variants */
        .test-card {
            background: linear-gradient(135deg, var(--card-bg) 0%, rgba(37, 99, 235, 0.05) 100%);
        }
        
        .result-card {
            background: linear-gradient(135deg, var(--card-bg) 0%, rgba(16, 185, 129, 0.05) 100%);
        }
        
        .dashboard-card {
            background: linear-gradient(135deg, var(--card-bg) 0%, rgba(100, 116, 139, 0.05) 100%);
        }
        
        .action-card {
            background: linear-gradient(135deg, var(--card-bg) 0%, rgba(245, 158, 11, 0.05) 100%);
        }
        
        /* Stats Card Enhancements */
        .stats-trend {
            font-size: 0.8rem;
            color: var(--text-secondary);
            margin-top: 0.5rem;
        }
        
        /* Enhanced navbar with scroll effect */
        .navbar.scrolled {
            background: rgba(15, 23, 42, 0.98) !important;
            box-shadow: 0 2px 20px rgba(0, 0, 0, 0.3);
        }
        
        /* Time Display */
        #current-time {
            font-family: 'Courier New', monospace;
            font-weight: 600;
        }
        
        /* Smooth Scrolling */
        html {
            scroll-behavior: smooth;
        }
        
        /* Fixed navbar spacing */
        body {
            padding-top: 80px;
        }
        
        .navbar {
            z-index: 1000;
        }
    </style>
</head>
<body>
    <!-- Particle Background -->
    <div id="particles-js"></div>
    
    <!-- Enhanced Navbar -->
    <nav class="navbar navbar-expand-lg fixed-top">
        <div class="container">
            <span class="navbar-brand text-gradient">
                <i class="fas fa-shield-alt me-2"></i>ThreatX AI Security
            </span>
            <div class="navbar-nav ms-auto">
                <span class="nav-item">
                    <span class="badge status-badge me-3">
                        <i class="fas fa-circle me-1"></i>System Online
                    </span>
                </span>
                <span class="nav-item">
                    <span class="badge bg-info">
                        <i class="fas fa-clock me-1"></i><span id="current-time"></span>
                    </span>
                </span>
            </div>
        </div>
    </nav>
    
    <!-- Hero Section -->
    <div class="hero-section">
        <div class="container">
            <div class="row align-items-center min-vh-100">
                <div class="col-lg-8 mx-auto text-center">
                    <h1 class="hero-title mb-4">
                        <i class="fas fa-shield-virus me-3"></i>
                        AI-Powered Cybersecurity
                        <span class="text-gradient d-block">Threat Detection System</span>
                    </h1>
                    <p class="hero-subtitle mb-5">Advanced machine learning algorithms protecting your digital infrastructure in real-time</p>
                    <div class="d-flex justify-content-center gap-3">
                        <button class="btn btn-primary btn-lg" onclick="scrollToSection('dashboard')">
                            <i class="fas fa-tachometer-alt me-2"></i>Dashboard
                        </button>
                        <button class="btn btn-outline-primary btn-lg" onclick="scrollToSection('test-interface')">
                            <i class="fas fa-vial me-2"></i>Test Interface
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Stats Overview -->
    <section id="dashboard" class="stats-section py-5">
        <div class="container">
            <div class="row mb-5">
                <div class="col-12 text-center">
                    <h2 class="section-title mb-4">Real-Time Security Metrics</h2>
                    <p class="section-subtitle">Monitor your security posture with advanced analytics</p>
                </div>
            </div>
            <div class="row g-4">
                <div class="col-md-3">
                    <div class="stats-card">
                        <div class="stats-icon danger">
                            <i class="fas fa-exclamation-triangle"></i>
                        </div>
                        <div class="stats-value" id="totalThreats">0</div>
                        <div class="stats-label">Threats Detected</div>
                        <div class="stats-trend">
                            <i class="fas fa-arrow-up text-danger"></i> +12% from yesterday
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stats-card">
                        <div class="stats-icon warning">
                            <i class="fas fa-globe"></i>
                        </div>
                        <div class="stats-value" id="suspiciousIPs">0</div>
                        <div class="stats-label">Suspicious IPs</div>
                        <div class="stats-trend">
                            <i class="fas fa-arrow-down text-success"></i> -5% from yesterday
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stats-card">
                        <div class="stats-icon info">
                            <i class="fas fa-users"></i>
                        </div>
                        <div class="stats-value" id="activeUsers">0</div>
                        <div class="stats-label">Monitored Users</div>
                        <div class="stats-trend">
                            <i class="fas fa-arrow-up text-info"></i> +8% from yesterday
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stats-card">
                        <div class="stats-icon success">
                            <i class="fas fa-shield-check"></i>
                        </div>
                        <div class="stats-value">99.8%</div>
                        <div class="stats-label">System Uptime</div>
                        <div class="stats-trend">
                            <i class="fas fa-check text-success"></i> Operational
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>
    
    <!-- Test Interface Section -->
    <section id="test-interface" class="py-5">
        <div class="container">
            <div class="row mb-5">
                <div class="col-12 text-center">
                    <h2 class="section-title mb-4">Threat Detection Testing</h2>
                    <p class="section-subtitle">Simulate security events and analyze AI responses</p>
                </div>
            </div>
        
            <div class="row g-4">
                <div class="col-lg-6">
                    <div class="card test-card">
                        <div class="card-header">
                            <h5 class="card-title">
                                <i class="fas fa-vial"></i>
                                Simulate Security Event
                            </h5>
                        </div>
                    <div class="card-body">
                        <form id="threatForm">
                            <div class="mb-3">
                                <label class="form-label">IP Address</label>
                                <input type="text" class="form-control" id="ipAddress" value="192.168.1.100">
                            </div>
                            <div class="mb-3">
                                <label class="form-label">User ID</label>
                                <input type="text" class="form-control" id="userId" value="test_user">
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Event Type</label>
                                <select class="form-control" id="eventType">
                                    <option value="login">Normal Login</option>
                                    <option value="failed_login">Failed Login</option>
                                    <option value="brute_force">Brute Force Attack</option>
                                    <option value="ddos">DDoS Attack</option>
                                    <option value="port_scan">Port Scan</option>
                                    <option value="buffer_overflow">Buffer Overflow</option>
                                    <option value="unknown_attack">Unknown Attack</option>
                                    <option value="data_access">Data Access</option>
                                    <option value="file_download">File Download</option>
                                    <option value="privilege_escalation">Privilege Escalation</option>
                                </select>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Failed Login Attempts</label>
                                <input type="number" class="form-control" id="failedLogins" value="0">
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Bytes Transferred</label>
                                <input type="number" class="form-control" id="bytesTransferred" value="1024">
                            </div>
                            <button type="submit" class="btn btn-primary w-100">
                                <i class="fas fa-search me-2"></i>
                                Analyze Threat
                            </button>
                        </form>
                    </div>
                </div>
            </div>
            
                <div class="col-lg-6">
                    <div class="card result-card">
                        <div class="card-header">
                            <h5 class="card-title">
                                <i class="fas fa-chart-line"></i>
                                AI Analysis Results
                            </h5>
                        </div>
                    <div class="card-body">
                        <div id="result">
                            <p class="text-muted">Submit a test to see threat analysis results...</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="col-md-4">
                <div class="card dashboard-card">
                    <div class="card-header">
                        <h6 class="card-title">
                            <i class="fas fa-chart-line"></i>
                            Recent Threats
                        </h6>
                    </div>
                    <div class="card-body">
                        <div id="recentThreats">
                            <p class="text-muted">No threats detected yet</p>
                        </div>
                    </div>
                </div>
            </div>
            
                <div class="col-lg-4">
                    <div class="card dashboard-card">
                        <div class="card-header">
                            <h6 class="card-title">
                                <i class="fas fa-users"></i>
                                User Risk Profiles
                            </h6>
                        </div>
                    <div class="card-body">
                        <div id="userProfiles">
                            <p class="text-muted">No user profiles yet</p>
                        </div>
                    </div>
                </div>
            </div>
            
                <div class="col-lg-4">
                    <div class="card dashboard-card">
                        <div class="card-header">
                            <h6 class="card-title">
                                <i class="fas fa-globe-americas"></i>
                                Suspicious IPs
                            </h6>
                        </div>
                    <div class="card-body">
                        <div id="suspiciousIps">
                            <p class="text-muted">No suspicious IPs yet</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        </div>
    </section>
    
    <!-- Quick Actions Section -->
    <section class="py-5">
        <div class="container">
            <div class="row">
                <div class="col-12">
                    <div class="card action-card">
                        <div class="card-header text-center">
                            <h5 class="card-title mb-0">
                                <i class="fas fa-bolt me-2"></i>
                                Quick Actions
                            </h5>
                        </div>
                        <div class="card-body">
                            <div class="row g-3">
                                <div class="col-md-3">
                                    <button class="btn btn-success w-100" onclick="runQuickTest('normal')">
                                        <i class="fas fa-user-check me-2"></i>
                                        Normal Activity
                                    </button>
                                </div>
                                <div class="col-md-3">
                                    <button class="btn btn-warning w-100" onclick="runQuickTest('brute_force')">
                                        <i class="fas fa-user-lock me-2"></i>
                                        Brute Force
                                    </button>
                                </div>
                                <div class="col-md-3">
                                    <button class="btn btn-danger w-100" onclick="runQuickTest('ddos')">
                                        <i class="fas fa-water me-2"></i>
                                        DDoS Attack
                                    </button>
                                </div>
                                <div class="col-md-3">
                                    <button class="btn btn-info w-100" onclick="runQuickTest('scan')">
                                        <i class="fas fa-search-location me-2"></i>
                                        Port Scan
                                    </button>
                                </div>
                            </div>
                            <div class="row g-3 mt-3">
                                <div class="col-md-6">
                                    <a href="/health" class="btn btn-info w-100">
                                        <i class="fas fa-heartbeat me-2"></i>
                                        System Health Check
                                    </a>
                                </div>
                                <div class="col-md-6">
                                    <a href="/api/threat-statistics" class="btn btn-secondary w-100">
                                        <i class="fas fa-chart-bar me-2"></i>
                                        View Statistics
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Enhanced JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <!-- Fetch API polyfill for older browsers -->
    <script src="https://cdn.jsdelivr.net/npm/whatwg-fetch@3.6.20/fetch.min.js"></script>
    
    <script>
        // Enhanced fetch polyfill and compatibility check
        (function() {
            // Ensure fetch is available or provide XMLHttpRequest fallback
            if (typeof fetch === 'undefined') {
                console.warn('Fetch API not available, using XMLHttpRequest fallback');
                
                window.fetch = function(url, options) {
                    return new Promise(function(resolve, reject) {
                        const xhr = new XMLHttpRequest();
                        const method = (options && options.method) || 'GET';
                        
                        xhr.open(method, url, true);
                        
                        // Set headers
                        if (options && options.headers) {
                            for (const header in options.headers) {
                                xhr.setRequestHeader(header, options.headers[header]);
                            }
                        }
                        
                        xhr.onload = function() {
                            if (xhr.status >= 200 && xhr.status < 300) {
                                resolve({
                                    ok: true,
                                    status: xhr.status,
                                    statusText: xhr.statusText,
                                    json: function() {
                                        return Promise.resolve(JSON.parse(xhr.responseText));
                                    },
                                    text: function() {
                                        return Promise.resolve(xhr.responseText);
                                    }
                                });
                            } else {
                                reject(new Error('HTTP ' + xhr.status + ': ' + xhr.statusText));
                            }
                        };
                        
                        xhr.onerror = function() {
                            reject(new Error('Network Error'));
                        };
                        
                        xhr.ontimeout = function() {
                            reject(new Error('Request Timeout'));
                        };
                        
                        // Send request
                        if (options && options.body) {
                            xhr.send(options.body);
                        } else {
                            xhr.send();
                        }
                    });
                };
            }
        })();
        function updateTime() {
            const now = new Date();
            const timeString = now.toLocaleTimeString('en-US', {
                hour12: false,
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
            document.getElementById('current-time').textContent = timeString;
        }
        
        // Smooth scroll function
        function scrollToSection(sectionId) {
            document.getElementById(sectionId).scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
        
        // Navbar scroll effect
        window.addEventListener('scroll', () => {
            const navbar = document.querySelector('.navbar');
            if (window.scrollY > 100) {
                navbar.classList.add('scrolled');
            } else {
                navbar.classList.remove('scrolled');
            }
        });
        
        // Initialize time updates
        updateTime();
        setInterval(updateTime, 1000);
        particlesJS('particles-js', {
            particles: {
                number: { value: 80, density: { enable: true, value_area: 800 } },
                color: { value: '#2563eb' },
                shape: { type: 'circle' },
                opacity: { value: 0.5, random: false },
                size: { value: 3, random: true },
                line_linked: {
                    enable: true,
                    distance: 150,
                    color: '#2563eb',
                    opacity: 0.4,
                    width: 1
                },
                move: {
                    enable: true,
                    speed: 6,
                    direction: 'none',
                    random: false,
                    straight: false,
                    out_mode: 'out',
                    bounce: false
                }
            },
            interactivity: {
                detect_on: 'canvas',
                events: {
                    onhover: { enable: true, mode: 'repulse' },
                    onclick: { enable: true, mode: 'push' },
                    resize: true
                }
            },
            retina_detect: true
        });
        
        // Enhanced form submission
        document.getElementById('threatForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const submitBtn = e.target.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerHTML;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Analyzing...';
            submitBtn.disabled = true;
            
            const data = {
                ip_address: document.getElementById('ipAddress').value,
                user_id: document.getElementById('userId').value,
                event_type: document.getElementById('eventType').value,
                failed_login_attempts: parseInt(document.getElementById('failedLogins').value),
                bytes_transferred: parseInt(document.getElementById('bytesTransferred').value),
                timestamp: new Date().toISOString()
            };
            
            fetch('/api/detect-threat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(result => {
                displayResult(result);
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
            })
            .catch(error => {
                console.error('Error:', error);
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
            });
        });
        
        function displayResult(result) {
            const riskClass = 'threat-' + result.risk_level.toLowerCase();
            const riskIcon = {
                'HIGH': 'fas fa-skull-crossbones',
                'MEDIUM': 'fas fa-exclamation-triangle', 
                'LOW': 'fas fa-info-circle',
                'NORMAL': 'fas fa-check-circle'
            }[result.risk_level] || 'fas fa-question-circle';
            
            const html = `
                <div class="alert alert-light border glow">
                    <div class="d-flex align-items-center mb-3">
                        <div class="stats-icon ${riskClass === 'threat-high' ? 'danger' : riskClass === 'threat-medium' ? 'warning' : riskClass === 'threat-low' ? 'info' : 'success'} me-3">
                            <i class="${riskIcon} fa-2x"></i>
                        </div>
                        <div>
                            <h5 class="mb-0">${result.threat_category} Detected</h5>
                            <span class="badge ${riskClass === 'threat-high' ? 'bg-danger' : riskClass === 'threat-medium' ? 'bg-warning' : riskClass === 'threat-low' ? 'bg-info' : 'bg-success'}">
                                Risk: ${result.risk_level} (${result.risk_score})
                            </span>
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <p><strong>Risk Score:</strong> <span class="${riskClass}">${result.risk_score}</span></p>
                        <p><strong>Risk Level:</strong> <span class="${riskClass} fw-bold">${result.risk_level}</span></p>
                        <p><strong>Confidence:</strong> ${(result.confidence * 100).toFixed(1)}%</p>
                    </div>
                    
                    <div class="mb-3">
                        <strong>Threat Types:</strong><br>
                        ${result.threat_types.length ? result.threat_types.map(t => `<span class="badge bg-secondary me-1">${t}</span>`).join('') : '<span class="text-muted">None detected</span>'}
                    </div>
                    
                    <div class="mb-3">
                        <strong>Recommendations:</strong>
                        <ul class="mb-0">
                            ${result.recommendations.map(r => `<li>${r}</li>`).join('')}
                        </ul>
                    </div>
                    
                    <div class="small text-muted mt-3">
                        <i class="fas fa-clock me-1"></i>Analysis completed at ${new Date(result.timestamp).toLocaleString()}
                    </div>
                </div>
            `;
            
            document.getElementById('result').innerHTML = html;
        }
        
        // Quick test functions
        function runQuickTest(type) {
            let testData = {};
            
            switch(type) {
                case 'normal':
                    testData = {
                        ip_address: '192.168.1.100',
                        user_id: 'alice.johnson',
                        event_type: 'login',
                        failed_login_attempts: 0,
                        bytes_transferred: 1024
                    };
                    break;
                case 'brute_force':
                    testData = {
                        ip_address: '198.51.100.30',
                        user_id: 'charlie.brown',
                        event_type: 'brute_force',
                        failed_login_attempts: 8,
                        bytes_transferred: 512,
                        dictionary_attack: true
                    };
                    break;
                case 'ddos':
                    testData = {
                        ip_address: '185.220.101.5',
                        user_id: 'unknown',
                        event_type: 'ddos',
                        failed_login_attempts: 25,
                        bytes_transferred: 75000000,
                        connection_rate: 150
                    };
                    break;
                case 'scan':
                    testData = {
                        ip_address: '91.240.118.172',
                        user_id: 'scanner_bot',
                        event_type: 'port_scan',
                        failed_login_attempts: 0,
                        bytes_transferred: 2048,
                        unique_ports_accessed: 50,
                        scan_duration: 300
                    };
                    break;
            }
            
            // Submit test data
            const submitBtn = document.querySelector('.btn-primary');
            const originalText = submitBtn.innerHTML;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Testing...';
            submitBtn.disabled = true;
            
            fetch('/api/detect-threat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(testData)
            })
            .then(response => response.json())
            .then(result => {
                displayResult(result);
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
            })
            .catch(error => {
                console.error('Error:', error);
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
            });
        }
        
        // Auto-refresh dashboard data
        function loadDashboardData() {
            fetch('/api/dashboard-data')
                .then(response => response.json())
                .then(data => {
                    const profiles = data.user_profiles || {};
                    const ips = data.suspicious_ips || {};
                    const stats = data.stats || {};
                    
                    // Update stats
                    document.getElementById('totalThreats').textContent = stats.total_threats || 0;
                    document.getElementById('activeUsers').textContent = Object.keys(profiles).length;
                    document.getElementById('suspiciousIPs').textContent = Object.keys(ips).length;
                    
                    // Update recent threats
                    const recentContainer = document.getElementById('recentThreats');
                    const recentThreats = data.recent_threats || [];
                    
                    if (recentThreats.length === 0) {
                        recentContainer.innerHTML = '<div class="text-center py-3"><i class="fas fa-shield-check fa-2x text-success mb-2"></i><p class="text-secondary">No threats detected</p></div>';
                    } else {
                        const html = recentThreats.slice(0, 3).map(threat => {
                            const riskClass = threat.result.risk_level.toLowerCase();
                            return `
                                <div class="d-flex align-items-center mb-2 p-2 rounded" style="background: rgba(30, 41, 59, 0.5);">
                                    <div class="me-2">
                                        <i class="fas fa-${riskClass === 'high' ? 'skull-crossbones' : riskClass === 'medium' ? 'exclamation-triangle' : 'info-circle'} ${riskClass === 'high' ? 'text-danger' : riskClass === 'medium' ? 'text-warning' : 'text-info'}"></i>
                                    </div>
                                    <div class="flex-grow-1 small">
                                        <div class="fw-bold">${threat.log_data.event_type}</div>
                                        <div class="text-secondary">${threat.result.risk_level} Risk</div>
                                    </div>
                                    <div class="small text-muted">${new Date(threat.timestamp).toLocaleTimeString()}</div>
                                </div>
                            `;
                        }).join('');
                        recentContainer.innerHTML = html;
                    }
                    
                    // Update user profiles
                    const userContainer = document.getElementById('userProfiles');
                    const profileArray = Object.values(profiles);
                    
                    if (profileArray.length === 0) {
                        userContainer.innerHTML = '<div class="text-center py-3"><i class="fas fa-users fa-2x text-warning mb-2"></i><p class="text-secondary">No active users</p></div>';
                    } else {
                        const html = profileArray.slice(0, 3).map(user => `
                            <div class="d-flex align-items-center mb-2 p-2 rounded" style="background: rgba(30, 41, 59, 0.5);">
                                <div class="me-2">
                                    <i class="fas fa-user"></i>
                                </div>
                                <div class="flex-grow-1 small">
                                    <div class="fw-bold">${user.user_id}</div>
                                    <div class="text-secondary">Risk: ${user.current_risk_score.toFixed(2)}</div>
                                </div>
                                <div class="small ${user.current_risk_score > 0.75 ? 'text-danger' : user.current_risk_score > 0.5 ? 'text-warning' : 'text-success'}">
                                    ${user.current_risk_score > 0.75 ? 'High' : user.current_risk_score > 0.5 ? 'Medium' : 'Low'}
                                </div>
                            </div>
                        `).join('');
                        userContainer.innerHTML = html;
                    }
                    
                    // Update suspicious IPs
                    const ipContainer = document.getElementById('suspiciousIps');
                    const ipArray = Object.values(ips);
                    
                    if (ipArray.length === 0) {
                        ipContainer.innerHTML = '<div class="text-center py-3"><i class="fas fa-globe fa-2x text-warning mb-2"></i><p class="text-secondary">No suspicious IPs</p></div>';
                    } else {
                        const html = ipArray.slice(0, 3).map(ip => `
                            <div class="d-flex align-items-center mb-2 p-2 rounded" style="background: rgba(30, 41, 59, 0.5);">
                                <div class="me-2">
                                    <i class="fas fa-${ip.is_blocked ? 'ban' : 'exclamation-triangle'} ${ip.is_blocked ? 'text-danger' : 'text-warning'}"></i>
                                </div>
                                <div class="flex-grow-1 small">
                                    <div class="fw-bold">${ip.ip_address}</div>
                                    <div class="text-secondary">${ip.threat_count} threats</div>
                                </div>
                                <div class="small text-muted">${ip.is_blocked ? 'Blocked' : 'Active'}</div>
                            </div>
                        `).join('');
                        ipContainer.innerHTML = html;
                    }
                })
                .catch(error => {
                    console.error('Error loading dashboard data:', error);
                });
        }
        
        // Auto-refresh every 30 seconds
        loadDashboardData();
        setInterval(loadDashboardData, 30000);
    </script>
</body>
</html>
    """
    return dashboard_html

@app.route('/health')
def health():
    """Health check endpoint with formatted HTML display"""
    health_data = {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '2.0.0-enhanced',
        'mode': 'enhanced-dataset-integration',
        'dataset_status': 'NSL-KDD loaded and trained' if detector.use_enhanced else 'heuristic-mode',
        'models_trained': detector.use_enhanced,
        'total_threats_analyzed': len(threat_data),
        'active_users': len(user_profiles),
        'suspicious_ips': len(suspicious_ips)
    }
    
    # Check if request wants JSON
    if request.headers.get('Accept') == 'application/json' or request.args.get('format') == 'json':
        return jsonify(health_data)
    
    # Return formatted HTML
    health_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ThreatX System Health</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet">
    
    <!-- Enhanced font loading strategies for better compatibility -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Source+Sans+Pro:wght@300;400;600;700&display=swap" rel="stylesheet">
    
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');
        @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap');
        
        /* Enhanced font fallback strategy */
        body {
            font-family: 'Inter', 'Roboto', 'Source Sans Pro', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #f8fafc;
            min-height: 100vh;
            font-size: 16px;
            line-height: 1.6;
        }
        
        /* Ensure comprehensive font inheritance */
        *, *::before, *::after {
            font-family: inherit;
        }
        
        /* Enhanced Font Awesome Icon Fix */
        .fa, .fas, .far, .fal, .fad, .fab, .fa-solid, .fa-regular, .fa-brands, .fa-sharp,
        i[class*="fa-"] {
            font-family: 'Font Awesome 6 Free' !important;
            font-weight: 900 !important;
            font-style: normal !important;
            font-variant: normal !important;
            text-rendering: auto !important;
            line-height: 1 !important;
            -webkit-font-smoothing: antialiased !important;
            -moz-osx-font-smoothing: grayscale !important;
            display: inline-block !important;
            color: #f8fafc !important; /* Ensure icons are visible */
        }
        
        .fa-brands, .fab {
            font-family: 'Font Awesome 6 Brands' !important;
            font-weight: 400 !important;
        }
        
        .fa-sharp, .fass {
            font-family: 'Font Awesome 6 Sharp' !important;
        }
        
        /* Ensure specific icons mentioned in the issue are visible */
        .fa-bolt, .fa-vial, .fa-shield-virus,
        .fa-bolt.me-2, .fa-vial.me-2, .fa-shield-virus.me-2 {
            color: #f8fafc !important;
            display: inline-block !important;
        }
        
        /* Additional fixes for icon visibility */
        i[class*="fa-"] {
            display: inline-block !important;
            font-style: normal !important;
            font-variant: normal !important;
            text-rendering: auto !important;
            line-height: 1 !important;
        }
        
        /* Ensure icons in buttons and nav links are visible */
        .btn .fa, .btn .fas, .btn .far, .btn .fab,
        .nav-link .fa, .nav-link .fas, .nav-link .far, .nav-link .fab,
        .card .fa, .card .fas, .card .far, .card .fab {
            color: inherit !important;
        }
        
        /* Force font inheritance for all elements with enhanced specificity */
        h1, h2, h3, h4, h5, h6, p, span, div, a, button, input, select, textarea, label, strong, em, .card, .card-header, .card-body, .metric-card, .badge, .btn {
            font-family: inherit !important;
            color: #f8fafc !important; /* Ensure text is visible on dark background */
        }}
        
        /* Bootstrap component overrides */
        .btn, .form-control, .form-select, .navbar, .navbar-brand, .nav-link {
            font-family: inherit !important;
            color: #f8fafc !important; /* Ensure text is visible on dark background */
        }}
        
        /* Ensure text elements have proper contrast */
        .text-muted {
            color: #94a3b8 !important; /* Light gray for muted text */
        }}
        
        .text-secondary {
            color: #cbd5e1 !important; /* Medium gray for secondary text */
        }}
        
        .card {
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid #334155;
            border-radius: 15px;
            color: #f8fafc !important; /* Ensure card text is visible */
        }}
        
        .metric-card {
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid #334155;
            border-radius: 15px;
            padding: 1rem;
            text-align: center;
            color: #f8fafc !important; /* Ensure metric card text is visible */
        }}
        
        .metric-card .metric-value {
            font-size: 2rem;
            font-weight: 700;
            color: #f8fafc !important; /* Ensure metric values are visible */
        }}
        
        .metric-card .metric-label {
            font-size: 1rem;
            color: #94a3b8 !important; /* Light gray for labels */
        }}
        
        .chart-container {
            width: 100%;
            height: 400px;
        }}
        
        .chart-container canvas {
            width: 100%;
            height: 100%;
        }}
        
        /* Stat card styling */
        .stat-card h3 {
            color: #f8fafc !important; /* Ensure stat card headings are visible */
        }}
        
        .stat-card p {
            color: #94a3b8 !important; /* Light gray for stat card text */
        }}
        
        /* Risk level styling */
        .risk-high {
            color: #ef4444 !important; /* Red for high risk */
        }}
        
        .risk-medium {
            color: #f59e0b !important; /* Yellow for medium risk */
        }}
        
        .risk-low {
            color: #06b6d4 !important; /* Cyan for low risk */
        }}
        
        /* Table and row styling */
        .row {
            color: #f8fafc !important; /* Ensure row text is visible */
        }}
        
        .col-6 strong {
            color: #f8fafc !important; /* Ensure strong text is visible */
        }}
        
        .col-6 {
            color: #cbd5e1 !important; /* Medium gray for regular text */
        }}
        
        /* Additional text visibility enhancements */
        .card-header {
            color: #f8fafc !important;
            background: rgba(30, 41, 59, 0.9) !important;
        }}
        
        .card-header h2, .card-header h3, .card-header h4, .card-header h5 {
            color: #f8fafc !important;
        }}
        
        .card-body {
            color: #f8fafc !important;
        }}
        
        .card-body h5 {
            color: #f8fafc !important;
        }}
        
        .btn-primary {
            color: #ffffff !important;
            background-color: #3b82f6 !important;
            border-color: #3b82f6 !important;
        }}
        
        .btn-success {
            color: #ffffff !important;
            background-color: #10b981 !important;
            border-color: #10b981 !important;
        }}
        
        .btn-secondary {
            color: #ffffff !important;
            background-color: #64748b !important;
            border-color: #64748b !important;
        }}
        
        /* Ensure all text elements in charts have proper contrast */
        .chartjs-render-monitor {
            color: #f8fafc !important;
        }}
        
        /* Fix for text inside chart legends */
        .chart-legend {
            color: #f8fafc !important;
        }}
        
        /* Ensure all links are visible */
        a {
            color: #60a5fa !important;
        }}
        
        a:hover {
            color: #93c5fd !important;
        }}
        
        /* Ensure all form elements are visible */
        input, select, textarea {
            color: #f8fafc !important;
            background-color: rgba(30, 41, 59, 0.8) !important;
            border: 1px solid #334155 !important;
        }}
        
        /* Ensure all badges are visible */
        .badge {
            color: #ffffff !important;
        }}
        
        /* Ensure all alert messages are visible */
        .alert {
            color: #f8fafc !important;
        }}
        
        /* Ensure all list items are visible */
        li {
            color: #f8fafc !important;
        }}
        
        /* Ensure all table text is visible */
        table, th, td {
            color: #f8fafc !important;
        }}
        
        /* Ensure all modal content is visible */
        .modal-content {
            color: #f8fafc !important;
            background-color: #1e293b !important;
        }}
        
        /* Ensure all popover content is visible */
        .popover {
            color: #f8fafc !important;
            background-color: #1e293b !important;
        }}
        
        /* Ensure all tooltip content is visible */
        .tooltip-inner {
            color: #f8fafc !important;
            background-color: #0f172a !important;
        }}
    </style>
</head>
<body>
    <div class="container py-5">
        <h1 class="text-center mb-4">ThreatX System Health</h1>
        <div class="row mb-4">
            <div class="col-md-4">
                <div class="metric-card">
                    <div class="metric-value" id="totalThreats">0</div>
                    <div class="metric-label">Total Threats</div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="metric-card">
                    <div class="metric-value" id="activeUsers">0</div>
                    <div class="metric-label">Active Users</div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="metric-card">
                    <div class="metric-value" id="suspiciousIPs">0</div>
                    <div class="metric-label">Suspicious IPs</div>
                </div>
            </div>
        </div>
        <div class="row mb-4">
            <div class="col-md-6">
                <h2 class="mb-3">Top Active Users</h2>
                <div id="activeUsersList"></div>
            </div>
            <div class="col-md-6">
                <h2 class="mb-3">Suspicious IPs</h2>
                <div id="suspiciousIps"></div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        function loadDashboardData() {
            fetch('/api/dashboard-data')
                .then(response => response.json())
                .then(data => {
                    updateActiveUsers(data.user_profiles);
                    updateSuspiciousIPs(data.suspicious_ips);
                    updateStats(data.stats);
                })
                .catch(error => console.error('Error fetching dashboard data:', error));
        }
        
        function updateActiveUsers(profiles) {
            const container = document.getElementById('activeUsersList');
            const profilesArray = Object.values(profiles);
            
            if (profilesArray.length === 0) {
                container.innerHTML = '<div class="text-center py-3"><i class="fas fa-users fa-2x text-warning mb-2"></i><p class="text-secondary">No active users</p></div>';
                return;
            }
            
            const html = profilesArray.slice(0, 5).map(user => `
                <div class="d-flex align-items-center mb-3 p-2 rounded" style="background: rgba(30, 41, 59, 0.5);">
                    <div class="me-3">
                        <i class="fas fa-user"></i>
                    </div>
                    <div class="flex-grow-1">
                        <div class="small fw-bold">${user.user_id}</div>
                        <div class="small text-secondary">Risk: ${user.current_risk_score.toFixed(2)}</div>
                    </div>
                </div>
            `).join('');
            
            container.innerHTML = html;
        }
        
        function updateSuspiciousIPs(ips) {
            const container = document.getElementById('suspiciousIps');
            const ipsArray = Object.values(ips);
            
            if (ipsArray.length === 0) {
                container.innerHTML = '<div class="text-center py-3"><i class="fas fa-globe fa-2x text-warning mb-2"></i><p class="text-secondary">No suspicious IPs</p></div>';
                return;
            }
            
            const html = ipsArray.slice(0, 5).map(ip => `
                <div class="d-flex align-items-center mb-3 p-2 rounded" style="background: rgba(30, 41, 59, 0.5);">
                    <div class="me-3">
                        <i class="fas fa-${ip.is_blocked ? 'ban' : 'exclamation-triangle'} ${ip.is_blocked ? 'text-danger' : 'text-warning'}"></i>
                    </div>
                    <div class="flex-grow-1">
                        <div class="small fw-bold">${ip.ip_address}</div>
                        <div class="small text-secondary">${ip.threat_count} threats</div>
                    </div>
                </div>
            `).join('');
            
            container.innerHTML = html;
        }
        
        function updateStats(stats) {
            document.getElementById('totalThreats').textContent = stats.total_threats || 0;
            document.getElementById('activeUsers').textContent = Object.keys(user_profiles || {}).length;
            document.getElementById('suspiciousIPs').textContent = Object.keys(suspicious_ips || {}).length;
        }
        
        // Auto-refresh
        loadDashboardData();
        setInterval(loadDashboardData, 30000);
        
        // Add smooth scrolling
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                document.querySelector(this.getAttribute('href')).scrollIntoView({
                    behavior: 'smooth'
                });
            });
        });
    </script>
</body>
</html>
    """
    
    return health_html



@app.route('/api/detect-threat', methods=['POST'])
def detect_threat():
    """Main threat detection endpoint"""
    try:
        log_data = request.json
        if not log_data:
            return jsonify({'error': 'No log data provided'}), 400
        
        result = detector.analyze(log_data)
        logger.info(f"Threat analysis: {result['risk_level']} risk detected")
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error in threat detection: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user-risk-profile/<user_id>')
def get_user_profile(user_id):
    """Get user risk profile"""
    if user_id in user_profiles:
        return jsonify(user_profiles[user_id])
    else:
        return jsonify({
            'user_id': user_id,
            'current_risk_score': 0.5,
            'total_alerts': 0,
            'message': 'No profile found'
        })

@app.route('/api/threat-statistics')
def get_threat_statistics():
    """Get threat statistics with formatted HTML display"""
    now = datetime.utcnow()
    
    # Count threats by level in last 24h
    recent_threats = [t for t in threat_data if (now - t['timestamp']).total_seconds() < 86400]
    
    threat_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'NORMAL': 0}
    threat_categories = {'DoS': 0, 'Probe': 0, 'R2L': 0, 'U2R': 0, 'Normal': 0, 'Unknown': 0}
    
    for threat in recent_threats:
        level = threat['result']['risk_level']
        category = threat['result'].get('threat_category', 'Unknown')
        threat_counts[level] += 1
        if category in threat_categories:
            threat_categories[category] += 1
        else:
            threat_categories['Unknown'] += 1
    
    stats_data = {
        'time_range': '24h',
        'total_threats': len(recent_threats),
        'threat_counts': threat_counts,
        'threat_categories': threat_categories,
        'recent_count': len(recent_threats),
        'generated_at': now.isoformat(),
        'dataset_informed': detector.use_enhanced,
        'models_active': detector.use_enhanced
    }
    
    # Check if request wants JSON
    if request.headers.get('Accept') == 'application/json' or request.args.get('format') == 'json':
        return jsonify(stats_data)
    
    # Calculate percentages
    total = max(1, stats_data['total_threats'])  # Avoid division by zero
    threat_percentages = {k: round((v/total)*100, 1) for k, v in threat_counts.items()}
    category_percentages = {k: round((v/total)*100, 1) for k, v in threat_categories.items()}
    
    # Use regular string formatting to avoid issues with curly braces in CSS/JS
    analysis_type = 'success' if stats_data['dataset_informed'] else 'warning'
    analysis_text = 'Dataset-Informed ML' if stats_data['dataset_informed'] else 'Heuristic Rules'
    
    # Return formatted HTML using format() method with proper escaping for JS
    stats_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ThreatX Statistics Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet">
    
    <!-- Enhanced font loading strategies for better compatibility -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Source+Sans+Pro:wght@300;400;600;700&display=swap" rel="stylesheet">
    
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');
        @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap');
        
        /* Enhanced font fallback strategy */
        body {{
            font-family: 'Inter', 'Roboto', 'Source Sans Pro', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #f8fafc;
            min-height: 100vh;
            font-size: 16px;
            line-height: 1.6;
        }}
        
        /* Ensure comprehensive font inheritance */
        *, *::before, *::after {{
            font-family: inherit;
        }}
        
        /* Enhanced Font Awesome Icon Fix */
        .fa, .fas, .far, .fal, .fad, .fab, .fa-solid, .fa-regular, .fa-brands, .fa-sharp,
        i[class*="fa-"] {{
            font-family: 'Font Awesome 6 Free' !important;
            font-weight: 900 !important;
            font-style: normal !important;
            font-variant: normal !important;
            text-rendering: auto !important;
            line-height: 1 !important;
            -webkit-font-smoothing: antialiased !important;
            -moz-osx-font-smoothing: grayscale !important;
            display: inline-block !important;
            color: #f8fafc !important; /* Ensure icons are visible */
        }}
        
        .fa-brands, .fab {{
            font-family: 'Font Awesome 6 Brands' !important;
            font-weight: 400 !important;
        }}
        
        .fa-sharp, .fass {{
            font-family: 'Font Awesome 6 Sharp' !important;
        }}
        
        /* Ensure specific icons mentioned in the issue are visible */
        .fa-bolt, .fa-vial, .fa-shield-virus,
        .fa-bolt.me-2, .fa-vial.me-2, .fa-shield-virus.me-2 {{
            color: #f8fafc !important;
            display: inline-block !important;
        }}
        
        /* Additional fixes for icon visibility */
        i[class*="fa-"] {{
            display: inline-block !important;
            font-style: normal !important;
            font-variant: normal !important;
            text-rendering: auto !important;
            line-height: 1 !important;
        }}
        
        /* Ensure icons in buttons and nav links are visible */
        .btn .fa, .btn .fas, .btn .far, .btn .fab,
        .nav-link .fa, .nav-link .fas, .nav-link .far, .nav-link .fab,
        .card .fa, .card .fas, .card .far, .card .fab {{
            color: inherit !important;
        }}
        
        /* Force font inheritance for all elements with enhanced specificity */
        h1, h2, h3, h4, h5, h6, p, span, div, a, button, input, select, textarea, label, strong, em, .card, .card-header, .card-body, .metric-card, .badge, .btn {{
            font-family: inherit !important;
            color: #f8fafc !important; /* Ensure text is visible on dark background */
        }}
        
        /* Bootstrap component overrides */
        .btn, .form-control, .form-select, .navbar, .navbar-brand, .nav-link {{
            font-family: inherit !important;
            color: #f8fafc !important; /* Ensure text is visible on dark background */
        }}
        
        /* Ensure text elements have proper contrast */
        .text-muted {{
            color: #94a3b8 !important; /* Light gray for muted text */
        }}
        
        .text-secondary {{
            color: #cbd5e1 !important; /* Medium gray for secondary text */
        }}
        
        .card {{
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid #334155;
            border-radius: 15px;
            color: #f8fafc !important; /* Ensure card text is visible */
        }}
        
        .metric-card {{
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid #334155;
            border-radius: 15px;
            padding: 1rem;
            text-align: center;
            color: #f8fafc !important; /* Ensure metric card text is visible */
        }}
        
        .metric-card .metric-value {{
            font-size: 2rem;
            font-weight: 700;
            color: #f8fafc !important; /* Ensure metric values are visible */
        }}
        
        .metric-card .metric-label {{
            font-size: 1rem;
            color: #94a3b8 !important; /* Light gray for labels */
        }}
        
        .chart-container {{
            width: 100%;
            height: 400px;
        }}
        
        .chart-container canvas {{
            width: 100%;
            height: 100%;
        }}
        
        /* Stat card styling */
        .stat-card h3 {{
            color: #f8fafc !important; /* Ensure stat card headings are visible */
        }}
        
        .stat-card p {{
            color: #94a3b8 !important; /* Light gray for stat card text */
        }}
        
        /* Risk level styling */
        .risk-high {{
            color: #ef4444 !important; /* Red for high risk */
        }}
        
        .risk-medium {{
            color: #f59e0b !important; /* Yellow for medium risk */
        }}
        
        .risk-low {{
            color: #06b6d4 !important; /* Cyan for low risk */
        }}
        
        /* Table and row styling */
        .row {{
            color: #f8fafc !important; /* Ensure row text is visible */
        }}
        
        .col-6 strong {{
            color: #f8fafc !important; /* Ensure strong text is visible */
        }}
        
        .col-6 {{
            color: #cbd5e1 !important; /* Medium gray for regular text */
        }}
        
        /* Additional text visibility enhancements */
        .card-header {{
            color: #f8fafc !important;
            background: rgba(30, 41, 59, 0.9) !important;
        }}
        
        .card-header h2, .card-header h3, .card-header h4, .card-header h5 {{
            color: #f8fafc !important;
        }}
        
        .card-body {{
            color: #f8fafc !important;
        }}
        
        .card-body h5 {{
            color: #f8fafc !important;
        }}
        
        .btn-primary {{
            color: #ffffff !important;
            background-color: #3b82f6 !important;
            border-color: #3b82f6 !important;
        }}
        
        .btn-success {{
            color: #ffffff !important;
            background-color: #10b981 !important;
            border-color: #10b981 !important;
        }}
        
        .btn-secondary {{
            color: #ffffff !important;
            background-color: #64748b !important;
            border-color: #64748b !important;
        }}
        
        /* Ensure all text elements in charts have proper contrast */
        .chartjs-render-monitor {{
            color: #f8fafc !important;
        }}
        
        /* Fix for text inside chart legends */
        .chart-legend {{
            color: #f8fafc !important;
        }}
        
        /* Ensure all links are visible */
        a {{
            color: #60a5fa !important;
        }}
        
        a:hover {{
            color: #93c5fd !important;
        }}
        
        /* Ensure all form elements are visible */
        input, select, textarea {{
            color: #f8fafc !important;
            background-color: rgba(30, 41, 59, 0.8) !important;
            border: 1px solid #334155 !important;
        }}
        
        /* Ensure all badges are visible */
        .badge {{
            color: #ffffff !important;
        }}
        
        /* Ensure all alert messages are visible */
        .alert {{
            color: #f8fafc !important;
        }}
        
        /* Ensure all list items are visible */
        li {{
            color: #f8fafc !important;
        }}
        
        /* Ensure all table text is visible */
        table, th, td {{
            color: #f8fafc !important;
        }}
        
        /* Ensure all modal content is visible */
        .modal-content {{
            color: #f8fafc !important;
            background-color: #1e293b !important;
        }}
        
        /* Ensure all popover content is visible */
        .popover {{
            color: #f8fafc !important;
            background-color: #1e293b !important;
        }}
        
        /* Ensure all tooltip content is visible */
        .tooltip-inner {{
            color: #f8fafc !important;
            background-color: #0f172a !important;
        }}
    </style>
</head>
<body>
    <div class="container mt-4">
        <div class="row">
            <div class="col-12">
                <div class="card">
                    <div class="card-header text-center">
                        <h2><i class="fas fa-chart-bar me-2"></i>ThreatX Security Statistics</h2>
                        <p class="mb-0 text-muted">Real-time threat analysis and security metrics (Last 24 hours)</p>
                    </div>
                    <div class="card-body">
                        <!-- Overall Stats -->
                        <div class="row mb-4">
                            <div class="col-md-3">
                                <div class="stat-card">
                                    <h3 class="text-info">{stats_data_total_threats}</h3>
                                    <p class="mb-0 text-secondary">Total Threats</p>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="stat-card">
                                    <h3 class="risk-high">{threat_counts_HIGH}</h3>
                                    <p class="mb-0 text-secondary">High Risk</p>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="stat-card">
                                    <h3 class="risk-medium">{threat_counts_MEDIUM}</h3>
                                    <p class="mb-0 text-secondary">Medium Risk</p>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="stat-card">
                                    <h3 class="risk-low">{threat_counts_LOW}</h3>
                                    <p class="mb-0 text-secondary">Low Risk</p>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Charts Row -->
                        <div class="row">
                            <div class="col-md-6">
                                <div class="card">
                                    <div class="card-header">
                                        <h5><i class="fas fa-exclamation-triangle me-2"></i>Risk Level Distribution</h5>
                                    </div>
                                    <div class="card-body">
                                        <div class="chart-container">
                                            <canvas id="riskChart"></canvas>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="card">
                                    <div class="card-header">
                                        <h5><i class="fas fa-shield-virus me-2"></i>Attack Category Distribution</h5>
                                    </div>
                                    <div class="card-body">
                                        <div class="chart-container">
                                            <canvas id="categoryChart"></canvas>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Detailed Breakdown -->
                        <div class="row mt-4">
                            <div class="col-md-6">
                                <div class="card">
                                    <div class="card-header">
                                        <h5>Risk Level Breakdown</h5>
                                    </div>
                                    <div class="card-body">
                                        <div class="row mb-2">
                                            <div class="col-6"><strong class="text-white">High Risk:</strong></div>
                                            <div class="col-6 text-secondary">{threat_counts_HIGH} ({threat_percentages_HIGH}%)</div>
                                        </div>
                                        <div class="row mb-2">
                                            <div class="col-6"><strong class="text-white">Medium Risk:</strong></div>
                                            <div class="col-6 text-secondary">{threat_counts_MEDIUM} ({threat_percentages_MEDIUM}%)</div>
                                        </div>
                                        <div class="row mb-2">
                                            <div class="col-6"><strong class="text-white">Low Risk:</strong></div>
                                            <div class="col-6 text-secondary">{threat_counts_LOW} ({threat_percentages_LOW}%)</div>
                                        </div>
                                        <div class="row mb-2">
                                            <div class="col-6"><strong class="text-white">Normal:</strong></div>
                                            <div class="col-6 text-secondary">{threat_counts_NORMAL} ({threat_percentages_NORMAL}%)</div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="card">
                                    <div class="card-header">
                                        <h5>Attack Category Breakdown</h5>
                                    </div>
                                    <div class="card-body">
                                        <div class="row mb-2">
                                            <div class="col-6"><strong class="text-white">DoS Attacks:</strong></div>
                                            <div class="col-6 text-secondary">{threat_categories_DoS} ({category_percentages_DoS}%)</div>
                                        </div>
                                        <div class="row mb-2">
                                            <div class="col-6"><strong class="text-white">Probe Attacks:</strong></div>
                                            <div class="col-6 text-secondary">{threat_categories_Probe} ({category_percentages_Probe}%)</div>
                                        </div>
                                        <div class="row mb-2">
                                            <div class="col-6"><strong class="text-white">R2L Attacks:</strong></div>
                                            <div class="col-6 text-secondary">{threat_categories_R2L} ({category_percentages_R2L}%)</div>
                                        </div>
                                        <div class="row mb-2">
                                            <div class="col-6"><strong class="text-white">U2R Attacks:</strong></div>
                                            <div class="col-6 text-secondary">{threat_categories_U2R} ({category_percentages_U2R}%)</div>
                                        </div>
                                        <div class="row mb-2">
                                            <div class="col-6"><strong class="text-white">Normal:</strong></div>
                                            <div class="col-6 text-secondary">{threat_categories_Normal} ({category_percentages_Normal}%)</div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- System Info -->
                        <div class="row mt-4">
                            <div class="col-12">
                                <div class="card">
                                    <div class="card-header">
                                        <h5><i class="fas fa-info-circle me-2"></i>System Information</h5>
                                    </div>
                                    <div class="card-body">
                                        <div class="row">
                                            <div class="col-md-4">
                                                <strong class="text-white">Generated At:</strong><br>
                                                <span class="text-muted">{stats_data_generated_at}</span>
                                            </div>
                                            <div class="col-md-4">
                                                <strong class="text-white">Analysis Type:</strong><br>
                                                <span class="text-{analysis_type}">{analysis_text}</span>
                                            </div>
                                            <div class="col-md-4">
                                                <strong class="text-white">Time Range:</strong><br>
                                                <span class="text-muted">{stats_data_time_range}</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="text-center mt-4">
                            <a href="/" class="btn btn-primary me-2">
                                <i class="fas fa-home me-2"></i>Back to Dashboard
                            </a>
                            <a href="/health" class="btn btn-success me-2">
                                <i class="fas fa-heartbeat me-2"></i>System Health
                            </a>
                            <a href="/api/threat-statistics?format=json" class="btn btn-secondary">
                                <i class="fas fa-code me-2"></i>JSON Format
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Risk Level Chart
        const riskCtx = document.getElementById('riskChart').getContext('2d');
        new Chart(riskCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['High', 'Medium', 'Low', 'Normal'],
                datasets: [{{
                    data: [{threat_counts_HIGH}, {threat_counts_MEDIUM}, {threat_counts_LOW}, {threat_counts_NORMAL}],
                    backgroundColor: ['#ef4444', '#f59e0b', '#06b6d4', '#10b981'],
                    borderWidth: 2,
                    borderColor: '#334155'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        labels: {{ 
                            color: '#f8fafc',
                            font: {{
                                family: "'Inter', 'Roboto', 'Source Sans Pro', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif"
                            }}
                        }}
                    }}
                }}
            }}
        }});
        
        // Category Chart
        const categoryCtx = document.getElementById('categoryChart').getContext('2d');
        new Chart(categoryCtx, {{
            type: 'bar',
            data: {{
                labels: ['DoS', 'Probe', 'R2L', 'U2R', 'Normal'],
                datasets: [{{
                    data: [{threat_categories_DoS}, {threat_categories_Probe}, {threat_categories_R2L}, {threat_categories_U2R}, {threat_categories_Normal}],
                    backgroundColor: ['#ef4444', '#f59e0b', '#06b6d4', '#8b5cf6', '#10b981'],
                    borderWidth: 1,
                    borderColor: '#334155'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    y: {{
                        ticks: {{ 
                            color: '#f8fafc',
                            font: {{
                                family: "'Inter', 'Roboto', 'Source Sans Pro', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif"
                            }}
                        }},
                        grid: {{ color: '#334155' }}
                    }},
                    x: {{
                        ticks: {{ 
                            color: '#f8fafc',
                            font: {{
                                family: "'Inter', 'Roboto', 'Source Sans Pro', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif"
                            }}
                        }},
                        grid: {{ color: '#334155' }}
                    }}
                }}
            }}
        }});
    </script>
    
</body>
</html>
    """.format(
        stats_data_total_threats=stats_data['total_threats'],
        threat_counts_HIGH=threat_counts['HIGH'],
        threat_counts_MEDIUM=threat_counts['MEDIUM'],
        threat_counts_LOW=threat_counts['LOW'],
        threat_counts_NORMAL=threat_counts['NORMAL'],
        threat_percentages_HIGH=threat_percentages['HIGH'],
        threat_percentages_MEDIUM=threat_percentages['MEDIUM'],
        threat_percentages_LOW=threat_percentages['LOW'],
        threat_percentages_NORMAL=threat_percentages['NORMAL'],
        threat_categories_DoS=threat_categories['DoS'],
        threat_categories_Probe=threat_categories['Probe'],
        threat_categories_R2L=threat_categories['R2L'],
        threat_categories_U2R=threat_categories['U2R'],
        threat_categories_Normal=threat_categories['Normal'],
        category_percentages_DoS=category_percentages['DoS'],
        category_percentages_Probe=category_percentages['Probe'],
        category_percentages_R2L=category_percentages['R2L'],
        category_percentages_U2R=category_percentages['U2R'],
        category_percentages_Normal=category_percentages['Normal'],
        stats_data_generated_at=stats_data['generated_at'],
        analysis_type=analysis_type,
        analysis_text=analysis_text,
        stats_data_time_range=stats_data['time_range']
    )
    
    return stats_html

@app.route('/api/suspicious-ips')
def get_suspicious_ips():
    """Get suspicious IPs"""
    return jsonify(suspicious_ips)

@app.route('/api/recent-threats')
def get_recent_threats():
    """Get recent threats"""
    recent = sorted(threat_data, key=lambda x: x['timestamp'], reverse=True)[:10]
    return jsonify(recent)

@app.route('/api/user-profiles')
def get_user_profiles():
    """Get all user profiles"""
    return jsonify(user_profiles)

def generate_sample_data():
    """Generate enhanced sample data with NSL-KDD inspired attack scenarios"""
    sample_logs = [
        # Normal activity
        {
            'ip_address': '192.168.1.100',
            'user_id': 'alice.johnson',
            'event_type': 'login',
            'failed_login_attempts': 0,
            'bytes_transferred': 1024,
            'connection_rate': 1
        },
        # R2L attack (brute force)
        {
            'ip_address': '198.51.100.30',
            'user_id': 'charlie.brown',
            'event_type': 'brute_force',
            'failed_login_attempts': 8,
            'bytes_transferred': 512,
            'dictionary_attack': True
        },
        # DoS attack
        {
            'ip_address': '185.220.101.5',
            'user_id': 'unknown',
            'event_type': 'ddos',
            'failed_login_attempts': 25,
            'bytes_transferred': 75000000,
            'connection_rate': 150
        },
        # Probe attack
        {
            'ip_address': '91.240.118.172',
            'user_id': 'scanner_bot',
            'event_type': 'port_scan',
            'failed_login_attempts': 0,
            'bytes_transferred': 2048,
            'unique_ports_accessed': 50,
            'scan_duration': 300
        },
        # U2R attack
        {
            'ip_address': '104.244.76.187',
            'user_id': 'compromised_user',
            'event_type': 'buffer_overflow',
            'failed_login_attempts': 1,
            'bytes_transferred': 4096,
            'privilege_escalation': True,
            'root_access_attempt': True
        },
        # Behavioral anomaly
        {
            'ip_address': '203.0.113.45',
            'user_id': 'night_worker',
            'event_type': 'login',
            'failed_login_attempts': 0,
            'bytes_transferred': 512000,
            'geographic_distance': 8000,
            'session_duration': 7200
        },
        # Unknown threat simulation
        {
            'ip_address': '203.0.113.199',
            'user_id': 'unknown_actor',
            'event_type': 'unknown_attack',
            'failed_login_attempts': 0,
            'bytes_transferred': 150000000,
            'protocol_violation': True,
            'encrypted_suspicious_traffic': True,
            'unknown_user_agent': True,
            'error_rate': 0.7
        }
    ]
    
    for log in sample_logs:
        log['timestamp'] = datetime.utcnow().isoformat()
        result = detector.analyze(log)
        logger.info(f"Sample analysis: {log['event_type']} -> {result['risk_level']} ({result['threat_category']})")
    
    logger.info("Generated enhanced sample threat data with dataset-inspired scenarios")

if __name__ == '__main__':
    logger.info("🛡️ Starting ThreatX Test Server...")
    
    # Generate some sample data
    generate_sample_data()
    
    print("=" * 70)
    print("🛡️  ThreatX AI-Powered Threat Detector - Enhanced Test Server")
    print("🔬 With NSL-KDD & CICIDS Dataset Integration")
    print("=" * 70)
    print("")
    print("🚀 Server starting on: http://localhost:5000")
    print("📊 Enhanced Dashboard: http://localhost:5000")
    print("🔍 Health Check: http://localhost:5000/health")
    print("📚 API Statistics: http://localhost:5000/api/threat-statistics")
    print("")
    print("✨ Enhanced Features:")
    print("  • Real cybersecurity dataset integration (NSL-KDD)")
    print("  • Advanced ML models (RF, GB, Isolation Forest)")
    print("  • DoS, Probe, R2L, U2R attack detection")
    print("  • 🚨 UNKNOWN THREAT DETECTION (Zero-day capabilities)")
    print("  • Behavioral anomaly detection")
    print("  • Statistical anomaly analysis")
    print("  • Threat intelligence integration")
    print("  • Real-time risk assessment")
    print("")
    print("🧪 Enhanced Test scenarios:")
    print("  • Normal activity (baseline behavior)")
    print("  • R2L attacks (brute force, credential stuffing)")
    print("  • DoS attacks (DDoS, service flooding)")
    print("  • Probe attacks (network scanning, port probes)")
    print("  • U2R attacks (privilege escalation, buffer overflow)")
    print("  • 🔮 UNKNOWN THREATS (zero-day simulation)")
    print("")
    print("📈 Dataset Intelligence:")
    if detector.use_enhanced:
        print("  • ✅ Enhanced detector with dataset training active")
        print("  • ✅ NSL-KDD attack patterns integrated")
        print("  • ✅ Machine learning models available")
    else:
        print("  • ⚠️  Using dataset-informed heuristic analysis")
        print("  • ⚠️  Enhanced ML models not available")
    print("")
    print("Press Ctrl+C to stop the server")
    print("=" * 70)
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        use_reloader=False
    )