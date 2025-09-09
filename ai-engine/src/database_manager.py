import psycopg2
from psycopg2.extras import RealDictCursor
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from contextlib import contextmanager

from config import Config

logger = logging.getLogger(__name__)

class DatabaseManager:
    """
    Manages database operations for threat detection system
    """
    
    def __init__(self):
        self.connection_string = Config.DATABASE_URL
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize database tables if they don't exist"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Create tables
                self._create_tables(cursor)
                conn.commit()
                
                logger.info("Database initialized successfully")
                
        except Exception as e:
            logger.error(f"Error initializing database: {str(e)}")
            # Don't raise exception to allow app to start without DB
    
    def _create_tables(self, cursor):
        """Create necessary database tables"""
        
        # Log entries table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS log_entries (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
                ip_address INET,
                user_id VARCHAR(255),
                event_type VARCHAR(100),
                raw_data JSONB,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
        """)
        
        # Threat analyses table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_analyses (
                id SERIAL PRIMARY KEY,
                log_entry_id INTEGER REFERENCES log_entries(id),
                risk_score FLOAT NOT NULL,
                risk_level VARCHAR(20) NOT NULL,
                model_scores JSONB,
                threat_types TEXT[],
                recommendations TEXT[],
                confidence FLOAT,
                analysis_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
        """)
        
        # User risk profiles table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_risk_profiles (
                user_id VARCHAR(255) PRIMARY KEY,
                current_risk_score FLOAT DEFAULT 0.5,
                total_alerts INTEGER DEFAULT 0,
                last_suspicious_activity TIMESTAMP WITH TIME ZONE,
                risk_history JSONB,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
        """)
        
        # Suspicious IPs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS suspicious_ips (
                ip_address INET PRIMARY KEY,
                reputation_score FLOAT DEFAULT 0.5,
                threat_count INTEGER DEFAULT 0,
                last_threat_time TIMESTAMP WITH TIME ZONE,
                country_code VARCHAR(2),
                is_blocked BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
        """)
        
        # Create indexes for better performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_log_entries_timestamp ON log_entries(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_log_entries_ip ON log_entries(ip_address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_log_entries_user ON log_entries(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_analyses_risk ON threat_analyses(risk_level)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_analyses_timestamp ON threat_analyses(analysis_timestamp)")
    
    @contextmanager
    def get_connection(self):
        """Get database connection with context manager"""
        conn = None
        try:
            conn = psycopg2.connect(
                self.connection_string,
                cursor_factory=RealDictCursor
            )
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database connection error: {str(e)}")
            raise
        finally:
            if conn:
                conn.close()
    
    def store_threat_analysis(self, log_data: Dict[str, Any], threat_result: Dict[str, Any]) -> Optional[int]:
        """Store log entry and threat analysis results"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Insert log entry
                cursor.execute("""
                    INSERT INTO log_entries (timestamp, ip_address, user_id, event_type, raw_data)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                """, (
                    log_data.get('timestamp', datetime.utcnow()),
                    log_data.get('ip_address'),
                    log_data.get('user_id'),
                    log_data.get('event_type', 'unknown'),
                    json.dumps(log_data)
                ))
                
                log_entry_id = cursor.fetchone()['id']
                
                # Insert threat analysis
                cursor.execute("""
                    INSERT INTO threat_analyses 
                    (log_entry_id, risk_score, risk_level, model_scores, threat_types, recommendations, confidence)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (
                    log_entry_id,
                    threat_result.get('risk_score', 0),
                    threat_result.get('risk_level', 'UNKNOWN'),
                    json.dumps(threat_result.get('model_scores', {})),
                    threat_result.get('threat_types', []),
                    threat_result.get('recommendations', []),
                    threat_result.get('confidence', 0)
                ))
                
                # Update user risk profile if user_id exists
                user_id = log_data.get('user_id')
                if user_id:
                    self._update_user_risk_profile(cursor, user_id, threat_result)
                
                # Update suspicious IP if high risk
                ip_address = log_data.get('ip_address')
                if ip_address and threat_result.get('risk_level') in ['HIGH', 'MEDIUM']:
                    self._update_suspicious_ip(cursor, ip_address, threat_result)
                
                conn.commit()
                return log_entry_id
                
        except Exception as e:
            logger.error(f"Error storing threat analysis: {str(e)}")
            return None
    
    def _update_user_risk_profile(self, cursor, user_id: str, threat_result: Dict[str, Any]):
        """Update user risk profile"""
        try:
            # Get current profile or create new one
            cursor.execute("""
                INSERT INTO user_risk_profiles (user_id, current_risk_score)
                VALUES (%s, %s)
                ON CONFLICT (user_id) DO NOTHING
            """, (user_id, threat_result.get('risk_score', 0.5)))
            
            # Update profile
            risk_score = threat_result.get('risk_score', 0)
            is_suspicious = threat_result.get('risk_level') in ['HIGH', 'MEDIUM']
            
            cursor.execute("""
                UPDATE user_risk_profiles 
                SET current_risk_score = %s,
                    total_alerts = total_alerts + %s,
                    last_suspicious_activity = CASE WHEN %s THEN NOW() ELSE last_suspicious_activity END,
                    updated_at = NOW()
                WHERE user_id = %s
            """, (risk_score, 1 if is_suspicious else 0, is_suspicious, user_id))
            
        except Exception as e:
            logger.error(f"Error updating user risk profile: {str(e)}")
    
    def _update_suspicious_ip(self, cursor, ip_address: str, threat_result: Dict[str, Any]):
        """Update suspicious IP tracking"""
        try:
            cursor.execute("""
                INSERT INTO suspicious_ips (ip_address, reputation_score, threat_count, last_threat_time)
                VALUES (%s, %s, 1, NOW())
                ON CONFLICT (ip_address) DO UPDATE SET
                    threat_count = suspicious_ips.threat_count + 1,
                    last_threat_time = NOW(),
                    updated_at = NOW()
            """, (ip_address, 1.0 - threat_result.get('risk_score', 0)))
            
        except Exception as e:
            logger.error(f"Error updating suspicious IP: {str(e)}")
    
    def get_user_risk_profile(self, user_id: str) -> Dict[str, Any]:
        """Get user risk profile"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT * FROM user_risk_profiles WHERE user_id = %s
                """, (user_id,))
                
                profile = cursor.fetchone()
                
                if profile:
                    return dict(profile)
                else:
                    return {
                        'user_id': user_id,
                        'current_risk_score': 0.5,
                        'total_alerts': 0,
                        'last_suspicious_activity': None,
                        'message': 'No profile found'
                    }
                    
        except Exception as e:
            logger.error(f"Error getting user risk profile: {str(e)}")
            return {'error': 'Database error'}
    
    def get_threat_statistics(self, time_range: str = '24h') -> Dict[str, Any]:
        """Get threat statistics for dashboard"""
        try:
            # Parse time range
            if time_range == '1h':
                start_time = datetime.utcnow() - timedelta(hours=1)
            elif time_range == '24h':
                start_time = datetime.utcnow() - timedelta(hours=24)
            elif time_range == '7d':
                start_time = datetime.utcnow() - timedelta(days=7)
            elif time_range == '30d':
                start_time = datetime.utcnow() - timedelta(days=30)
            else:
                start_time = datetime.utcnow() - timedelta(hours=24)
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Total threats by level
                cursor.execute("""
                    SELECT risk_level, COUNT(*) as count
                    FROM threat_analyses
                    WHERE analysis_timestamp >= %s
                    GROUP BY risk_level
                """, (start_time,))
                
                threat_counts = {row['risk_level']: row['count'] for row in cursor.fetchall()}
                
                # Timeline data (hourly aggregation)
                cursor.execute("""
                    SELECT 
                        DATE_TRUNC('hour', analysis_timestamp) as hour,
                        risk_level,
                        COUNT(*) as count
                    FROM threat_analyses
                    WHERE analysis_timestamp >= %s
                    GROUP BY DATE_TRUNC('hour', analysis_timestamp), risk_level
                    ORDER BY hour
                """, (start_time,))
                
                timeline_data = {}
                for row in cursor.fetchall():
                    hour = row['hour'].isoformat()
                    if hour not in timeline_data:
                        timeline_data[hour] = {}
                    timeline_data[hour][row['risk_level']] = row['count']
                
                # Top suspicious IPs
                cursor.execute("""
                    SELECT ip_address, threat_count, last_threat_time
                    FROM suspicious_ips
                    WHERE last_threat_time >= %s
                    ORDER BY threat_count DESC
                    LIMIT 10
                """, (start_time,))
                
                top_suspicious_ips = [dict(row) for row in cursor.fetchall()]
                
                # Top threat types
                cursor.execute("""
                    SELECT 
                        UNNEST(threat_types) as threat_type,
                        COUNT(*) as count
                    FROM threat_analyses
                    WHERE analysis_timestamp >= %s AND threat_types IS NOT NULL
                    GROUP BY threat_type
                    ORDER BY count DESC
                    LIMIT 10
                """, (start_time,))
                
                top_threat_types = [dict(row) for row in cursor.fetchall()]
                
                return {
                    'time_range': time_range,
                    'total_threats': sum(threat_counts.values()),
                    'threat_counts': threat_counts,
                    'timeline_data': timeline_data,
                    'top_suspicious_ips': top_suspicious_ips,
                    'top_threat_types': top_threat_types,
                    'generated_at': datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            logger.error(f"Error getting threat statistics: {str(e)}")
            return {'error': 'Database error'}
    
    def get_suspicious_ips(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get list of suspicious IP addresses"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT * FROM suspicious_ips
                    ORDER BY threat_count DESC, last_threat_time DESC
                    LIMIT %s
                """, (limit,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Error getting suspicious IPs: {str(e)}")
            return []
    
    def get_recent_threats(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent threat analyses"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT 
                        ta.*,
                        le.ip_address,
                        le.user_id,
                        le.event_type
                    FROM threat_analyses ta
                    JOIN log_entries le ON ta.log_entry_id = le.id
                    ORDER BY ta.analysis_timestamp DESC
                    LIMIT %s
                """, (limit,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Error getting recent threats: {str(e)}")
            return []