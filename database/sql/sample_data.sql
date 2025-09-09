-- Sample data for ThreatX database
-- This file contains test data for development and demonstration

-- Sample log entries
INSERT INTO log_entries (timestamp, ip_address, user_id, event_type, raw_data) VALUES
('2024-01-15 08:00:00+00', '192.168.1.100', 'alice.johnson', 'login', '{"success": true, "method": "password", "user_agent": "Mozilla/5.0"}'),
('2024-01-15 08:05:00+00', '203.0.113.45', 'bob.smith', 'login', '{"success": true, "method": "password", "user_agent": "Mozilla/5.0"}'),
('2024-01-15 08:10:00+00', '198.51.100.30', 'charlie.brown', 'failed_login', '{"success": false, "method": "password", "attempts": 1}'),
('2024-01-15 08:12:00+00', '198.51.100.30', 'charlie.brown', 'failed_login', '{"success": false, "method": "password", "attempts": 2}'),
('2024-01-15 08:15:00+00', '198.51.100.30', 'charlie.brown', 'failed_login', '{"success": false, "method": "password", "attempts": 3}'),
('2024-01-15 08:18:00+00', '198.51.100.30', 'charlie.brown', 'failed_login', '{"success": false, "method": "password", "attempts": 4}'),
('2024-01-15 08:20:00+00', '198.51.100.30', 'charlie.brown', 'failed_login', '{"success": false, "method": "password", "attempts": 5}'),
('2024-01-15 08:25:00+00', '192.168.1.105', 'diana.prince', 'data_access', '{"file": "/secure/confidential.pdf", "size": 2048576}'),
('2024-01-15 08:30:00+00', '10.0.0.50', 'eve.adam', 'api_call', '{"endpoint": "/api/users", "method": "GET", "status": 200}'),
('2024-01-15 08:35:00+00', '172.16.0.25', 'frank.miller', 'file_download', '{"file": "database_backup.sql", "size": 10485760}'),
('2024-01-15 09:00:00+00', '185.220.101.5', 'unknown', 'port_scan', '{"ports": [22, 80, 443, 3389], "duration": 30}'),
('2024-01-15 09:15:00+00', '91.240.118.172', 'admin', 'admin_login', '{"success": false, "location": "Russia", "suspicious": true}'),
('2024-01-15 09:30:00+00', '192.168.1.200', 'grace.hopper', 'bulk_data_access', '{"records": 50000, "table": "user_profiles"}'),
('2024-01-15 10:00:00+00', '104.244.72.115', 'test_user', 'brute_force', '{"attempts": 25, "duration": 300, "success": false}'),
('2024-01-15 10:30:00+00', '192.168.1.150', 'henry.ford', 'unusual_activity', '{"after_hours": true, "location": "different", "risk": "medium"}');

-- Sample threat analyses
INSERT INTO threat_analyses (log_entry_id, risk_score, risk_level, model_scores, threat_types, recommendations, confidence, model_version) VALUES
(1, 0.1, 'NORMAL', '{"isolation_forest": 0.05, "random_forest": 0.15, "autoencoder": 0.1}', '{}', '{}', 0.9, 'v1.0'),
(2, 0.2, 'NORMAL', '{"isolation_forest": 0.1, "random_forest": 0.2, "autoencoder": 0.3}', '{}', '{}', 0.85, 'v1.0'),
(3, 0.4, 'LOW', '{"isolation_forest": 0.3, "random_forest": 0.4, "autoencoder": 0.5}', '{"Failed Login"}', '{"Monitor user activity"}', 0.75, 'v1.0'),
(4, 0.5, 'MEDIUM', '{"isolation_forest": 0.4, "random_forest": 0.5, "autoencoder": 0.6}', '{"Failed Login", "Brute Force"}', '{"Consider account lockout", "Monitor IP activity"}', 0.8, 'v1.0'),
(5, 0.6, 'MEDIUM', '{"isolation_forest": 0.5, "random_forest": 0.6, "autoencoder": 0.7}', '{"Brute Force Attack"}', '{"Temporary account lockout", "Alert security team"}', 0.85, 'v1.0'),
(6, 0.7, 'MEDIUM', '{"isolation_forest": 0.6, "random_forest": 0.7, "autoencoder": 0.8}', '{"Brute Force Attack"}', '{"Block IP address", "Alert security team"}', 0.9, 'v1.0'),
(7, 0.8, 'HIGH', '{"isolation_forest": 0.7, "random_forest": 0.8, "autoencoder": 0.9}', '{"Brute Force Attack", "Credential Stuffing"}', '{"Block IP immediately", "Alert security team", "Force password reset"}', 0.95, 'v1.0'),
(8, 0.3, 'LOW', '{"isolation_forest": 0.2, "random_forest": 0.3, "autoencoder": 0.4}', '{"Data Access Anomaly"}', '{"Monitor file access patterns"}', 0.7, 'v1.0'),
(9, 0.1, 'NORMAL', '{"isolation_forest": 0.05, "random_forest": 0.1, "autoencoder": 0.15}', '{}', '{}', 0.9, 'v1.0'),
(10, 0.6, 'MEDIUM', '{"isolation_forest": 0.5, "random_forest": 0.6, "autoencoder": 0.7}', '{"Data Exfiltration"}', '{"Review file access permissions", "Monitor user activity"}', 0.8, 'v1.0'),
(11, 0.9, 'HIGH', '{"isolation_forest": 0.85, "random_forest": 0.9, "autoencoder": 0.95}', '{"Port Scan", "Reconnaissance"}', '{"Block IP immediately", "Alert security team", "Monitor network traffic"}', 0.95, 'v1.0'),
(12, 0.85, 'HIGH', '{"isolation_forest": 0.8, "random_forest": 0.85, "autoencoder": 0.9}', '{"Geographic Anomaly", "Malicious IP"}', '{"Block IP address", "Alert security team", "Verify admin credentials"}', 0.9, 'v1.0'),
(13, 0.5, 'MEDIUM', '{"isolation_forest": 0.4, "random_forest": 0.5, "autoencoder": 0.6}', '{"Bulk Data Access"}', '{"Review data access patterns", "Monitor user privileges"}', 0.75, 'v1.0'),
(14, 0.95, 'HIGH', '{"isolation_forest": 0.9, "random_forest": 0.95, "autoencoder": 1.0}', '{"Brute Force Attack", "Malicious IP", "Botnet Activity"}', '{"Block IP immediately", "Alert security team", "Review all failed logins"}', 0.98, 'v1.0'),
(15, 0.4, 'LOW', '{"isolation_forest": 0.3, "random_forest": 0.4, "autoencoder": 0.5}', '{"After Hours Access", "Geographic Anomaly"}', '{"Verify user identity", "Monitor session activity"}', 0.7, 'v1.0');

-- Sample user risk profiles
INSERT INTO user_risk_profiles (user_id, current_risk_score, total_alerts, high_risk_alerts, medium_risk_alerts, last_suspicious_activity, trust_score, department, access_level, login_count, failed_login_count) VALUES
('alice.johnson', 0.1, 0, 0, 0, NULL, 0.9, 'Engineering', 'standard', 245, 2),
('bob.smith', 0.2, 1, 0, 1, '2024-01-10 14:30:00+00', 0.8, 'Marketing', 'standard', 156, 5),
('charlie.brown', 0.8, 15, 2, 8, '2024-01-15 08:20:00+00', 0.2, 'Sales', 'standard', 89, 45),
('diana.prince', 0.3, 3, 0, 2, '2024-01-12 16:45:00+00', 0.7, 'Finance', 'elevated', 312, 8),
('eve.adam', 0.1, 0, 0, 0, NULL, 0.95, 'IT', 'admin', 567, 1),
('frank.miller', 0.6, 8, 1, 4, '2024-01-15 08:35:00+00', 0.4, 'Operations', 'standard', 234, 23),
('grace.hopper', 0.5, 5, 1, 2, '2024-01-15 09:30:00+00', 0.6, 'Research', 'elevated', 445, 12),
('henry.ford', 0.4, 4, 0, 3, '2024-01-15 10:30:00+00', 0.65, 'Manufacturing', 'standard', 178, 18),
('admin', 0.85, 25, 12, 8, '2024-01-15 09:15:00+00', 0.15, 'IT', 'admin', 45, 89),
('test_user', 0.95, 50, 25, 15, '2024-01-15 10:00:00+00', 0.05, 'Unknown', 'guest', 12, 234);

-- Sample suspicious IPs
INSERT INTO suspicious_ips (ip_address, reputation_score, threat_count, last_threat_time, first_seen, country_code, country_name, is_blocked, city, region, isp, organization, attack_types, severity_level) VALUES
('198.51.100.30', 0.2, 15, '2024-01-15 08:20:00+00', '2024-01-10 12:00:00+00', 'US', 'United States', FALSE, 'Example City', 'Example State', 'Example ISP', 'Example Org', '{"Brute Force", "Credential Stuffing"}', 'HIGH'),
('185.220.101.5', 0.1, 25, '2024-01-15 09:00:00+00', '2024-01-08 15:30:00+00', 'RU', 'Russia', TRUE, 'Moscow', 'Moscow', 'Tor Network', 'Tor Project', '{"Port Scan", "Reconnaissance"}', 'HIGH'),
('91.240.118.172', 0.15, 12, '2024-01-15 09:15:00+00', '2024-01-12 09:45:00+00', 'RU', 'Russia', TRUE, 'St. Petersburg', 'St. Petersburg', 'VPS Provider', 'Hostile Network', '{"Geographic Anomaly", "Admin Access"}', 'HIGH'),
('104.244.72.115', 0.05, 45, '2024-01-15 10:00:00+00', '2024-01-05 18:20:00+00', 'CN', 'China', TRUE, 'Shanghai', 'Shanghai', 'Cloud Provider', 'Botnet C2', '{"Brute Force", "Botnet", "DDoS"}', 'CRITICAL'),
('203.0.113.45', 0.4, 3, '2024-01-12 14:30:00+00', '2024-01-01 10:15:00+00', 'AU', 'Australia', FALSE, 'Sydney', 'New South Wales', 'Telstra', 'Corporate', '{"Failed Login"}', 'MEDIUM'),
('172.16.0.25', 0.6, 2, '2024-01-15 08:35:00+00', '2024-01-14 16:20:00+00', NULL, 'Unknown', FALSE, NULL, NULL, 'Private Network', 'Internal', '{"Data Exfiltration"}', 'MEDIUM'),
('10.0.0.50', 0.8, 1, '2024-01-13 11:45:00+00', '2024-01-13 11:45:00+00', NULL, 'Unknown', FALSE, NULL, NULL, 'Private Network', 'Internal', '{"Suspicious Activity"}', 'LOW'),
('192.168.1.200', 0.5, 5, '2024-01-15 09:30:00+00', '2024-01-10 08:00:00+00', NULL, 'Unknown', FALSE, NULL, NULL, 'Private Network', 'Internal', '{"Bulk Data Access"}', 'MEDIUM'),
('8.8.8.8', 0.9, 0, NULL, '2024-01-01 00:00:00+00', 'US', 'United States', FALSE, 'Mountain View', 'California', 'Google', 'Google LLC', '{}', 'LOW'),
('1.1.1.1', 0.95, 0, NULL, '2024-01-01 00:00:00+00', 'US', 'United States', FALSE, 'San Francisco', 'California', 'Cloudflare', 'Cloudflare Inc', '{}', 'LOW');

-- Sample threat intelligence
INSERT INTO threat_intelligence (indicator_type, indicator_value, threat_type, malware_family, confidence_score, severity, source, tags, description) VALUES
('ip', '185.220.101.5', 'Tor Exit Node', NULL, 0.95, 'HIGH', 'TorProject', '{"tor", "anonymization", "privacy"}', 'Known Tor exit node with suspicious activity'),
('ip', '91.240.118.172', 'Botnet C2', 'Mirai', 0.9, 'HIGH', 'SecurityFeed', '{"botnet", "c2", "mirai"}', 'Command and control server for Mirai botnet'),
('ip', '104.244.72.115', 'Malware C2', 'Zeus', 0.85, 'CRITICAL', 'ThreatIntel', '{"malware", "banking", "trojan"}', 'Zeus banking trojan command and control'),
('domain', 'malicious-site.example', 'Phishing', NULL, 0.8, 'HIGH', 'PhishTank', '{"phishing", "credential_theft"}', 'Known phishing domain targeting financial institutions'),
('url', 'http://suspicious-download.example/malware.exe', 'Malware Distribution', 'Ransomware', 0.9, 'CRITICAL', 'MalwareBazaar', '{"malware", "ransomware", "download"}', 'Ransomware distribution URL'),
('hash', 'd41d8cd98f00b204e9800998ecf8427e', 'Malware Hash', 'Trojan', 0.7, 'MEDIUM', 'VirusTotal', '{"hash", "malware", "trojan"}', 'MD5 hash of known trojan'),
('email', 'attacker@malicious.example', 'Spam/Phishing', NULL, 0.6, 'MEDIUM', 'SpamHaus', '{"email", "spam", "phishing"}', 'Email address used in phishing campaigns'),
('ip', '198.51.100.30', 'Brute Force', NULL, 0.7, 'MEDIUM', 'Internal', '{"brute_force", "authentication"}', 'IP observed performing brute force attacks');

-- Sample model metrics
INSERT INTO model_metrics (model_name, model_version, metric_name, metric_value, dataset_size, training_time_seconds) VALUES
('isolation_forest', 'v1.0', 'precision', 0.85, 10000, 45),
('isolation_forest', 'v1.0', 'recall', 0.78, 10000, 45),
('isolation_forest', 'v1.0', 'f1_score', 0.81, 10000, 45),
('isolation_forest', 'v1.0', 'auc_roc', 0.88, 10000, 45),
('random_forest', 'v1.0', 'precision', 0.92, 10000, 120),
('random_forest', 'v1.0', 'recall', 0.89, 10000, 120),
('random_forest', 'v1.0', 'f1_score', 0.90, 10000, 120),
('random_forest', 'v1.0', 'auc_roc', 0.94, 10000, 120),
('autoencoder', 'v1.0', 'reconstruction_error', 0.045, 10000, 300),
('autoencoder', 'v1.0', 'anomaly_detection_rate', 0.82, 10000, 300);

-- Sample audit log entries
INSERT INTO audit_log (action, resource_type, resource_id, user_id, ip_address, details) VALUES
('CREATE', 'threat_analysis', '1', 'system', '127.0.0.1', '{"model_version": "v1.0", "processing_time": 150}'),
('UPDATE', 'user_risk_profile', 'charlie.brown', 'system', '127.0.0.1', '{"old_score": 0.5, "new_score": 0.8}'),
('BLOCK', 'suspicious_ip', '185.220.101.5', 'admin', '192.168.1.10', '{"reason": "High threat count", "auto_block": false}'),
('LOGIN', 'dashboard', NULL, 'admin', '192.168.1.10', '{"success": true, "method": "password"}'),
('EXPORT', 'threat_report', NULL, 'security_analyst', '192.168.1.15', '{"format": "csv", "time_range": "24h"}'),
('RETRAIN', 'ml_model', 'isolation_forest', 'admin', '192.168.1.10', '{"dataset_size": 15000, "improvement": 0.02}'),
('CONFIG_CHANGE', 'system_config', 'anomaly_threshold', 'admin', '192.168.1.10', '{"old_value": "0.1", "new_value": "0.08"}'),
('DELETE', 'log_entries', 'bulk', 'system', '127.0.0.1', '{"retention_cleanup": true, "deleted_count": 1000});

-- Additional test data for recent activity (last few hours)
INSERT INTO log_entries (timestamp, ip_address, user_id, event_type, raw_data) VALUES
(NOW() - INTERVAL '30 minutes', '192.168.1.111', 'new_user', 'login', '{"success": true, "first_time": true}'),
(NOW() - INTERVAL '25 minutes', '203.0.113.78', 'regular_user', 'api_access', '{"endpoint": "/api/data", "large_response": true}'),
(NOW() - INTERVAL '20 minutes', '198.51.100.99', 'suspicious_user', 'failed_login', '{"attempts": 8, "rapid_succession": true}'),
(NOW() - INTERVAL '15 minutes', '185.220.102.1', 'unknown', 'vulnerability_scan', '{"tools": ["nmap", "nikto"], "targets": ["web_server"]}'),
(NOW() - INTERVAL '10 minutes', '192.168.1.150', 'privileged_user', 'admin_action', '{"action": "user_deletion", "target": "terminated_employee"}'),
(NOW() - INTERVAL '5 minutes', '104.244.73.200', 'bot_user', 'ddos_attempt', '{"requests_per_second": 1000, "duration": 120}');

-- Corresponding threat analyses for recent data
INSERT INTO threat_analyses (log_entry_id, risk_score, risk_level, model_scores, threat_types, recommendations, confidence) 
SELECT 
    id,
    CASE 
        WHEN event_type = 'login' THEN 0.1
        WHEN event_type = 'api_access' THEN 0.3
        WHEN event_type = 'failed_login' THEN 0.7
        WHEN event_type = 'vulnerability_scan' THEN 0.9
        WHEN event_type = 'admin_action' THEN 0.2
        WHEN event_type = 'ddos_attempt' THEN 0.95
        ELSE 0.5
    END,
    CASE 
        WHEN event_type IN ('login', 'admin_action') THEN 'NORMAL'
        WHEN event_type = 'api_access' THEN 'LOW'
        WHEN event_type = 'failed_login' THEN 'MEDIUM'
        WHEN event_type = 'vulnerability_scan' THEN 'HIGH'
        WHEN event_type = 'ddos_attempt' THEN 'HIGH'
        ELSE 'NORMAL'
    END,
    '{"isolation_forest": 0.5, "random_forest": 0.5, "autoencoder": 0.5}',
    CASE 
        WHEN event_type = 'failed_login' THEN '{"Failed Login", "Brute Force"}'
        WHEN event_type = 'vulnerability_scan' THEN '{"Vulnerability Scan", "Reconnaissance"}'
        WHEN event_type = 'ddos_attempt' THEN '{"DDoS Attack", "Botnet"}'
        WHEN event_type = 'api_access' THEN '{"Bulk Data Access"}'
        ELSE '{}'
    END,
    CASE 
        WHEN event_type = 'failed_login' THEN '{"Monitor user activity", "Consider account lockout"}'
        WHEN event_type = 'vulnerability_scan' THEN '{"Block IP immediately", "Alert security team"}'
        WHEN event_type = 'ddos_attempt' THEN '{"Activate DDoS protection", "Block IP range"}'
        WHEN event_type = 'api_access' THEN '{"Review API access patterns"}'
        ELSE '{"Continue monitoring"}'
    END,
    0.8
FROM log_entries 
WHERE timestamp > NOW() - INTERVAL '1 hour';

COMMIT;