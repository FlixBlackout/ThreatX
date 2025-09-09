# ThreatX Configuration Guide

This guide covers all configuration options for the ThreatX AI-Powered Cybersecurity Threat Detector.

## Configuration Overview

ThreatX uses environment files, configuration files, and database settings to control system behavior.

## AI Engine Configuration

### Environment Variables (.env)

Located at `ai-engine/.env`:

```bash
# Flask Configuration
SECRET_KEY=your-secret-key-change-in-production
FLASK_DEBUG=false
FLASK_ENV=production

# Database Configuration
DATABASE_URL=postgresql://threatx:password@localhost:5432/threatx_db

# ML Model Configuration
MODEL_UPDATE_INTERVAL=7                 # Days between retraining
ANOMALY_THRESHOLD=0.1                   # Anomaly detection sensitivity (0.0-1.0)

# API Configuration
API_HOST=0.0.0.0                       # Bind address
API_PORT=5000                          # Port number

# Security Configuration
MAX_LOGIN_ATTEMPTS=5                   # Failed login threshold
SUSPICIOUS_IP_THRESHOLD=10             # Threats before IP marked suspicious

# GeoIP Configuration
GEOIP_DATABASE_PATH=./data/GeoLite2-City.mmdb

# Logging Configuration
LOG_LEVEL=INFO                         # DEBUG, INFO, WARNING, ERROR
LOG_FILE=logs/threatx.log
```

### Model Configuration

Configure ML models in `ai-engine/src/threat_detector.py`:

```python
# Risk thresholds
self.risk_thresholds = {
    'low': 0.3,       # Scores 0.3-0.6 = LOW risk
    'medium': 0.6,    # Scores 0.6-0.8 = MEDIUM risk
    'high': 0.8       # Scores 0.8+ = HIGH risk
}

# Model weights for ensemble prediction
weights = {
    'isolation_forest': 0.4,  # 40% weight
    'random_forest': 0.3,     # 30% weight
    'autoencoder': 0.3        # 30% weight
}
```

### Feature Engineering

Configure feature extraction in `ai-engine/src/data_preprocessor.py`:

```python
# Country risk scores (0.0 = safest, 1.0 = highest risk)
self.country_risk_scores = {
    'US': 0.1, 'CA': 0.1, 'GB': 0.1, 'DE': 0.1, 'FR': 0.1,
    'CN': 0.7, 'RU': 0.8, 'KP': 0.9, 'IR': 0.8, 'SY': 0.8,
    'Unknown': 0.5
}

# Expected feature columns
self.feature_columns = [
    'hour_of_day', 'day_of_week', 'is_weekend',
    'login_attempts_last_hour', 'login_attempts_last_day',
    'ip_reputation_score', 'is_private_ip', 'country_risk_score',
    'user_session_count', 'bytes_transferred', 'unique_endpoints_accessed',
    'failed_login_ratio', 'geographic_anomaly', 'time_since_last_activity'
]
```

## Dashboard Configuration

### Application Properties

Located at `dashboard/src/main/resources/application.properties`:

```properties
# Application Configuration
spring.application.name=threatx-dashboard
server.port=8080

# Database Configuration
spring.datasource.url=jdbc:postgresql://localhost:5432/threatx_db
spring.datasource.username=threatx
spring.datasource.password=password
spring.datasource.driver-class-name=org.postgresql.Driver

# JPA Configuration
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=false
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect

# AI Engine Configuration
threatx.ai-engine.base-url=http://localhost:5000
threatx.ai-engine.timeout=30000

# Security Configuration
threatx.security.jwt.secret=your-secret-key
threatx.security.jwt.expiration=86400000

# Logging Configuration
logging.level.com.threatx=INFO
logging.file.name=logs/dashboard.log
```

### Security Configuration

Configure authentication and authorization:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/", "/health", "/css/**", "/js/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard")
                .permitAll()
            )
            .logout(logout -> logout.permitAll());
        
        return http.build();
    }
}
```

## Database Configuration

### Connection Settings

Configure database connections in `docker-compose.yml`:

```yaml
postgres:
  environment:
    POSTGRES_DB: threatx_db
    POSTGRES_USER: threatx
    POSTGRES_PASSWORD: password
    # Performance tuning
    POSTGRES_SHARED_BUFFERS: 256MB
    POSTGRES_EFFECTIVE_CACHE_SIZE: 1GB
    POSTGRES_MAINTENANCE_WORK_MEM: 64MB
    POSTGRES_CHECKPOINT_COMPLETION_TARGET: 0.9
    POSTGRES_WAL_BUFFERS: 16MB
    POSTGRES_DEFAULT_STATISTICS_TARGET: 100
```

### Schema Configuration

Database schema settings in `database/sql/schema.sql`:

```sql
-- System configuration table
INSERT INTO system_config (key, value, description, category) VALUES
('anomaly_threshold', '0.1', 'ML anomaly detection threshold', 'ml_models'),
('high_risk_threshold', '0.8', 'High risk classification threshold', 'risk_scoring'),
('data_retention_days', '90', 'Log data retention period', 'data_management'),
('auto_block_enabled', 'false', 'Auto-block suspicious IPs', 'security');
```

## Docker Configuration

### Docker Compose Settings

Main configuration in `docker-compose.yml`:

```yaml
version: '3.8'

services:
  ai-engine:
    build: ./ai-engine
    environment:
      - FLASK_ENV=production
      - DATABASE_URL=postgresql://threatx:password@postgres:5432/threatx_db
    ports:
      - "5000:5000"
    volumes:
      - ./ai-engine/models:/app/models
      - ./ai-engine/logs:/app/logs
    
  dashboard:
    build: ./dashboard
    environment:
      - SPRING_PROFILES_ACTIVE=docker
      - THREATX_AI_ENGINE_BASE_URL=http://ai-engine:5000
    ports:
      - "8080:8080"
    depends_on:
      - postgres
      - ai-engine
```

### Resource Limits

Configure resource limits for production:

```yaml
services:
  ai-engine:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G
  
  postgres:
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 1G
```

## Nginx Configuration

### Reverse Proxy Settings

Configure Nginx in `docker/nginx/nginx.conf`:

```nginx
upstream dashboard {
    server dashboard:8080;
    keepalive 32;
}

upstream ai-engine {
    server ai-engine:5000;
    keepalive 16;
}

server {
    listen 80;
    server_name threatx.local;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
    # Rate limiting
    limit_req zone=api burst=10 nodelay;
    
    location / {
        proxy_pass http://dashboard;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    
    location /ai-api/ {
        proxy_pass http://ai-engine/;
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;
    }
}
```

### SSL Configuration

For HTTPS in production:

```nginx
server {
    listen 443 ssl http2;
    server_name threatx.yourdomain.com;
    
    ssl_certificate /etc/nginx/ssl/threatx.crt;
    ssl_certificate_key /etc/nginx/ssl/threatx.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}
```

## Monitoring Configuration

### Prometheus Settings

Configure metrics collection in `docker/prometheus/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'threatx-dashboard'
    static_configs:
      - targets: ['dashboard:8080']
    metrics_path: '/actuator/prometheus'
    scrape_interval: 30s
    
  - job_name: 'threatx-ai-engine'
    static_configs:
      - targets: ['ai-engine:5000']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

### Grafana Dashboards

Configure Grafana dashboards in `docker/grafana/provisioning/`:

```yaml
# dashboards.yml
apiVersion: 1

providers:
  - name: 'threatx'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /etc/grafana/provisioning/dashboards
```

## Environment-Specific Configuration

### Development Environment

Create `docker-compose.dev.yml`:

```yaml
version: '3.8'

services:
  ai-engine:
    environment:
      - FLASK_DEBUG=true
      - LOG_LEVEL=DEBUG
    volumes:
      - ./ai-engine:/app
    command: ["python", "app.py", "--reload"]
    
  dashboard:
    environment:
      - SPRING_PROFILES_ACTIVE=dev
      - LOGGING_LEVEL_COM_THREATX=DEBUG
    volumes:
      - ./dashboard/src:/app/src
```

### Production Environment

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  ai-engine:
    environment:
      - FLASK_ENV=production
      - LOG_LEVEL=WARNING
    restart: unless-stopped
    
  dashboard:
    environment:
      - SPRING_PROFILES_ACTIVE=prod
      - LOGGING_LEVEL_ROOT=WARN
    restart: unless-stopped
    
  nginx:
    ports:
      - "443:443"
    volumes:
      - ./ssl:/etc/nginx/ssl:ro
```

## Advanced Configuration

### Custom Feature Engineering

Add custom features in `data_preprocessor.py`:

```python
def extract_custom_features(self, log_data):
    """Extract domain-specific features"""
    features = {}
    
    # Custom business logic
    if log_data.get('department') == 'finance':
        features['is_finance_user'] = 1.0
    else:
        features['is_finance_user'] = 0.0
    
    # Custom time-based features
    hour = datetime.now().hour
    features['is_business_hours'] = 1.0 if 9 <= hour <= 17 else 0.0
    
    return features
```

### Custom Threat Detection Rules

Add custom rules in `threat_detector.py`:

```python
def apply_custom_rules(self, features, base_score):
    """Apply custom business rules"""
    adjusted_score = base_score
    
    # Finance users accessing sensitive data after hours
    if (features.get('is_finance_user') and 
        not features.get('is_business_hours') and
        features.get('bytes_transferred', 0) > 1000000):
        adjusted_score += 0.3
    
    # Multiple failed logins from new geographic location
    if (features.get('failed_login_ratio', 0) > 0.5 and
        features.get('geographic_anomaly', 0) > 0.7):
        adjusted_score += 0.4
    
    return min(1.0, adjusted_score)
```

### Database Indexing Strategy

Optimize database performance:

```sql
-- Create composite indexes for common queries
CREATE INDEX CONCURRENTLY idx_threat_analysis_composite 
ON threat_analyses(risk_level, analysis_timestamp DESC);

CREATE INDEX CONCURRENTLY idx_log_entries_composite 
ON log_entries(ip_address, timestamp DESC) 
WHERE event_type IN ('login', 'failed_login');

-- Partial indexes for frequently filtered data
CREATE INDEX CONCURRENTLY idx_suspicious_ips_active 
ON suspicious_ips(threat_count DESC) 
WHERE is_blocked = false;
```

## Configuration Validation

### Startup Checks

Add configuration validation:

```python
def validate_configuration():
    """Validate configuration on startup"""
    required_vars = [
        'DATABASE_URL', 'SECRET_KEY', 'API_HOST', 'API_PORT'
    ]
    
    missing = [var for var in required_vars if not os.getenv(var)]
    if missing:
        raise ValueError(f"Missing required environment variables: {missing}")
    
    # Validate numeric ranges
    threshold = float(os.getenv('ANOMALY_THRESHOLD', 0.1))
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("ANOMALY_THRESHOLD must be between 0.0 and 1.0")
```

### Health Checks

Monitor configuration health:

```python
@app.route('/config-health')
def config_health():
    checks = {
        'database': check_database_connection(),
        'model_files': check_model_files_exist(),
        'environment': check_environment_variables(),
        'disk_space': check_disk_space()
    }
    
    all_healthy = all(checks.values())
    status_code = 200 if all_healthy else 503
    
    return jsonify({
        'status': 'healthy' if all_healthy else 'unhealthy',
        'checks': checks,
        'timestamp': datetime.utcnow().isoformat()
    }), status_code
```

## Best Practices

### Security
- Use strong passwords and change defaults
- Enable SSL/TLS in production
- Implement proper authentication and authorization
- Regular security updates
- Monitor and audit configuration changes

### Performance
- Tune database parameters for your workload
- Implement proper caching strategies
- Monitor resource usage and scale appropriately
- Use connection pooling
- Optimize ML model parameters

### Maintenance
- Regular backups of configuration and data
- Version control for configuration files
- Document custom configurations
- Test configuration changes in staging
- Monitor system health and alerts

## Troubleshooting Configuration

### Common Issues

1. **Database Connection Failed**
   - Check DATABASE_URL format
   - Verify credentials and network connectivity
   - Check PostgreSQL service status

2. **ML Models Not Loading**
   - Verify model file paths and permissions
   - Check available disk space
   - Review model compatibility

3. **High Memory Usage**
   - Adjust batch sizes in configuration
   - Tune JVM heap settings for Java dashboard
   - Configure resource limits

4. **API Timeouts**
   - Increase timeout values
   - Check network latency
   - Monitor system load

For more troubleshooting help, see the [Installation Guide](installation.md).