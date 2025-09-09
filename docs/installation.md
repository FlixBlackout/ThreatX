# ThreatX Installation Guide

This guide will help you install and configure the ThreatX AI-Powered Cybersecurity Threat Detector system.

## Prerequisites

### System Requirements
- **Operating System**: Linux, macOS, or Windows 10/11
- **RAM**: Minimum 8GB (16GB recommended)
- **Storage**: Minimum 50GB free space
- **CPU**: Multi-core processor (4+ cores recommended)
- **Network**: Internet connection for downloading dependencies

### Required Software
- [Docker](https://docs.docker.com/get-docker/) (version 20.10+)
- [Docker Compose](https://docs.docker.com/compose/install/) (version 2.0+)
- [Git](https://git-scm.com/downloads) (for cloning the repository)

## Quick Start (Recommended)

### 1. Clone the Repository
```bash
git clone <repository-url>
cd ThreatX
```

### 2. Run Setup Script

#### On Linux/macOS:
```bash
chmod +x setup.sh
./setup.sh
```

#### On Windows:
```cmd
setup.bat
```

The setup script will:
- Check all dependencies
- Create necessary directories
- Set up environment files
- Download sample datasets
- Build and start all services
- Wait for services to be ready
- Display service URLs and status

### 3. Access the System

Once setup is complete, you can access:
- **Main Dashboard**: http://localhost:8080
- **AI Engine API**: http://localhost:5000
- **Grafana Monitoring**: http://localhost:3000 (admin/admin)
- **Kibana Logs**: http://localhost:5601
- **Prometheus Metrics**: http://localhost:9090

## Manual Installation

If you prefer to install manually or need to customize the setup:

### 1. Environment Configuration

Copy the environment example file:
```bash
cp ai-engine/.env.example ai-engine/.env
```

Edit the `.env` file to customize settings:
```bash
# Database Configuration
DATABASE_URL=postgresql://threatx:password@localhost:5432/threatx_db

# AI Engine Configuration
API_HOST=0.0.0.0
API_PORT=5000
ANOMALY_THRESHOLD=0.1

# Security Configuration
SECRET_KEY=your-secret-key-change-in-production
```

### 2. Build and Start Services

Build the Docker images:
```bash
docker-compose build
```

Start all services:
```bash
docker-compose up -d
```

### 3. Verify Installation

Check service status:
```bash
docker-compose ps
```

View logs for troubleshooting:
```bash
docker-compose logs -f [service-name]
```

## Service Architecture

The ThreatX system consists of the following services:

### Core Services
- **PostgreSQL**: Database for storing logs and threat analyses
- **AI Engine**: Python Flask API for threat detection
- **Dashboard**: Java Spring Boot web application
- **Redis**: Caching and session management

### Monitoring Stack
- **Nginx**: Reverse proxy and load balancer
- **Elasticsearch**: Log storage and search
- **Kibana**: Log visualization
- **Grafana**: Metrics dashboard
- **Prometheus**: Metrics collection

## Configuration

### Database Configuration

The PostgreSQL database is automatically configured with:
- Database: `threatx_db`
- User: `threatx`
- Password: `password` (change in production)

To connect manually:
```bash
docker-compose exec postgres psql -U threatx -d threatx_db
```

### AI Engine Configuration

Key configuration options in `ai-engine/.env`:
- `ANOMALY_THRESHOLD`: Sensitivity for anomaly detection (0.0-1.0)
- `MODEL_UPDATE_INTERVAL`: Days between model retraining
- `MAX_LOGIN_ATTEMPTS`: Failed login threshold
- `LOG_LEVEL`: Logging verbosity (DEBUG, INFO, WARNING, ERROR)

### Dashboard Configuration

Configure the dashboard in `dashboard/src/main/resources/application.properties`:
- Database connection settings
- AI Engine API endpoint
- Security configuration
- Logging settings

## Security Considerations

### Production Deployment

For production deployment, ensure you:

1. **Change Default Passwords**:
   ```bash
   # Update in docker-compose.yml and .env files
   POSTGRES_PASSWORD=secure-password
   GRAFANA_ADMIN_PASSWORD=secure-password
   ```

2. **Enable HTTPS**:
   - Obtain SSL certificates
   - Update nginx configuration
   - Redirect HTTP to HTTPS

3. **Configure Firewall**:
   ```bash
   # Allow only necessary ports
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw deny 5432/tcp  # Block direct database access
   ```

4. **Update Secret Keys**:
   ```bash
   SECRET_KEY=your-very-secure-secret-key
   JWT_SECRET=your-jwt-secret-key
   ```

### Network Security

- Use private networks for internal communication
- Implement proper access controls
- Regular security updates
- Monitor system logs

## Troubleshooting

### Common Issues

#### Services Won't Start
```bash
# Check Docker daemon
sudo systemctl status docker

# Check logs
docker-compose logs -f

# Restart services
docker-compose restart
```

#### Database Connection Issues
```bash
# Check PostgreSQL status
docker-compose exec postgres pg_isready -U threatx

# Reset database
docker-compose down -v
docker-compose up -d postgres
```

#### Memory Issues
```bash
# Increase Docker memory limits
# Add to docker-compose.yml:
services:
  ai-engine:
    deploy:
      resources:
        limits:
          memory: 2G
```

#### Port Conflicts
```bash
# Check which service is using the port
sudo netstat -tulpn | grep :8080

# Change ports in docker-compose.yml:
ports:
  - "8081:8080"  # Use different external port
```

### Log Locations

- **AI Engine**: `ai-engine/logs/threatx.log`
- **Dashboard**: `dashboard/logs/dashboard.log`
- **Docker Logs**: `docker-compose logs [service-name]`
- **System Logs**: `/var/log/syslog` (Linux)

### Performance Tuning

#### Database Optimization
```sql
-- Connect to PostgreSQL
\c threatx_db

-- Check index usage
SELECT schemaname, tablename, attname, n_distinct, correlation 
FROM pg_stats WHERE tablename IN ('log_entries', 'threat_analyses');

-- Analyze query performance
EXPLAIN ANALYZE SELECT * FROM threat_analyses WHERE risk_level = 'HIGH';
```

#### Memory Optimization
```yaml
# In docker-compose.yml
services:
  postgres:
    environment:
      - POSTGRES_SHARED_BUFFERS=256MB
      - POSTGRES_EFFECTIVE_CACHE_SIZE=1GB
```

## Backup and Recovery

### Database Backup
```bash
# Create backup
docker-compose exec postgres pg_dump -U threatx threatx_db > backup.sql

# Restore backup
docker-compose exec -T postgres psql -U threatx threatx_db < backup.sql
```

### Full System Backup
```bash
# Stop services
docker-compose down

# Backup volumes
docker run --rm -v threatx_postgres_data:/data -v $(pwd):/backup ubuntu tar czf /backup/postgres_backup.tar.gz /data

# Restart services
docker-compose up -d
```

## Updating the System

### Update Docker Images
```bash
# Pull latest images
docker-compose pull

# Restart with new images
docker-compose up -d
```

### Update Application Code
```bash
# Get latest code
git pull origin main

# Rebuild images
docker-compose build --no-cache

# Restart services
docker-compose up -d
```

## Support

### Getting Help

- Check the [troubleshooting section](#troubleshooting) first
- Review the logs for error messages
- Check the [API documentation](api.md) for integration issues
- Consult the [configuration guide](configuration.md) for setup questions

### Reporting Issues

When reporting issues, please include:
- System information (OS, Docker version)
- Error messages from logs
- Steps to reproduce the problem
- Configuration files (remove sensitive data)

### Community

- Documentation: [docs/](../docs/)
- Issues: GitHub Issues
- Discussions: GitHub Discussions