@echo off
REM ThreatX System Setup Script for Windows
REM This script sets up the complete ThreatX system using Docker Compose

echo 🛡️  ThreatX AI-Powered Cybersecurity Threat Detector Setup
echo ==========================================================

REM Check if Docker is installed
echo 📋 Checking dependencies...
docker --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker is not installed. Please install Docker Desktop first.
    pause
    exit /b 1
)

docker-compose --version >nul 2>&1
if errorlevel 1 (
    docker compose version >nul 2>&1
    if errorlevel 1 (
        echo ❌ Docker Compose is not installed. Please install Docker Compose first.
        pause
        exit /b 1
    )
)

echo ✅ Dependencies check passed

REM Create necessary directories
echo 📁 Creating necessary directories...
if not exist "ai-engine\logs" mkdir "ai-engine\logs"
if not exist "ai-engine\models" mkdir "ai-engine\models"
if not exist "dashboard\logs" mkdir "dashboard\logs"
if not exist "docker\nginx\ssl" mkdir "docker\nginx\ssl"
if not exist "docker\grafana\provisioning" mkdir "docker\grafana\provisioning"
if not exist "datasets\sample" mkdir "datasets\sample"
echo ✅ Directories created

REM Setup environment files
echo 🔧 Setting up environment files...
if not exist "ai-engine\.env" (
    copy "ai-engine\.env.example" "ai-engine\.env" >nul
    echo 📝 Created ai-engine\.env from example
)
echo ✅ Environment files configured

REM Create sample datasets
echo 📊 Setting up sample datasets...
(
echo timestamp,ip_address,user_id,event_type,bytes_transferred,failed_login_attempts
echo 2024-01-15 08:00:00,192.168.1.100,alice.johnson,login,1024,0
echo 2024-01-15 08:05:00,203.0.113.45,bob.smith,login,2048,0
echo 2024-01-15 08:10:00,198.51.100.30,charlie.brown,failed_login,512,1
echo 2024-01-15 08:12:00,198.51.100.30,charlie.brown,failed_login,512,2
echo 2024-01-15 08:15:00,198.51.100.30,charlie.brown,failed_login,512,3
) > "datasets\sample\network_logs.csv"

(
echo # Sample threat indicators for testing
echo # Format: type:value:severity:description
echo ip:185.220.101.5:HIGH:Known Tor exit node
echo ip:91.240.118.172:HIGH:Botnet C2 server
echo domain:malicious-site.example:HIGH:Phishing domain
echo hash:d41d8cd98f00b204e9800998ecf8427e:MEDIUM:Malware hash
) > "datasets\sample\threat_indicators.txt"
echo ✅ Sample datasets created

REM Build and start services
echo 🚀 Building and starting ThreatX services...
echo 🔨 Building Docker images...
docker-compose build --no-cache
if errorlevel 1 (
    echo ❌ Failed to build Docker images
    pause
    exit /b 1
)

echo ▶️  Starting services...
docker-compose up -d
if errorlevel 1 (
    echo ❌ Failed to start services
    pause
    exit /b 1
)
echo ✅ Services started

REM Wait for services to be ready
echo ⏳ Waiting for services to be ready...
echo 📊 Waiting for PostgreSQL...
timeout /t 60 /nobreak >nul

echo 🤖 Waiting for AI Engine...
:wait_ai_engine
curl -f http://localhost:5000/health >nul 2>&1
if errorlevel 1 (
    timeout /t 5 /nobreak >nul
    goto wait_ai_engine
)

echo 📊 Waiting for Dashboard...
:wait_dashboard
curl -f http://localhost:8080/health >nul 2>&1
if errorlevel 1 (
    timeout /t 5 /nobreak >nul
    goto wait_dashboard
)

echo ✅ All services are ready

REM Show service status and URLs
echo.
echo 🎉 ThreatX system is ready!
echo =========================
echo.
echo 📊 Services:
echo   • Main Dashboard:     http://localhost:8080
echo   • AI Engine API:      http://localhost:5000
echo   • Grafana Monitoring: http://localhost:3000 (admin/admin)
echo   • Kibana Logs:        http://localhost:5601
echo   • Prometheus Metrics: http://localhost:9090
echo.
echo 🔍 Service Status:
docker-compose ps
echo.
echo 📋 Quick Commands:
echo   • View logs: docker-compose logs -f [service-name]
echo   • Stop system: docker-compose down
echo   • Restart service: docker-compose restart [service-name]
echo   • Update system: docker-compose pull ^&^& docker-compose up -d
echo.
echo 🛡️  Happy threat hunting!
echo.
pause