#!/bin/bash

# ThreatX System Setup Script
# This script sets up the complete ThreatX system using Docker Compose

set -e

echo "🛡️  ThreatX AI-Powered Cybersecurity Threat Detector Setup"
echo "=========================================================="

# Check if Docker and Docker Compose are installed
check_dependencies() {
    echo "📋 Checking dependencies..."
    
    if ! command -v docker &> /dev/null; then
        echo "❌ Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        echo "❌ Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    echo "✅ Dependencies check passed"
}

# Create necessary directories
create_directories() {
    echo "📁 Creating necessary directories..."
    
    mkdir -p ai-engine/logs
    mkdir -p ai-engine/models
    mkdir -p dashboard/logs
    mkdir -p docker/nginx/ssl
    mkdir -p docker/grafana/provisioning
    mkdir -p datasets/sample
    
    echo "✅ Directories created"
}

# Copy environment files
setup_environment() {
    echo "🔧 Setting up environment files..."
    
    # Copy AI Engine environment file
    if [ ! -f ai-engine/.env ]; then
        cp ai-engine/.env.example ai-engine/.env
        echo "📝 Created ai-engine/.env from example"
    fi
    
    # Set proper file permissions
    chmod 600 ai-engine/.env 2>/dev/null || true
    
    echo "✅ Environment files configured"
}

# Download sample datasets
download_datasets() {
    echo "📊 Setting up sample datasets..."
    
    # Create sample dataset files
    cat > datasets/sample/network_logs.csv << 'EOF'
timestamp,ip_address,user_id,event_type,bytes_transferred,failed_login_attempts
2024-01-15 08:00:00,192.168.1.100,alice.johnson,login,1024,0
2024-01-15 08:05:00,203.0.113.45,bob.smith,login,2048,0
2024-01-15 08:10:00,198.51.100.30,charlie.brown,failed_login,512,1
2024-01-15 08:12:00,198.51.100.30,charlie.brown,failed_login,512,2
2024-01-15 08:15:00,198.51.100.30,charlie.brown,failed_login,512,3
EOF
    
    cat > datasets/sample/threat_indicators.txt << 'EOF'
# Sample threat indicators for testing
# Format: type:value:severity:description
ip:185.220.101.5:HIGH:Known Tor exit node
ip:91.240.118.172:HIGH:Botnet C2 server
domain:malicious-site.example:HIGH:Phishing domain
hash:d41d8cd98f00b204e9800998ecf8427e:MEDIUM:Malware hash
EOF
    
    echo "✅ Sample datasets created"
}

# Build and start services
start_services() {
    echo "🚀 Building and starting ThreatX services..."
    
    # Build images
    echo "🔨 Building Docker images..."
    docker-compose build --no-cache
    
    # Start services
    echo "▶️  Starting services..."
    docker-compose up -d
    
    echo "✅ Services started"
}

# Wait for services to be ready
wait_for_services() {
    echo "⏳ Waiting for services to be ready..."
    
    # Wait for PostgreSQL
    echo "📊 Waiting for PostgreSQL..."
    timeout 60 bash -c 'until docker-compose exec -T postgres pg_isready -U threatx -d threatx_db; do sleep 2; done'
    
    # Wait for AI Engine
    echo "🤖 Waiting for AI Engine..."
    timeout 120 bash -c 'until curl -f http://localhost:5000/health &>/dev/null; do sleep 5; done'
    
    # Wait for Dashboard
    echo "📊 Waiting for Dashboard..."
    timeout 120 bash -c 'until curl -f http://localhost:8080/health &>/dev/null; do sleep 5; done'
    
    echo "✅ All services are ready"
}

# Show service status and URLs
show_status() {
    echo ""
    echo "🎉 ThreatX system is ready!"
    echo "========================="
    echo ""
    echo "📊 Services:"
    echo "  • Main Dashboard:     http://localhost:8080"
    echo "  • AI Engine API:      http://localhost:5000"
    echo "  • Grafana Monitoring: http://localhost:3000 (admin/admin)"
    echo "  • Kibana Logs:        http://localhost:5601"
    echo "  • Prometheus Metrics: http://localhost:9090"
    echo ""
    echo "🔍 Service Status:"
    docker-compose ps
    echo ""
    echo "📋 Quick Commands:"
    echo "  • View logs: docker-compose logs -f [service-name]"
    echo "  • Stop system: docker-compose down"
    echo "  • Restart service: docker-compose restart [service-name]"
    echo "  • Update system: docker-compose pull && docker-compose up -d"
    echo ""
    echo "🛡️  Happy threat hunting!"
}

# Main execution
main() {
    check_dependencies
    create_directories
    setup_environment
    download_datasets
    start_services
    wait_for_services
    show_status
}

# Handle script interruption
trap 'echo "❌ Setup interrupted"; exit 1' INT TERM

# Run main function
main