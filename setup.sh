#!/bin/bash

# CertiWipe Backend VPS Setup Script
# Run this script on your VPS to set up the backend automatically

set -e

echo "🚀 Starting CertiWipe Backend VPS Setup..."

# Update system
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install dependencies
echo "🐍 Installing Python and dependencies..."
sudo apt install python3 python3-pip python3-venv build-essential nginx git -y

# Create application directory
echo "📁 Setting up application directory..."
sudo mkdir -p /opt/certiwipe
sudo chown $USER:$USER /opt/certiwipe
cd /opt/certiwipe

# Clone or copy backend files
echo "📥 Setting up backend files..."
if [ -d "secure-wipe-backend" ]; then
    echo "Backend directory already exists, skipping..."
else
    echo "Please upload your backend files to /opt/certiwipe/secure-wipe-backend"
    echo "You can use: scp -r ./secure-wipe-backend user@your-vps:/opt/certiwipe/"
    exit 1
fi

cd secure-wipe-backend

# Set up virtual environment
echo "🔧 Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python packages
echo "📚 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create environment file
echo "⚙️ Creating environment configuration..."
cat > .env << EOF
# Basic Configuration
CERTIWIPE_API_KEY=$(openssl rand -hex 32)
CERTIWIPE_DB=certiwipe.db

# Security Settings
CERTIWIPE_ENABLE_SECURE_ERASE=1
CERTIWIPE_ENABLE_HPA_DCO=0
CERTIWIPE_ENABLE_MOCK=0

# Rate Limiting
CERTIWIPE_RATE_LIMIT_PER_MINUTE=60

# Logging
CERTIWIPE_JSONL=1
CERTIWIPE_LOG_JSON=1

# Production Settings
UVICORN_HOST=0.0.0.0
UVICORN_PORT=8000
EOF

# Create systemd service
echo "🔄 Setting up systemd service..."
sudo tee /etc/systemd/system/certiwipe.service > /dev/null << EOF
[Unit]
Description=CertiWipe Secure Data Wiping API
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/certiwipe/secure-wipe-backend
Environment=PATH=/opt/certiwipe/secure-wipe-backend/venv/bin
ExecStart=/opt/certiwipe/secure-wipe-backend/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Configure Nginx
echo "🌐 Configuring Nginx reverse proxy..."
sudo tee /etc/nginx/sites-available/certiwipe > /dev/null << EOF
server {
    listen 80;
    server_name _;

    # API endpoints
    location /api/ {
        proxy_pass http://localhost:8000/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # Health check
    location /health {
        proxy_pass http://localhost:8000/docs;
        proxy_set_header Host \$host;
    }
}
EOF

# Enable Nginx site
sudo ln -sf /etc/nginx/sites-available/certiwipe /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t

# Configure firewall
echo "🔒 Configuring firewall..."
sudo ufw allow ssh
sudo ufw allow 80
sudo ufw allow 443
sudo ufw allow 8000
sudo ufw --force enable

# Start services
echo "🚀 Starting services..."
sudo systemctl daemon-reload
sudo systemctl enable certiwipe
sudo systemctl start certiwipe
sudo systemctl restart nginx

# Test the setup
echo "🧪 Testing setup..."
sleep 5

if systemctl is-active --quiet certiwipe; then
    echo "✅ CertiWipe service is running"
else
    echo "❌ CertiWipe service failed to start"
    sudo systemctl status certiwipe
fi

if systemctl is-active --quiet nginx; then
    echo "✅ Nginx is running"
else
    echo "❌ Nginx failed to start"
    sudo systemctl status nginx
fi

# Get server information
IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')
API_KEY=$(grep CERTIWIPE_API_KEY /opt/certiwipe/secure-wipe-backend/.env | cut -d= -f2)

echo ""
echo "🎉 Setup Complete!"
echo "===================="
echo "Server IP: $IP"
echo "API Base URL: http://$IP/api"
echo "Direct API URL: http://$IP:8000"
echo "API Documentation: http://$IP:8000/docs"
echo "API Key: $API_KEY"
echo ""
echo "📝 Next steps:"
echo "1. Update your frontend to use: http://$IP/api"
echo "2. Test the API at: http://$IP:8000/docs"
echo "3. Monitor logs with: sudo journalctl -u certiwipe -f"
echo ""
echo "🔧 Useful commands:"
echo "- Restart service: sudo systemctl restart certiwipe"
echo "- View logs: sudo journalctl -u certiwipe -f"
echo "- Check status: sudo systemctl status certiwipe"
