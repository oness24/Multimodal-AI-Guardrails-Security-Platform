

# AdversarialShield - Production Deployment Guide

Complete guide for deploying AdversarialShield to production environments.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Database Configuration](#database-configuration)
4. [Application Deployment](#application-deployment)
5. [Security Hardening](#security-hardening)
6. [Monitoring & Logging](#monitoring--logging)
7. [Backup & Recovery](#backup--recovery)
8. [Scaling](#scaling)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

**Minimum (Development)**:
- CPU: 2 cores
- RAM: 4 GB
- Disk: 20 GB
- OS: Linux (Ubuntu 22.04 recommended) or macOS

**Recommended (Production)**:
- CPU: 8+ cores
- RAM: 16+ GB
- Disk: 100+ GB SSD
- OS: Linux (Ubuntu 22.04 LTS)

### Software Requirements

- Docker 24.0+ and Docker Compose 2.0+
- Python 3.11+
- Node.js 18+ (for frontend)
- PostgreSQL 15+
- Redis 7+
- MongoDB 7+
- nginx (reverse proxy)

### API Keys

Required for full functionality:
- OpenAI API key (for GPT models)
- Anthropic API key (for Claude models)
- Optional: Hugging Face token

---

## Environment Setup

### 1. Clone Repository

```bash
git clone https://github.com/your-org/adversarialshield.git
cd adversarialshield
```

### 2. Create Environment File

```bash
cp .env.example .env
```

### 3. Configure Environment Variables

Edit `.env`:

```bash
# Environment
ENVIRONMENT=production

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4

# Security (IMPORTANT: Change these!)
SECRET_KEY=$(openssl rand -hex 32)
JWT_ALGORITHM=HS256
JWT_EXPIRATION_MINUTES=60

# Database URLs
DATABASE_URL=postgresql://postgres:STRONG_PASSWORD@localhost:5432/adversarialshield
REDIS_URL=redis://:REDIS_PASSWORD@localhost:6379/0
MONGODB_URL=mongodb://admin:MONGO_PASSWORD@localhost:27017/adversarialshield

# LLM API Keys
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
HUGGINGFACE_API_KEY=hf_...

# SIEM Integration (Optional)
WAZUH_API_URL=https://your-wazuh:55000
WAZUH_API_USERNAME=wazuh
WAZUH_API_PASSWORD=wazuh_password
SPLUNK_API_URL=https://your-splunk:8088
SPLUNK_API_TOKEN=Splunk_HEC_Token

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json

# Rate Limiting
RATE_LIMIT_PER_MINUTE=100

# Feature Flags
ENABLE_MULTIMODAL_ATTACKS=true
ENABLE_STATIC_ANALYSIS=true
ENABLE_DYNAMIC_ANALYSIS=true
ENABLE_THREAT_MODELING=true
```

**Security Notes**:
- Generate strong SECRET_KEY: `openssl rand -hex 32`
- Use strong database passwords
- Never commit `.env` to version control

---

## Database Configuration

### PostgreSQL Setup

#### 1. Install PostgreSQL

```bash
# Ubuntu
sudo apt update
sudo apt install postgresql-15 postgresql-contrib

# Start service
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

#### 2. Create Database and User

```bash
sudo -u postgres psql

CREATE DATABASE adversarialshield;
CREATE USER adversarialshield WITH ENCRYPTED PASSWORD 'STRONG_PASSWORD';
GRANT ALL PRIVILEGES ON DATABASE adversarialshield TO adversarialshield;
\q
```

#### 3. Configure PostgreSQL

Edit `/etc/postgresql/15/main/postgresql.conf`:

```
# Performance tuning
shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 64MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 16MB
min_wal_size = 1GB
max_wal_size = 4GB

# Connection pooling
max_connections = 100
```

Edit `/etc/postgresql/15/main/pg_hba.conf`:

```
# Allow local connections
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             ::1/128                 scram-sha-256
```

#### 4. Run Migrations

```bash
cd backend
alembic upgrade head
```

---

### Redis Setup

#### 1. Install Redis

```bash
# Ubuntu
sudo apt install redis-server

# Start service
sudo systemctl start redis-server
sudo systemctl enable redis-server
```

#### 2. Configure Redis

Edit `/etc/redis/redis.conf`:

```
# Security
requirepass REDIS_PASSWORD
bind 127.0.0.1

# Performance
maxmemory 2gb
maxmemory-policy allkeys-lru

# Persistence
save 900 1
save 300 10
save 60 10000
```

#### 3. Restart Redis

```bash
sudo systemctl restart redis-server
```

---

### MongoDB Setup

#### 1. Install MongoDB

```bash
# Ubuntu 22.04
wget -qO - https://www.mongodb.org/static/pgp/server-7.0.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list

sudo apt update
sudo apt install -y mongodb-org

# Start service
sudo systemctl start mongod
sudo systemctl enable mongod
```

#### 2. Configure MongoDB

```bash
mongosh

use admin
db.createUser({
  user: "admin",
  pwd: "MONGO_PASSWORD",
  roles: [ { role: "root", db: "admin" } ]
})

use adversarialshield
db.createUser({
  user: "adversarialshield",
  pwd: "STRONG_PASSWORD",
  roles: [ { role: "readWrite", db: "adversarialshield" } ]
})
```

Edit `/etc/mongod.conf`:

```yaml
security:
  authorization: enabled

net:
  bindIp: 127.0.0.1
  port: 27017
```

#### 3. Restart MongoDB

```bash
sudo systemctl restart mongod
```

---

## Application Deployment

### Option 1: Docker Deployment (Recommended)

#### 1. Build Images

```bash
# Build all services
docker-compose -f docker-compose.prod.yml build
```

#### 2. Start Services

```bash
# Start in detached mode
docker-compose -f docker-compose.prod.yml up -d

# View logs
docker-compose -f docker-compose.prod.yml logs -f
```

#### 3. Verify Health

```bash
curl http://localhost:8000/health
```

---

### Option 2: Manual Deployment

#### Backend Deployment

```bash
cd backend

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run migrations
alembic upgrade head

# Start application (using gunicorn)
gunicorn backend.api.main:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --access-logfile /var/log/adversarialshield/access.log \
  --error-logfile /var/log/adversarialshield/error.log \
  --log-level info
```

#### Frontend Deployment

```bash
cd frontend

# Install dependencies
npm install

# Build for production
npm run build

# Start production server
npm run start

# Or use PM2 for process management
npm install -g pm2
pm2 start npm --name "adversarialshield-frontend" -- start
```

---

### Option 3: Systemd Services

#### Create Backend Service

Create `/etc/systemd/system/adversarialshield-api.service`:

```ini
[Unit]
Description=AdversarialShield API
After=network.target postgresql.service redis-server.service mongod.service

[Service]
Type=notify
User=adversarialshield
Group=adversarialshield
WorkingDirectory=/opt/adversarialshield/backend
Environment="PATH=/opt/adversarialshield/backend/venv/bin"
EnvironmentFile=/opt/adversarialshield/.env
ExecStart=/opt/adversarialshield/backend/venv/bin/gunicorn \
  backend.api.main:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --access-logfile /var/log/adversarialshield/access.log \
  --error-logfile /var/log/adversarialshield/error.log
ExecReload=/bin/kill -s HUP $MAINPID
KillMode=mixed
KillSignal=SIGQUIT
TimeoutStopSec=5
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

#### Start Services

```bash
sudo systemctl daemon-reload
sudo systemctl start adversarialshield-api
sudo systemctl enable adversarialshield-api
sudo systemctl status adversarialshield-api
```

---

## Security Hardening

### 1. SSL/TLS Configuration

#### Install Certbot (Let's Encrypt)

```bash
sudo apt install certbot python3-certbot-nginx
```

#### Obtain Certificate

```bash
sudo certbot --nginx -d adversarialshield.yourdomain.com
```

---

### 2. nginx Reverse Proxy

Create `/etc/nginx/sites-available/adversarialshield`:

```nginx
# Rate limiting
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=100r/m;
limit_req_zone $binary_remote_addr zone=web_limit:10m rate=500r/m;

# Upstream backends
upstream api_backend {
    least_conn;
    server 127.0.0.1:8000;
    # Add more backends for load balancing
    # server 127.0.0.1:8001;
    # server 127.0.0.1:8002;
}

upstream frontend_backend {
    server 127.0.0.1:3000;
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name adversarialshield.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS server
server {
    listen 443 ssl http2;
    server_name adversarialshield.yourdomain.com;

    # SSL certificates
    ssl_certificate /etc/letsencrypt/live/adversarialshield.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/adversarialshield.yourdomain.com/privkey.pem;

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';" always;

    # API endpoints
    location /api/ {
        limit_req zone=api_limit burst=20 nodelay;

        proxy_pass http://api_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }

    # Health check (no rate limit)
    location /health {
        proxy_pass http://api_backend;
        access_log off;
    }

    # Frontend
    location / {
        limit_req zone=web_limit burst=100 nodelay;

        proxy_pass http://frontend_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Static files
    location /_next/static/ {
        proxy_pass http://frontend_backend;
        proxy_cache_valid 200 60m;
        add_header Cache-Control "public, max-age=3600";
    }

    # Logging
    access_log /var/log/nginx/adversarialshield_access.log;
    error_log /var/log/nginx/adversarialshield_error.log;
}
```

#### Enable Site

```bash
sudo ln -s /etc/nginx/sites-available/adversarialshield /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

---

### 3. Firewall Configuration

```bash
# UFW firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp  # SSH
sudo ufw allow 80/tcp  # HTTP
sudo ufw allow 443/tcp # HTTPS
sudo ufw enable
```

---

### 4. Application Security

#### Create Admin User

```bash
python cli.py init  # Creates default admin user

# Then immediately change password via API:
curl -X POST https://your-domain/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin@adversarialshield.ai", "password": "admin123"}'

# Use returned token to change password (implement password change endpoint)
```

#### Generate API Keys

```bash
# Via API after authentication
curl -X POST https://your-domain/api/v1/auth/api-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production API Key",
    "scopes": ["read", "scan"],
    "expires_in_days": 90
  }'
```

---

## Monitoring & Logging

### Prometheus Setup

#### 1. Install Prometheus

```bash
wget https://github.com/prometheus/prometheus/releases/download/v2.45.0/prometheus-2.45.0.linux-amd64.tar.gz
tar xvfz prometheus-*.tar.gz
cd prometheus-*
```

#### 2. Configure Prometheus

Create `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'adversarialshield'
    static_configs:
      - targets: ['localhost:8000']
```

#### 3. Start Prometheus

```bash
./prometheus --config.file=prometheus.yml
```

---

### Grafana Setup

#### 1. Install Grafana

```bash
sudo apt-get install -y software-properties-common
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
sudo apt-get update
sudo apt-get install grafana

sudo systemctl start grafana-server
sudo systemctl enable grafana-server
```

#### 2. Access Grafana

Navigate to `http://localhost:3000` (default login: admin/admin)

---

### Centralized Logging (ELK Stack)

#### Quick Setup with Docker

```bash
docker-compose -f docker-compose.logging.yml up -d
```

This starts:
- Elasticsearch (port 9200)
- Logstash (port 5000)
- Kibana (port 5601)

---

## Backup & Recovery

### Database Backups

#### PostgreSQL Backup

```bash
#!/bin/bash
# /opt/adversarialshield/scripts/backup-postgres.sh

BACKUP_DIR="/backup/adversarialshield/postgres"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/adversarialshield_$TIMESTAMP.sql.gz"

# Create backup
pg_dump -U adversarialshield adversarialshield | gzip > "$BACKUP_FILE"

# Keep only last 7 days
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +7 -delete

echo "Backup completed: $BACKUP_FILE"
```

#### MongoDB Backup

```bash
#!/bin/bash
# /opt/adversarialshield/scripts/backup-mongo.sh

BACKUP_DIR="/backup/adversarialshield/mongodb"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create backup
mongodump --uri="mongodb://admin:MONGO_PASSWORD@localhost:27017/adversarialshield" \
  --out="$BACKUP_DIR/$TIMESTAMP"

# Compress
tar -czf "$BACKUP_DIR/adversarialshield_$TIMESTAMP.tar.gz" "$BACKUP_DIR/$TIMESTAMP"
rm -rf "$BACKUP_DIR/$TIMESTAMP"

# Keep only last 7 days
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +7 -delete

echo "Backup completed: $BACKUP_DIR/adversarialshield_$TIMESTAMP.tar.gz"
```

#### Schedule Backups (Cron)

```bash
# Edit crontab
crontab -e

# Add daily backups at 2 AM
0 2 * * * /opt/adversarialshield/scripts/backup-postgres.sh >> /var/log/adversarialshield/backup.log 2>&1
0 3 * * * /opt/adversarialshield/scripts/backup-mongo.sh >> /var/log/adversarialshield/backup.log 2>&1
```

---

## Scaling

### Horizontal Scaling (Multiple API Servers)

#### 1. Deploy Multiple Backend Instances

```bash
# Start multiple instances on different ports
gunicorn backend.api.main:app --workers 4 --bind 0.0.0.0:8000 &
gunicorn backend.api.main:app --workers 4 --bind 0.0.0.0:8001 &
gunicorn backend.api.main:app --workers 4 --bind 0.0.0.0:8002 &
```

#### 2. Configure nginx Load Balancing

Update nginx upstream:

```nginx
upstream api_backend {
    least_conn;
    server 127.0.0.1:8000;
    server 127.0.0.1:8001;
    server 127.0.0.1:8002;
}
```

### Database Read Replicas

#### PostgreSQL Streaming Replication

On primary server, edit `postgresql.conf`:

```
wal_level = replica
max_wal_senders = 3
```

On replica server:

```bash
pg_basebackup -h primary_host -D /var/lib/postgresql/15/main -U replicator -P --wal-method=stream
```

---

## Troubleshooting

### Common Issues

#### 1. API Not Responding

```bash
# Check service status
sudo systemctl status adversarialshield-api

# Check logs
tail -f /var/log/adversarialshield/error.log

# Check port binding
netstat -tulpn | grep 8000
```

#### 2. Database Connection Errors

```bash
# Test PostgreSQL connection
psql -U adversarialshield -d adversarialshield -h localhost

# Check PostgreSQL logs
tail -f /var/log/postgresql/postgresql-15-main.log

# Test Redis connection
redis-cli ping

# Test MongoDB connection
mongosh --host localhost --port 27017
```

#### 3. High CPU/Memory Usage

```bash
# Check resource usage
top
htop

# Check API processes
ps aux | grep gunicorn

# Restart services
sudo systemctl restart adversarialshield-api
```

#### 4. SSL Certificate Issues

```bash
# Renew certificates
sudo certbot renew

# Test SSL configuration
sudo nginx -t
```

---

## Health Checks

### Application Health Check

```bash
curl https://your-domain/health
```

Expected response:
```json
{
  "status": "healthy",
  "environment": "production",
  "version": "0.9.0"
}
```

### Database Health Checks

```bash
# PostgreSQL
pg_isready -h localhost -p 5432

# Redis
redis-cli ping

# MongoDB
mongosh --eval "db.adminCommand('ping')"
```

---

## Performance Tuning

### Application-Level

1. **Enable Caching**: Ensure Redis is configured
2. **Database Connection Pooling**: Configured in SQLAlchemy
3. **Async Operations**: All I/O operations use async/await
4. **Worker Count**: Set to (2 * CPU cores) + 1

### System-Level

1. **Increase File Descriptors**:
   ```bash
   ulimit -n 65536
   ```

2. **TCP Tuning** (`/etc/sysctl.conf`):
   ```
   net.core.somaxconn = 1024
   net.ipv4.tcp_max_syn_backlog = 2048
   ```

---

## Maintenance

### Regular Tasks

- **Daily**: Check logs, monitor metrics
- **Weekly**: Review security alerts, update dependencies
- **Monthly**: Rotate API keys, review user access
- **Quarterly**: Security audit, penetration testing

### Updates

```bash
# Pull latest code
git pull origin main

# Rebuild containers
docker-compose -f docker-compose.prod.yml build

# Run migrations
docker-compose -f docker-compose.prod.yml run backend alembic upgrade head

# Restart services
docker-compose -f docker-compose.prod.yml up -d
```

---

## Support

For issues or questions:
- GitHub Issues: https://github.com/your-org/adversarialshield/issues
- Documentation: https://docs.adversarialshield.ai
- Email: support@adversarialshield.ai

---

## License

AdversarialShield is licensed under the MIT License. See LICENSE file for details.
