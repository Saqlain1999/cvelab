# CVE Lab Platform - Docker & Dokploy Deployment Guide

## 🐳 **Overview**

This guide covers deploying CVE Lab Platform using Docker Compose, suitable for:
- **Local development** with hot reload
- **Dokploy deployment** (recommended for production)
- **Self-hosted production** on any server

---

## 📦 **Architecture**

The platform runs as a multi-container Docker application:

```
┌─────────────────────────────────────────────────────────┐
│                    Nginx (Optional)                     │
│              Reverse Proxy + SSL/TLS                    │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│                CVE Lab Application                      │
│         Node.js + Express + React (Port 5000)           │
└───┬──────────────────────────────────────────┬──────────┘
    │                                          │
    ▼                                          ▼
┌─────────────────┐                 ┌──────────────────┐
│   PostgreSQL    │                 │      Redis       │
│   (Port 5432)   │                 │   (Port 6379)    │
│                 │                 │                  │
│  - CVE Data     │                 │  - Cache         │
│  - User Data    │                 │  - Sessions      │
│  - Scans        │                 │  - Rate Limits   │
└─────────────────┘                 └──────────────────┘
```

**Services:**
- **app** - CVE Lab application (Node.js + Express backend, React frontend)
- **db** - PostgreSQL 15 database
- **redis** - Redis cache and session store
- **nginx** - Reverse proxy (optional, for production SSL/TLS)

---

## 🚀 **Quick Start (Local Development)**

### **Prerequisites**
- Docker & Docker Compose installed
- Git

### **Step 1: Clone & Configure**

```bash
# Clone repository
git clone <your-repo-url>
cd cvelab

# Create environment file
cp .env.docker .env

# Edit .env with your settings (at minimum, change passwords!)
nano .env
```

### **Step 2: Start Services**

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f app

# Check service status
docker-compose ps
```

### **Step 3: Initialize Database**

```bash
# Run database migrations
docker-compose exec app npm run db:push

# Verify database
docker-compose exec db psql -U cveuser -d cve_lab_db -c "\dt"
```

### **Step 4: Access Application**

Open browser: **http://localhost:5000**

**Default services:**
- Application: http://localhost:5000
- PostgreSQL: localhost:5432
- Redis: localhost:6379

### **Step 5: Test**

```bash
# Check health
curl http://localhost:5000/api/cves

# Should return: [] (empty array - database is ready!)
```

---

## 🌐 **Dokploy Deployment (Recommended for Production)**

Dokploy provides the easiest way to deploy with automatic SSL, monitoring, and updates.

### **Step 1: Prepare Repository**

```bash
# Ensure all files are committed
git add .
git commit -m "Ready for Dokploy deployment"
git push origin main
```

### **Step 2: Create Application in Dokploy**

1. Log into your Dokploy dashboard
2. Click **"New Application"**
3. Select **"Docker Compose"**
4. Fill in details:
   - **Name**: cvelab-platform
   - **Repository**: Your Git repository URL
   - **Branch**: main
   - **Compose File**: docker-compose.yml

### **Step 3: Configure Environment Variables**

In Dokploy, go to **Environment** tab and add:

```bash
# Required (MUST CHANGE!)
DB_PASSWORD=your-secure-database-password
REDIS_PASSWORD=your-secure-redis-password
JWT_SECRET=your-super-secret-jwt-key-64-chars-long

# Required (Your domain)
APP_URL=https://cvelab.yourdomain.com
FRONTEND_URL=https://cvelab.yourdomain.com
ALLOWED_ORIGINS=https://cvelab.yourdomain.com

# Optional (API keys)
GITHUB_TOKEN=your-github-token
VULNCHECK_API_KEY=your-vulncheck-key
GOOGLE_API_KEY=your-google-key

# Optional (Email - your WHM server)
SMTP_HOST=your-whm-server.com
SMTP_PORT=587
SMTP_USER=your-email@domain.com
SMTP_PASSWORD=your-smtp-password
SMTP_FROM=noreply@yourdomain.com

# Optional (Stripe for billing)
STRIPE_SECRET_KEY=sk_live_xxxxx
STRIPE_PUBLISHABLE_KEY=pk_live_xxxxx
STRIPE_WEBHOOK_SECRET=whsec_xxxxx
STRIPE_PRICE_PRO=price_xxxxx
STRIPE_PRICE_PREMIUM=price_xxxxx
```

**Pro Tip:** Use Dokploy's **Secret Management** for sensitive values.

### **Step 4: Configure Domain**

1. In Dokploy, go to **Domains** tab
2. Add your domain: `cvelab.yourdomain.com`
3. Enable **HTTPS** (Let's Encrypt)
4. Dokploy will automatically configure SSL

### **Step 5: Deploy**

1. Click **"Deploy"** button
2. Wait for build (first build takes 3-5 minutes)
3. Monitor logs in **Logs** tab
4. Verify health check passes

### **Step 6: Initialize Database**

```bash
# SSH into Dokploy server or use Dokploy terminal
dokploy exec cvelab-platform app npm run db:push
```

### **Step 7: Verify Deployment**

Visit: **https://cvelab.yourdomain.com**

---

## 🔧 **Environment Variables Reference**

### **Required (Must Configure)**

| Variable | Description | Example |
|----------|-------------|---------|
| `DB_PASSWORD` | PostgreSQL password | `SecurePass123!` |
| `REDIS_PASSWORD` | Redis password | `RedisPass456!` |
| `JWT_SECRET` | JWT signing secret (64+ chars) | Generate with `openssl rand -base64 64` |
| `APP_URL` | Your application URL | `https://cvelab.yourdomain.com` |

### **Optional (Enhance Functionality)**

| Variable | Description | Default |
|----------|-------------|---------|
| `GITHUB_TOKEN` | GitHub API token for PoC discovery | None (60 req/hr without) |
| `VULNCHECK_API_KEY` | VulnCheck API for KEV data | None |
| `GOOGLE_API_KEY` | Google Sheets export | None |
| `STRIPE_SECRET_KEY` | Stripe billing | None |

See `.env.docker` for complete list.

---

## 📊 **Database Management**

### **Backup Database**

```bash
# Create backup
docker-compose exec db pg_dump -U cveuser cve_lab_db > backup-$(date +%Y%m%d).sql

# With Docker Compose
docker-compose exec -T db pg_dump -U cveuser cve_lab_db | gzip > backup.sql.gz
```

### **Restore Database**

```bash
# Restore from backup
docker-compose exec -T db psql -U cveuser cve_lab_db < backup.sql

# Restore from gzip
gunzip < backup.sql.gz | docker-compose exec -T db psql -U cveuser cve_lab_db
```

### **Access Database Shell**

```bash
# PostgreSQL shell
docker-compose exec db psql -U cveuser -d cve_lab_db

# Run query
docker-compose exec db psql -U cveuser -d cve_lab_db -c "SELECT COUNT(*) FROM cves;"
```

### **View Redis Cache**

```bash
# Redis CLI
docker-compose exec redis redis-cli -a redispass

# Check keys
docker-compose exec redis redis-cli -a redispass KEYS '*'

# Flush cache (use carefully!)
docker-compose exec redis redis-cli -a redispass FLUSHALL
```

---

## 🔍 **Monitoring & Logs**

### **View Logs**

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f app
docker-compose logs -f db
docker-compose logs -f redis

# Last 100 lines
docker-compose logs --tail=100 app
```

### **Service Status**

```bash
# Check all services
docker-compose ps

# Check health
docker-compose exec app wget -O- http://localhost:5000/api/cves
```

### **Resource Usage**

```bash
# Container stats
docker stats

# Specific service
docker stats cvelab_app
```

---

## 🔒 **Security Checklist**

Before deploying to production:

- [ ] Change all default passwords (DB_PASSWORD, REDIS_PASSWORD)
- [ ] Generate secure JWT_SECRET (min 64 chars)
- [ ] Enable HTTPS (Let's Encrypt via Dokploy or Nginx)
- [ ] Configure firewall (only expose ports 80, 443)
- [ ] Set NODE_ENV=production
- [ ] Enable Sentry or error tracking
- [ ] Configure backup schedule
- [ ] Set up monitoring alerts
- [ ] Review ALLOWED_ORIGINS for CORS
- [ ] Enable rate limiting in production

---

## 🐛 **Troubleshooting**

### **App Won't Start**

```bash
# Check logs
docker-compose logs app

# Common issues:
# 1. Database not ready
docker-compose ps db  # Should be "healthy"

# 2. Environment variables missing
docker-compose exec app env | grep DATABASE_URL

# 3. Port conflict
lsof -i :5000  # Check if port is in use
```

### **Database Connection Failed**

```bash
# Test database connection
docker-compose exec app node -e "const { testDatabaseConnection } = require('./dist/server/db'); testDatabaseConnection();"

# Check database is running
docker-compose exec db pg_isready -U cveuser

# Verify credentials
docker-compose exec app env | grep DATABASE_URL
```

### **Build Fails**

```bash
# Clear cache and rebuild
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### **Out of Memory**

```bash
# Check memory usage
docker stats

# Increase memory in docker-compose.yml:
# deploy:
#   resources:
#     limits:
#       memory: 2G
```

---

## 🔄 **Updates & Maintenance**

### **Update Application**

```bash
# Pull latest code
git pull origin main

# Rebuild and restart
docker-compose down
docker-compose build --no-cache app
docker-compose up -d

# Run migrations
docker-compose exec app npm run db:push
```

### **Dokploy Auto-Updates**

In Dokploy:
1. Go to **Settings** → **Auto Deploy**
2. Enable **"Auto deploy on push"**
3. Now every `git push` triggers automatic deployment!

### **Scale Services**

```bash
# Scale app instances (if needed)
docker-compose up -d --scale app=3

# Behind nginx for load balancing
```

---

## 📈 **Performance Optimization**

### **Redis Caching**

The platform is already configured for Redis caching. To utilize:

```typescript
// In your code (future enhancement)
import { redis } from './services/redis';

// Cache CVE search results
const cacheKey = `cves:${filters}`;
const cached = await redis.get(cacheKey);
if (cached) return JSON.parse(cached);

// ... fetch from database ...
await redis.setex(cacheKey, 3600, JSON.stringify(results)); // 1 hour
```

### **Database Optimization**

```bash
# Analyze and optimize
docker-compose exec db psql -U cveuser -d cve_lab_db -c "VACUUM ANALYZE;"

# Check slow queries
docker-compose exec db psql -U cveuser -d cve_lab_db -c "SELECT * FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 10;"
```

---

## 🚦 **Production Checklist**

Before going live:

**Infrastructure:**
- [ ] Docker Compose configured with production settings
- [ ] All services healthy and passing health checks
- [ ] HTTPS enabled (Let's Encrypt via Dokploy)
- [ ] Database backups automated (daily)
- [ ] Redis persistence enabled

**Security:**
- [ ] All secrets changed from defaults
- [ ] JWT_SECRET is 64+ characters
- [ ] Firewall configured (only 80/443 exposed)
- [ ] CORS configured with actual domain
- [ ] Rate limiting enabled

**Monitoring:**
- [ ] Sentry configured for error tracking
- [ ] Log aggregation set up
- [ ] Uptime monitoring configured
- [ ] Disk space alerts configured
- [ ] Memory/CPU alerts configured

**Application:**
- [ ] Database schema deployed
- [ ] First admin user created
- [ ] Email sending tested
- [ ] Stripe webhooks configured (if using billing)
- [ ] All API keys configured

**Testing:**
- [ ] CVE scan tested end-to-end
- [ ] Login/logout tested (when implemented)
- [ ] Export functionality tested
- [ ] Mobile responsive checked
- [ ] Load tested (100+ concurrent users)

---

## 💡 **Tips & Best Practices**

### **Development Workflow**

```bash
# Local development (with hot reload)
npm run dev

# Test Docker build locally
docker-compose -f docker-compose.yml up --build

# Tail logs while developing
docker-compose logs -f app
```

### **Staging Environment**

Create a `docker-compose.staging.yml`:

```yaml
version: '3.9'

# Extends docker-compose.yml
# Override with staging-specific settings
services:
  app:
    environment:
      NODE_ENV: staging
      APP_URL: https://staging.cvelab.yourdomain.com
```

Deploy:
```bash
docker-compose -f docker-compose.yml -f docker-compose.staging.yml up -d
```

### **Health Monitoring**

The app includes health checks:
- HTTP GET `/api/cves` should return 200
- Docker health check runs every 30 seconds
- Dokploy monitors health and auto-restarts if unhealthy

---

## 🆘 **Getting Help**

**Common Resources:**
- **Setup Guide**: `SETUP_GUIDE.md`
- **TODO**: `TODO.md` (project roadmap)
- **Architecture**: `ARCHITECTURE.md`
- **Environment Variables**: `.env.docker`

**Logs Location:**
- App logs: `docker-compose logs app`
- Database logs: `docker-compose logs db`
- Nginx logs: `./nginx/logs/` (if using nginx)

**Dokploy Support:**
- Documentation: https://docs.dokploy.com
- Discord: https://discord.gg/dokploy

---

## 📝 **Next Steps**

After successful deployment:

1. **Test the platform**: Run a CVE scan
2. **Configure API keys**: Add GitHub, VulnCheck tokens
3. **Set up monitoring**: Configure Sentry, uptime checks
4. **Enable backups**: Automate daily database backups
5. **Implement authentication**: Milestone 1.2 from TODO.md
6. **Add billing**: Integrate Stripe (Milestone 5.1)

---

**Deployment Status:**
- ✅ Dockerized application
- ✅ Multi-container architecture
- ✅ Production-ready with health checks
- ✅ Dokploy compatible
- ✅ Easy updates and rollbacks

**Ready to deploy! 🚀**
