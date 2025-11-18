# CVE Lab Platform - Setup Guide

## 🚀 Quick Start

This guide will get your CVE Lab platform running with PostgreSQL database in 5 minutes.

---

## Prerequisites

- **Node.js** 18+ installed
- **Docker** & **Docker Compose** installed
- **Git** installed

---

## Step 1: Clone & Install Dependencies

```bash
# If you haven't already, clone the repository
git clone <your-repo-url>
cd cvelab

# Install dependencies
npm install
```

---

## Step 2: Start PostgreSQL Database

The project includes a pre-configured Docker Compose setup for PostgreSQL:

```bash
# Start PostgreSQL container
docker-compose up -d

# Verify it's running
docker ps | grep cve_lab_db
```

You should see output like:
```
cve_lab_db   postgres:15   Up X seconds   0.0.0.0:5432->5432/tcp
```

---

## Step 3: Configure Environment Variables

A `.env` file has already been created with default settings:

```bash
# View current configuration
cat .env
```

**Default configuration** (works out of the box):
```
DATABASE_URL=postgresql://cveuser:cvepass@localhost:5432/cve_lab_db
PORT=5000
NODE_ENV=development
JWT_SECRET=development-secret-key-change-in-production-please
```

**For production**, update these values:
1. Change `JWT_SECRET` to a secure random string
2. Update database credentials if needed
3. Add API keys (GitHub, VulnCheck, Google, etc.) - optional

See `.env.example` for all available options.

---

## Step 4: Deploy Database Schema

Deploy all tables to PostgreSQL:

```bash
# Push schema to database
npm run db:push
```

You should see output like:
```
✅ Database schema deployed successfully!
```

**Tables created:**
- users
- cves (with 40+ fields)
- cveScans
- monitoringConfig
- cveAlerts
- monitoringRuns
- cveSourceConfigs
- multiSourceCveScans
- appConfigs

---

## Step 5: Start the Development Server

```bash
# Start both backend and frontend
npm run dev
```

The server will start on:
- **Backend**: http://localhost:5000
- **Frontend**: http://localhost:5173

You should see:
```
📊 Database configured: postgresql://cveuser:****@localhost:5432/cve_lab_db
✅ Database connection successful!
Server running on port 5000
```

---

## Step 6: Verify Setup

### Test Database Connection

```bash
# From another terminal
curl http://localhost:5000/api/cves
```

Should return: `[]` (empty array - database is empty but working!)

### Run Your First CVE Scan

1. Open http://localhost:5173 in your browser
2. Click on "CVE Search" tab
3. Click "Start New Scan"
4. Select timeframe (e.g., "Last 90 days")
5. Click "Start Scan"

The system will:
- Fetch CVEs from NIST NVD
- Enrich with Docker deployment info
- Analyze fingerprintability
- Discover GitHub PoCs
- Store everything in PostgreSQL

---

## 🔧 Troubleshooting

### Database Connection Failed

**Error**: `Database connection failed`

**Solutions**:
1. Ensure Docker is running: `docker ps`
2. Start PostgreSQL: `docker-compose up -d`
3. Check DATABASE_URL in `.env`
4. Verify port 5432 is not in use: `lsof -i :5432`

### Port Already in Use

**Error**: `Port 5000 already in use`

**Solution**:
```bash
# Change PORT in .env
PORT=3000
```

### Schema Deployment Fails

**Error**: `Error pushing schema`

**Solutions**:
1. Ensure database is running
2. Drop and recreate database:
```bash
docker-compose down -v
docker-compose up -d
npm run db:push
```

---

## 🗄️ Database Management

### View Database in Drizzle Studio

```bash
npm run db:studio
```

Opens a browser-based database viewer at http://localhost:4983

### Reset Database (Clear All Data)

```bash
# Stop and remove containers with data
docker-compose down -v

# Restart and re-deploy schema
docker-compose up -d
npm run db:push
```

### Backup Database

```bash
# Create backup
docker exec cve_lab_db pg_dump -U cveuser cve_lab_db > backup.sql

# Restore backup
docker exec -i cve_lab_db psql -U cveuser cve_lab_db < backup.sql
```

---

## 📊 Available Scripts

```bash
# Development
npm run dev              # Start dev server (frontend + backend)
npm run build            # Build for production
npm start                # Start production server

# Database
npm run db:push          # Deploy schema to database
npm run db:studio        # Open Drizzle Studio (database GUI)
npm run db:generate      # Generate migration files

# Testing (to be implemented)
npm test                 # Run tests
```

---

## 🔐 Security Notes

### For Development

The default setup is configured for local development and is **NOT secure for production**:
- Default database credentials (`cveuser:cvepass`)
- Weak JWT secret
- No HTTPS
- No rate limiting on authentication

### For Production

Before deploying to production:

1. **Change all secrets**:
   ```bash
   # Generate secure JWT secret
   openssl rand -base64 64
   ```

2. **Use strong database credentials**

3. **Enable HTTPS** (Let's Encrypt, Cloudflare, etc.)

4. **Set NODE_ENV=production**

5. **Configure firewall** (block PostgreSQL port 5432 from internet)

6. **Use environment-specific .env files**

See `IMPLEMENTATION_ROADMAP.md` > Phase 5 > Milestone 5.4 for full production deployment guide.

---

## 🎯 Next Steps

Now that your database is set up:

1. **Phase 1**: Complete authentication system (see `TODO.md`)
2. **Add VulnCheck API key** (if you have one)
3. **Run comprehensive CVE scan**
4. **Explore the codebase**:
   - `server/services/` - 14 production-ready services
   - `server/routes.ts` - 50+ API endpoints
   - `client/src/` - React frontend

---

## 📚 Documentation

- **TODO.md** - Complete project roadmap and task tracker
- **ARCHITECTURE.md** - Full platform architecture and design
- **IMPLEMENTATION_ROADMAP.md** - Detailed implementation guide
- **.env.example** - All available environment variables

---

## 🐛 Common Issues

### "Cannot find module '@neondatabase/serverless'"

```bash
npm install
```

### TypeScript errors

```bash
# Clear build cache
rm -rf dist node_modules
npm install
npm run build
```

### Database "already exists" error

This is normal - it means the database was already created. Just run:
```bash
npm run db:push
```

---

## ✅ Setup Complete!

Your CVE Lab platform is now running with:
- ✅ PostgreSQL database connected
- ✅ Schema deployed (9 tables)
- ✅ Development server running
- ✅ Ready for CVE discovery

**Database Status**: All data is now persisted! Restarting the server won't lose your CVEs.

**What changed from before**:
- Previously: In-memory storage (lost on restart)
- Now: PostgreSQL database (persistent across restarts)

Start exploring your CVEs at **http://localhost:5173** 🎉

---

## Need Help?

1. Check `TODO.md` for development roadmap
2. Review `ARCHITECTURE.md` for system design
3. See `IMPLEMENTATION_ROADMAP.md` for detailed guides
4. Reach out to the development team
