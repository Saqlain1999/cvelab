# CVE Lab Platform 🔐

**Automated CVE Discovery & Lab Setup Platform** for cybersecurity professionals.

Find recent, lab-suitable CVEs with public PoCs, Docker deployments, and automated fingerprinting - all in one platform.

---

## ✨ Features

- **🔍 Multi-Source CVE Discovery** - Aggregates from 6+ sources (NIST, MITRE, ExploitDB, etc.)
- **🐳 Docker Deployment Automation** - 14 pre-built templates with auto-generated compose files
- **🎯 Lab Suitability Scoring** - Advanced scoring for educational value and deployment ease
- **📡 Fingerprinting** - Auto-generates curl/nmap/nuclei commands for detection
- **🔗 PoC Discovery** - Finds GitHub repos, Metasploit modules, Nuclei templates
- **📊 Advanced Filtering** - Filter by CVSS, technology, attack vector, availability
- **📈 Source Reliability** - Cross-source validation with conflict detection
- **💾 Data Persistence** - PostgreSQL database with full audit trail
- **🚀 Production Ready** - Docker Compose deployment with Redis caching

---

## 🚀 Quick Start

### **Option 1: Docker Deployment (Recommended)**

```bash
# Clone repository
git clone <your-repo-url>
cd cvelab

# Configure environment
cp .env.docker .env
# Edit .env - at minimum change DB_PASSWORD, REDIS_PASSWORD, JWT_SECRET

# Deploy with script
./scripts/deploy.sh

# Or manually
docker-compose up -d
docker-compose exec app npm run db:push
```

**Access**: http://localhost:5000

### **Option 2: Local Development**

```bash
# Install dependencies
npm install

# Start PostgreSQL
docker-compose up -d db

# Configure environment
cp .env.example .env
# Edit DATABASE_URL in .env

# Deploy database schema
npm run db:push

# Start development server
npm run dev
```

**Access**: http://localhost:5173 (frontend) + http://localhost:5000 (backend)

---

## 📋 Requirements

- **Node.js** 18+ (local development)
- **Docker** & **Docker Compose** (for deployment)
- **PostgreSQL** 15+ (included in Docker setup)
- **Redis** 7+ (included in Docker setup)

**Optional** (enhances functionality):
- GitHub API token (5000 req/hr vs 60 without)
- VulnCheck API key (KEV data access)
- Google API key (Sheets export)

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────┐
│           React Frontend (Vite)                  │
│  Dashboard, Search, Configuration, Export        │
└─────────────────────┬────────────────────────────┘
                      │ HTTP/JSON
┌─────────────────────▼────────────────────────────┐
│          Express Backend (50+ endpoints)         │
│  ├─ CVE Discovery (6 sources)                    │
│  ├─ PoC Discovery (GitHub, GitLab, ExploitDB)    │
│  ├─ Docker Automation (14 templates)             │
│  ├─ Fingerprinting (curl/nmap/nuclei)           │
│  ├─ Advanced Scoring & Deduplication            │
│  └─ Export (CSV, Google Sheets)                  │
└───┬──────────────────────────────────┬───────────┘
    │                                  │
    ▼                                  ▼
┌─────────────────┐          ┌──────────────────┐
│   PostgreSQL    │          │      Redis       │
│   (Port 5432)   │          │   (Port 6379)    │
│  - 9 tables     │          │  - Caching       │
│  - 40+ CVE      │          │  - Sessions      │
│    fields       │          │  - Rate limits   │
└─────────────────┘          └──────────────────┘
```

**Tech Stack:**
- Frontend: React 18, TypeScript, Vite, Shadcn UI, TailwindCSS
- Backend: Node.js, Express, TypeScript, Drizzle ORM
- Database: PostgreSQL 15
- Cache: Redis 7
- Deployment: Docker, Docker Compose, Dokploy

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| **[SETUP_GUIDE.md](SETUP_GUIDE.md)** | Detailed setup instructions for local development |
| **[DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md)** | Complete Docker & Dokploy deployment guide |
| **[ARCHITECTURE.md](ARCHITECTURE.md)** | Full platform architecture and SaaS roadmap |
| **[IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md)** | Step-by-step implementation guide |
| **[TODO.md](TODO.md)** | Project roadmap and progress tracking |

---

## 🎯 Use Cases

**For Pentesters:**
- Find recent exploitable CVEs for engagement scope
- Get PoCs and working exploits
- Deploy vulnerable targets in minutes

**For Security Researchers:**
- Track CVEs for specific technologies
- Discover new attack vectors
- Test detection capabilities

**For SOC/Blue Teams:**
- Understand vulnerabilities in your stack
- Practice detection and response
- Build lab environments for training

**For Bug Bounty Hunters:**
- Find CVEs affecting bug bounty programs
- Get proof-of-concept exploits
- Test against lab targets first

---

## 🔧 Available Commands

### **Development**
```bash
npm run dev          # Start development server (hot reload)
npm run build        # Build for production
npm start            # Start production server
```

### **Database**
```bash
npm run db:push      # Deploy schema to database
npm run db:studio    # Open Drizzle Studio (database GUI)
npm run db:generate  # Generate migration files
```

### **Docker**
```bash
docker-compose up -d              # Start all services
docker-compose down               # Stop all services
docker-compose logs -f app        # View application logs
docker-compose exec app sh        # Access app container shell
./scripts/deploy.sh               # Automated deployment
./scripts/backup.sh               # Backup database
```

---

## 🎨 Features Breakdown

### **CVE Discovery**
- Searches NIST NVD with 120-day chunking for efficiency
- Aggregates from MITRE, ExploitDB, CVE Details, Vulners, CIRCL
- Cross-source validation and deduplication
- Conflict detection with weighted reliability scoring

### **Lab Suitability**
- Filters for network-accessible, unauthenticated CVEs
- Prioritizes 80+ technologies (WordPress, Apache, Nginx, etc.)
- Analyzes Docker deployability
- Checks fingerprinting capability (curl/nmap)

### **PoC Discovery**
- GitHub code search with relevance ranking
- GitLab repository search
- ExploitDB RSS feed integration
- Metasploit module detection (planned)
- Nuclei template discovery (planned)

### **Docker Automation**
- 14 pre-built deployment templates
- Auto-generates docker-compose.yml files
- Includes test scripts and cleanup scripts
- Resource requirement calculation
- Health check configuration

### **Fingerprinting**
- Generates curl commands for HTTP fingerprinting
- Creates nmap scripts for service detection
- Builds Nuclei templates for automated scanning
- Technology-specific detection strategies

### **Advanced Scoring**
- Educational value (beginner-friendly vs advanced)
- Deployment complexity (simple vs complex setup)
- Technical impact (CVSS + attack surface)
- Practical exploitability (PoC availability)

---

## 📊 Current Status

**Completion**: 95% of core features built ✅

**What's Working:**
- ✅ Multi-source CVE discovery (6 sources)
- ✅ Docker deployment automation (14 templates)
- ✅ Fingerprinting generation (curl/nmap/nuclei)
- ✅ Advanced scoring and filtering
- ✅ PostgreSQL database with persistence
- ✅ Full Docker Compose deployment
- ✅ Export to CSV & Google Sheets
- ✅ 50+ production-ready API endpoints
- ✅ Complete React frontend with Shadcn UI

**In Progress** (see [TODO.md](TODO.md)):
- ⏳ Authentication system (Milestone 1.2)
- ⏳ Subscription/tier system (Milestone 1.3)
- ⏳ VulnCheck API integration (KEV data)
- ⏳ Webhooks for n8n/Zapier
- ⏳ AI-powered features (Docker compose generation)

**Timeline**: 8-12 weeks to full SaaS launch 🚀

---

## 🔐 Security Notes

**For Production Deployment:**

⚠️ **CRITICAL**: Change these before deploying:
```bash
DB_PASSWORD=your-secure-database-password  # Not 'cvepass'!
REDIS_PASSWORD=your-secure-redis-password  # Not 'redispass'!
JWT_SECRET=your-64-character-random-string # Generate with: openssl rand -base64 64
```

**Other Security Measures:**
- Enable HTTPS (Let's Encrypt via Dokploy or nginx)
- Configure firewall (only expose ports 80, 443)
- Set NODE_ENV=production
- Review ALLOWED_ORIGINS for CORS
- Keep Docker images updated
- Enable database backups (automated with `./scripts/backup.sh`)

---

## 🚢 Deployment Options

### **1. Dokploy (Recommended)**
- One-click deployment
- Automatic SSL/TLS
- Built-in monitoring
- Zero-downtime updates
- See [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md#dokploy-deployment-recommended-for-production)

### **2. Docker Compose (Self-Hosted)**
- Full control
- Deploy anywhere (VPS, on-premise)
- Nginx for SSL/TLS (included)
- See [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md#quick-start-local-development)

### **3. Kubernetes (Advanced)**
- High availability
- Auto-scaling
- Production-grade
- Helm charts (coming soon)

---

## 📈 Roadmap

See [TODO.md](TODO.md) for complete project roadmap.

**Phase 1: Core Infrastructure** (Weeks 1-3) - 33% Complete
- [x] Database connection (PostgreSQL) ✅
- [ ] Authentication system (JWT)
- [ ] Subscription system (multi-tier)

**Phase 2: Enhanced Discovery** (Weeks 4-6)
- [ ] VulnCheck API integration (KEV data)
- [ ] Nuclei template discovery
- [ ] Metasploit module detection
- [ ] Enhanced filtering UI

**Phase 3: Automation** (Weeks 7-8)
- [ ] Webhook system (n8n, Zapier)
- [ ] Saved searches with alerts
- [ ] Email notifications

**Phase 4: AI Features** (Weeks 9-10)
- [ ] AI Docker compose generation
- [ ] Setup guide summarization
- [ ] PoC code analysis

**Phase 5: Launch** (Weeks 11-12)
- [ ] Stripe billing integration
- [ ] API documentation (Swagger)
- [ ] Production deployment
- [ ] Public launch 🚀

---

## 🤝 Contributing

Contributions welcome! Areas we need help:

- Additional CVE source adapters
- More deployment templates
- Nuclei/Metasploit integrations
- Frontend improvements
- Documentation

---

## 📝 License

(Add your license here)

---

## 🙏 Acknowledgments

**Data Sources:**
- NIST NVD
- MITRE CVE
- ExploitDB
- Vulners
- CIRCL

**Tech Stack:**
- React, Vite, TailwindCSS
- Node.js, Express, TypeScript
- PostgreSQL, Redis
- Drizzle ORM
- Shadcn UI

---

## 📞 Support

- Documentation: See `/docs` folder
- Issues: GitHub Issues
- Deployment: [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md)

---

**Built with ❤️ for the cybersecurity community**

🔐 Happy vulnerability hunting! 🎯
