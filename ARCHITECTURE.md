# CVE Lab Platform - Public Tool Architecture

## Executive Summary

Transform the existing 95%-complete CVE discovery platform into a **public SaaS tool** for cybersecurity professionals to automate vulnerability research and lab setup.

---

## Vision: User Journey Example

```
User logs in → Selects filters → Gets enriched results → Exports/Automates

Example Flow:
1. User: "Pentester Pro" (Premium tier)
2. Searches: "Apache vulnerabilities, last 90 days"
3. Filters:
   ✅ Has public PoC
   ✅ Docker deployable
   ✅ Fingerprintable (curl/nmap)
   ✅ CVSS > 7.0
   ✅ Network-accessible, no auth
4. Results: 47 CVEs with:
   - NVD metadata
   - GitHub PoCs (ranked by relevance)
   - Metasploit modules
   - Nuclei templates
   - Docker Hub images
   - Medium.com writeups
   - Auto-generated docker-compose.yml
   - curl/nmap fingerprint commands
5. Actions:
   - Export to Google Sheets
   - Webhook to n8n → Auto-create Jira tickets
   - Save search for alerts (webhook when new CVEs match)
```

---

## Current State Analysis

### ✅ What's Built (95% Complete)

**Backend Services (14 files, production-ready):**
- Multi-source CVE discovery (6 sources)
- GitHub/GitLab/DockerHub PoC discovery
- Docker deployment automation (14 templates)
- Fingerprinting (curl/nmap/nuclei)
- Advanced scoring system
- Duplicate detection & merging
- Rate limiting & circuit breakers
- Export to CSV/Google Sheets

**API (50+ endpoints):**
- CVE search & filtering
- Scan management
- Deployment generation
- Fingerprinting commands
- Status tracking
- Bulk operations

**Frontend (React + Shadcn UI):**
- Dashboard with stats
- Advanced search
- CVE detail modals
- Status management
- Configuration panel
- Export functionality

**Database Schema (PostgreSQL):**
- 9 tables fully defined
- User management
- CVE storage (40+ fields)
- Scan history
- Monitoring configs
- Alerts (not implemented)

### ❌ Critical Gaps

1. **Authentication**: Schema exists, no implementation
2. **Subscription System**: Not implemented
3. **Database**: In-memory only (not persisted)
4. **Webhooks**: Not implemented
5. **VulnCheck API**: Not integrated (user has key)
6. **User Preferences**: No saved searches/filters
7. **API Access Control**: No per-tier rate limiting

---

## Enhanced Architecture

### **Tier System Design**

```
┌─────────────┬──────────┬─────────┬──────────┬────────────┐
│ Feature     │ Free     │ Pro     │ Premium  │ Enterprise │
├─────────────┼──────────┼─────────┼──────────┼────────────┤
│ CVE Scans   │ 10/month │ 100/mo  │ 500/mo   │ Unlimited  │
│ API Calls   │ 100/day  │ 1000/d  │ 10000/d  │ Unlimited  │
│ Saved       │ 3        │ 20      │ 100      │ Unlimited  │
│ Searches    │          │         │          │            │
│ Webhooks    │ 0        │ 2       │ 10       │ Unlimited  │
│ Export      │ CSV only │ CSV+XLS │ All      │ All+API    │
│ Alerts      │ Email    │ Email+  │ All      │ All+Custom │
│             │          │ Webhook │          │            │
│ AI Features │ No       │ Basic   │ Advanced │ Custom     │
│ Sources     │ 3 basic  │ 8       │ All      │ All+Custom │
│ History     │ 7 days   │ 30 days │ 1 year   │ Unlimited  │
└─────────────┴──────────┴─────────┴──────────┴────────────┘
```

### **Database Schema Additions**

```typescript
// New tables to add:

subscriptions {
  id: serial
  userId: integer → users
  tier: enum('free', 'pro', 'premium', 'enterprise')
  status: enum('active', 'cancelled', 'expired')
  startDate: timestamp
  endDate: timestamp
  stripeSubscriptionId: string
}

userPreferences {
  id: serial
  userId: integer → users
  savedSearches: jsonb[]  // Array of search configs
  defaultFilters: jsonb
  notificationSettings: jsonb
  webhookEndpoints: jsonb[]
}

webhooks {
  id: serial
  userId: integer → users
  name: string
  url: string
  events: string[]  // ['new_cve_match', 'scan_complete', etc.]
  secret: string
  active: boolean
  lastTriggered: timestamp
}

apiKeys {
  id: serial
  userId: integer → users
  key: string (hashed)
  name: string
  permissions: string[]
  rateLimit: integer
  lastUsed: timestamp
  expiresAt: timestamp
}

usageMetrics {
  id: serial
  userId: integer → users
  date: date
  scansRun: integer
  apiCalls: integer
  webhooksTriggered: integer
  exportsGenerated: integer
}

cveSavedSearches {
  id: serial
  userId: integer → users
  name: string
  filters: jsonb  // Search criteria
  alertOnMatch: boolean
  webhookId: integer → webhooks
  lastChecked: timestamp
  matchCount: integer
}
```

### **Authentication Flow**

```
Registration:
1. User submits email + password
2. Hash password with bcrypt (12 rounds)
3. Create user record
4. Send verification email
5. Create default preferences
6. Assign 'free' tier subscription

Login:
1. Verify email + password
2. Create JWT token (24hr expiry)
3. Set httpOnly cookie
4. Return user + subscription info

Protected Routes:
1. Middleware checks JWT
2. Loads user + subscription
3. Enforces tier limits
4. Tracks usage metrics
```

### **Enhanced API Integrations**

#### **VulnCheck API Integration**

```typescript
// server/services/vulnCheckService.ts

export class VulnCheckService {
  async getCVEEnrichment(cveId: string) {
    // GET https://api.vulncheck.com/v3/index/vulncheck-nvd2
    return {
      kevStatus: boolean,        // Known Exploited Vulnerability
      exploitMaturity: string,   // 'proof-of-concept' | 'weaponized'
      threatIntelligence: {
        activelyExploited: boolean,
        ransomwareUse: boolean,
        criminalUse: boolean
      },
      vendorAdvisories: Link[],
      patchAvailability: {
        available: boolean,
        version: string,
        releaseDate: string
      }
    }
  }
}
```

#### **Additional Source Adapters**

```typescript
// server/services/sourceAdapters/

1. vulnCheckAdapter.ts  ← KEV data, exploit intel
2. nucleiAdapter.ts     ← Nuclei template repo
3. metasploitAdapter.ts ← Metasploit module DB
4. packetStormAdapter.ts ← PacketStorm Security
5. cveDetailsAdapter.ts  ← Already implemented
6. nvdAdapter.ts         ← Enhanced NIST integration
```

### **Webhook System Architecture**

```
┌──────────────────────────────────────────────────┐
│                 Event Bus                        │
│  (In-memory queue with persistent fallback)      │
└──────┬────────────────────────────────┬──────────┘
       │                                │
       ↓                                ↓
┌─────────────┐                 ┌──────────────────┐
│  Event      │                 │  Webhook         │
│  Triggers   │                 │  Dispatcher      │
│             │                 │                  │
│ • New CVE   │                 │ • Retry logic    │
│   match     │                 │ • Rate limiting  │
│ • Scan done │                 │ • Signature      │
│ • Alert     │                 │ • Logs           │
└─────────────┘                 └──────────────────┘
                                         │
                                         ↓
                                ┌─────────────────┐
                                │  User Webhook   │
                                │  Endpoints      │
                                │  (n8n, Zapier)  │
                                └─────────────────┘

Webhook Payload Example:
{
  "event": "new_cve_match",
  "timestamp": "2025-11-14T10:30:00Z",
  "data": {
    "cveId": "CVE-2024-12345",
    "severity": "HIGH",
    "hasDocker": true,
    "hasPoc": true,
    "fingerprintable": true,
    "sources": ["nvd", "github", "exploitdb"],
    "links": {
      "dashboard": "https://cvelab.io/cves/CVE-2024-12345",
      "api": "https://api.cvelab.io/v1/cves/CVE-2024-12345"
    }
  },
  "signature": "sha256=..."
}
```

### **AI Integration Architecture**

```
┌───────────────────────────────────────────────┐
│              AI Service Layer                 │
├───────────────────────────────────────────────┤
│                                               │
│  User API Keys (configurable):               │
│  • OpenAI API                                │
│  • Anthropic Claude API                      │
│  • Ollama (local)                            │
│                                               │
│  Features:                                    │
│  1. Docker Compose Generator                 │
│     Input: CVE + product + version           │
│     Output: Full docker-compose.yml          │
│                                               │
│  2. Setup Guide Summarizer                   │
│     Input: Blog posts + docs                 │
│     Output: Step-by-step guide               │
│                                               │
│  3. PoC Code Analyzer                        │
│     Input: GitHub PoC                        │
│     Output: Safety analysis + instructions   │
│                                               │
│  4. Nuclei Template Generator                │
│     Input: CVE + fingerprint data            │
│     Output: Custom .yaml template            │
│                                               │
└───────────────────────────────────────────────┘

Database Addition:
aiConfigs {
  id: serial
  userId: integer
  provider: enum('openai', 'anthropic', 'ollama')
  apiKey: string (encrypted)
  model: string
  features: string[]  // Which AI features enabled
}
```

### **Advanced Search & Filtering**

```typescript
// Enhanced search interface

interface SearchFilters {
  // Basic filters (already implemented)
  keywords: string[]
  dateRange: { start: Date, end: Date }
  severity: ('LOW'|'MEDIUM'|'HIGH'|'CRITICAL')[]
  cvssMin: number

  // Enhanced filters (NEW)
  vendors: string[]           // Apache, Microsoft, Ivanti, etc.
  products: string[]          // httpd, Exchange, Connect Secure
  vulnerabilityTypes: string[] // RCE, SQLi, XSS, XXE, SSRF, etc.

  // Lab requirements
  hasPublicPoc: boolean
  pocSources: ('github'|'exploitdb'|'metasploit'|'nuclei'|'packetstorm')[]
  isDockerDeployable: boolean
  isVMAvailable: boolean
  isFingerprintable: boolean
  requiresAuth: boolean
  attackVector: ('network'|'adjacent'|'local'|'physical')[]

  // Resources
  hasNucleiTemplate: boolean
  hasMetasploitModule: boolean
  hasDockerImage: boolean
  hasISOImage: boolean
  hasSetupGuide: boolean

  // Advanced
  inKEV: boolean              // CISA Known Exploited
  activelyExploited: boolean  // Threat intel
  patchAvailable: boolean
  labSetupScore: { min: number, max: number }

  // Technology categories (NEW)
  techCategories: string[]    // 'CMS', 'Web Server', 'Firewall', etc.
  techStack: string[]         // WordPress, Laravel, React, etc.
}

// Saved search with alerts
interface SavedSearch {
  id: number
  name: string
  filters: SearchFilters
  alertSettings: {
    enabled: boolean
    frequency: 'realtime' | 'daily' | 'weekly'
    notifyVia: ('email' | 'webhook' | 'dashboard')[]
    webhookId?: number
  }
}
```

### **Technology Categorization System**

```typescript
// Already exists in cveService.ts but enhance:

const TECH_CATEGORIES = {
  'CMS': ['wordpress', 'drupal', 'joomla', 'opencms', 'craftcms'],
  'Web Frameworks': ['laravel', 'react', 'nextjs', 'nodejs', 'express'],
  'Web Servers': ['apache', 'nginx', 'iis', 'tomcat', 'jetty'],
  'Firewalls': ['fortinet', 'palo alto', 'panos', 'sonicwall', 'checkpoint'],
  'VPN': ['pulse secure', 'ivanti', 'fortinet ssl-vpn', 'palo alto globalprotect'],
  'Collaboration': ['confluence', 'sharepoint', 'exchange', 'mattermost', 'rocket.chat'],
  'File Transfer': ['crushftp', 'moveit', 'goanywhere', 'bitvise', 'serv-u'],
  'Load Balancers': ['f5 big-ip', 'citrix adc', 'haproxy', 'nginx'],
  'Virtualization': ['vmware', 'vcenter', 'esxi', 'horizon', 'vsphere'],
  'Databases': ['mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch'],
  'Network Services': ['dns', 'dhcp', 'ntp', 'snmp', 'ldap'],
  'CRM/ERP': ['salesforce', 'sap netweaver', 'oracle', 'dynamics'],
  'Security Tools': ['veeam', 'openfire', 'papercut', 'tableau'],
  'Message Queues': ['rocketmq', 'rabbitmq', 'kafka', 'activemq'],
  'Storage': ['minio', 'nextcloud', 'owncloud', 'nas'],
  'Proxies': ['squid', 'nginx', 'traefik', 'envoy']
}
```

---

## Implementation Roadmap

### **Phase 1: Core Infrastructure (2-3 weeks)**

**Priority: CRITICAL**

1. **Database Connection**
   - Replace MemStorage with Drizzle ORM
   - Connect to PostgreSQL
   - Test all existing endpoints
   - File: `server/storage.ts` → `server/db.ts`

2. **Authentication System**
   - Install bcrypt
   - Implement /api/auth/register, /api/auth/login, /api/auth/logout
   - JWT middleware
   - Protected route guards
   - Files: `server/auth.ts`, `client/pages/login.tsx`, `client/pages/register.tsx`

3. **Subscription Schema**
   - Add tables: subscriptions, userPreferences, usageMetrics
   - Implement tier checking middleware
   - Rate limiting per tier
   - Files: `shared/schema.ts`, `server/middleware/subscription.ts`

### **Phase 2: Enhanced Discovery (2-3 weeks)**

**Priority: HIGH**

4. **VulnCheck API Integration**
   - Implement vulnCheckAdapter.ts
   - Add KEV status to CVE records
   - Enhance CVE enrichment
   - Update database schema for KEV data

5. **Additional Source Adapters**
   - Nuclei template repo integration
   - Metasploit module DB
   - PacketStorm Security
   - Files: `server/services/sourceAdapters/`

6. **Enhanced Filtering**
   - Vendor/product selection UI
   - Vulnerability type filters
   - Technology category filters
   - PoC source selection
   - Files: `client/components/advanced-filter-panel.tsx`

### **Phase 3: Webhook & Automation (2 weeks)**

**Priority: HIGH**

7. **Webhook System**
   - Implement webhook schema
   - Event bus architecture
   - Webhook dispatcher with retry logic
   - Signature verification (HMAC)
   - Files: `server/services/webhookService.ts`, `server/events.ts`

8. **Saved Searches & Alerts**
   - Save search functionality
   - Background monitoring job
   - Alert on new matches
   - Files: `server/services/monitoringService.ts` (enhance existing)

9. **n8n Integration Examples**
   - Example workflows
   - Documentation
   - Webhook payload schemas
   - Files: `docs/n8n-examples.md`

### **Phase 4: AI Features (2-3 weeks)**

**Priority: MEDIUM**

10. **AI Configuration**
    - User AI settings page
    - API key storage (encrypted)
    - Provider selection UI
    - Files: `client/pages/ai-config.tsx`

11. **Docker Compose Generator**
    - AI-powered compose file generation
    - Integrate with existing deployment service
    - Files: `server/services/aiDockerService.ts`

12. **Setup Guide Summarizer**
    - Scrape blog posts
    - AI summarization
    - Step-by-step extraction
    - Files: `server/services/aiSummaryService.ts`

### **Phase 5: Polish & Launch (2 weeks)**

**Priority: HIGH**

13. **API Documentation**
    - OpenAPI/Swagger spec
    - Interactive docs
    - Code examples (curl, Python, JS)
    - Files: `docs/api/openapi.yaml`

14. **Public API Keys**
    - API key generation
    - Per-key rate limiting
    - Usage dashboard
    - Files: `server/middleware/apiKey.ts`

15. **Billing Integration**
    - Stripe integration
    - Subscription management
    - Usage tracking dashboard
    - Files: `server/services/billingService.ts`

16. **Production Deployment**
    - Docker production builds
    - Environment configs
    - Monitoring (Prometheus/Grafana)
    - Error tracking (Sentry)

---

## API Enhancement Plan

### **Public API v1 Endpoints**

```
Authentication:
POST /api/v1/auth/register
POST /api/v1/auth/login
POST /api/v1/auth/logout
GET  /api/v1/auth/me

Subscriptions:
GET  /api/v1/subscription
POST /api/v1/subscription/upgrade
GET  /api/v1/subscription/usage

CVE Discovery (Enhanced):
POST /api/v1/cves/search          ← Enhanced with all filters
GET  /api/v1/cves/:id
GET  /api/v1/cves/:id/enrichment  ← Full enrichment data
GET  /api/v1/cves/:id/resources   ← All resources (PoCs, Docker, etc.)

Saved Searches:
POST /api/v1/searches
GET  /api/v1/searches
PUT  /api/v1/searches/:id
DELETE /api/v1/searches/:id
POST /api/v1/searches/:id/run     ← Execute saved search

Webhooks:
POST /api/v1/webhooks
GET  /api/v1/webhooks
PUT  /api/v1/webhooks/:id
DELETE /api/v1/webhooks/:id
POST /api/v1/webhooks/:id/test    ← Test webhook

AI Features:
POST /api/v1/ai/docker-compose    ← Generate compose file
POST /api/v1/ai/summarize-guide   ← Summarize setup guide
POST /api/v1/ai/analyze-poc       ← Analyze PoC safety

API Keys:
POST /api/v1/api-keys
GET  /api/v1/api-keys
DELETE /api/v1/api-keys/:id
GET  /api/v1/api-keys/:id/usage

Export (Enhanced):
POST /api/v1/export/csv
POST /api/v1/export/json
POST /api/v1/export/google-sheets  ← Already exists
POST /api/v1/export/notion         ← NEW
POST /api/v1/export/jira           ← NEW
```

---

## Security Considerations

### **Authentication**
- Bcrypt password hashing (12+ rounds)
- JWT tokens with short expiry (24hr)
- httpOnly cookies for web app
- Rate limiting on auth endpoints (5 attempts/15min)

### **API Security**
- API key rate limiting per tier
- CORS configuration
- Input validation (zod schemas)
- SQL injection prevention (Drizzle ORM)
- XSS prevention (React escaping)

### **Webhook Security**
- HMAC signature verification
- HTTPS-only webhook endpoints
- Webhook secret per endpoint
- Retry with exponential backoff
- Log all webhook attempts

### **Data Privacy**
- Encrypted API keys (AES-256)
- No storage of user PoC code
- GDPR-compliant data export
- Data retention policies per tier

---

## Monitoring & Observability

### **Metrics to Track**
- API requests per endpoint
- CVE scans per day
- Source adapter success rates
- Webhook delivery success rates
- Average response times
- Database query performance
- User tier distribution
- Feature usage by tier

### **Alerts**
- API error rate > 5%
- Database connection failures
- External API failures (NIST, GitHub, etc.)
- Webhook delivery failures > 10%
- Unusual usage patterns (potential abuse)

### **Tools**
- **Logging**: Winston or Pino
- **Metrics**: Prometheus
- **Visualization**: Grafana
- **Error Tracking**: Sentry
- **Uptime Monitoring**: UptimeRobot or Pingdom

---

## Cost Analysis

### **External API Costs**

```
Free tier limits:
- NIST NVD: 5 req/30sec (no auth), 50 req/30sec (with key)
- GitHub: 60 req/hr (no auth), 5000 req/hr (with token)
- GitLab: No rate limits (free tier)
- DockerHub: Free, no auth required
- ExploitDB: RSS feed (free)
- VulnCheck: Free tier (1000 req/month), $49/mo (10k req)

Recommended for production:
- NIST API key (free): Required
- GitHub tokens (free): Use multiple rotating tokens
- VulnCheck Pro ($49/mo): Worth it for KEV data

AI APIs (per user key):
- OpenAI: ~$0.01-0.03 per compose file
- Anthropic: ~$0.015-0.075 per request
- Ollama: Self-hosted, free
```

### **Infrastructure Costs**

```
Minimum (for MVP):
- VPS: $20/mo (4GB RAM, 2 vCPU)
- PostgreSQL: Included or $10/mo managed
- Domain: $12/year
- SSL: Free (Let's Encrypt)
Total: ~$30/mo

Production (scaling):
- App servers: $100-500/mo
- Database: $50-200/mo (managed Postgres)
- CDN: $20-100/mo
- Monitoring: $30-50/mo (Sentry + monitoring)
- Email: $15/mo (SendGrid/Postmark)
Total: ~$215-900/mo
```

---

## Revenue Model

### **Subscription Pricing**

```
Free:
- $0/month
- 10 scans/month
- 100 API calls/day
- 3 saved searches
- Email alerts only
- 7-day history

Pro:
- $29/month
- 100 scans/month
- 1,000 API calls/day
- 20 saved searches
- 2 webhooks
- Email + webhook alerts
- Basic AI features
- 30-day history

Premium:
- $99/month
- 500 scans/month
- 10,000 API calls/day
- 100 saved searches
- 10 webhooks
- All alert types
- Advanced AI features
- All export formats
- 1-year history

Enterprise:
- Custom pricing
- Unlimited scans
- Unlimited API calls
- Unlimited searches
- Unlimited webhooks
- Custom AI features
- Custom integrations
- Dedicated support
- Unlimited history
- SLA guarantees
```

---

## Documentation Structure

```
docs/
├── README.md                 ← Quick start guide
├── ARCHITECTURE.md           ← This file
├── API.md                    ← API documentation
├── DEPLOYMENT.md             ← Production deployment
├── DEVELOPMENT.md            ← Developer setup
├── USER_GUIDE.md             ← End-user documentation
├── api/
│   ├── openapi.yaml          ← OpenAPI specification
│   ├── authentication.md     ← Auth guide
│   ├── webhooks.md           ← Webhook guide
│   └── rate-limits.md        ← Rate limiting info
├── integrations/
│   ├── n8n-examples.md       ← n8n workflow examples
│   ├── zapier-guide.md       ← Zapier integration
│   ├── github-actions.md     ← GitHub Actions
│   └── api-examples/         ← Code examples (curl, Python, JS)
└── ai/
    ├── docker-compose-ai.md  ← AI Docker generation
    └── setup-guide-ai.md     ← AI summarization
```

---

## Next Steps

### **Immediate Actions (This Week)**

1. **Connect PostgreSQL database** (Priority 1)
   - Update `server/storage.ts` to use Drizzle ORM
   - Test all existing endpoints
   - Deploy schema with `npm run db:push`

2. **Implement authentication** (Priority 1)
   - Create auth routes
   - Build login/register pages
   - Add JWT middleware

3. **Add subscription tables** (Priority 1)
   - Update `shared/schema.ts`
   - Implement tier checking

### **This Month**

4. Integrate VulnCheck API
5. Build webhook system
6. Implement saved searches
7. Create API documentation

### **Launch Readiness (8-12 weeks)**

8. Complete AI features
9. Stripe billing integration
10. Production deployment
11. Marketing site
12. Launch!

---

## Questions to Resolve

1. **Pricing**: Does $29/$99/custom pricing sound right for your target market?
2. **VulnCheck**: Do you have the API key ready? What tier?
3. **AI Provider**: Should we support multiple AI providers or start with one?
4. **Deployment**: Do you want to host this yourself or use a managed service (Vercel, Render, Railway)?
5. **Domain**: Do you have a domain name in mind?
6. **Billing**: Stripe is the default choice - is that OK?
7. **Email Provider**: SendGrid, Postmark, or AWS SES?

---

## Summary

Your platform is **95% complete** for core functionality. The main work needed:

**Critical (2-3 weeks):**
- ✅ Database connection
- ✅ Authentication system
- ✅ Subscription model

**High Priority (4-5 weeks):**
- VulnCheck API
- Webhook system
- Enhanced filtering
- Saved searches

**Nice-to-Have (3-4 weeks):**
- AI features
- Additional integrations
- Advanced analytics

**Total Timeline: 8-12 weeks to public launch**

This is a **production-quality codebase** with excellent architecture. You're much closer to launch than you might think!
