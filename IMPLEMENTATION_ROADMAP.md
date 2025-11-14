# CVE Lab Platform - Implementation Roadmap

## Overview

Transform the current 95%-complete platform into a public SaaS tool in **8-12 weeks**.

---

## Phase 1: Core Infrastructure (Weeks 1-3)

### **Task 1.1: Database Connection** ⚡ CRITICAL

**Current State**: Using in-memory storage (MemStorage class)
**Goal**: Connect to PostgreSQL with Drizzle ORM

**Steps:**

1. **Update database configuration**
   ```bash
   # Create .env file
   echo "DATABASE_URL=postgresql://cveuser:cvepass@localhost:5432/cve_lab_db" > .env
   ```

2. **Create new db.ts file**
   - File: `server/db.ts`
   - Import drizzle, neon, and schema
   - Export `db` instance

   ```typescript
   import { drizzle } from 'drizzle-orm/neon-http';
   import { neon } from '@neondatabase/serverless';
   import * as schema from '../shared/schema';

   const sql = neon(process.env.DATABASE_URL!);
   export const db = drizzle(sql, { schema });
   ```

3. **Replace MemStorage in routes.ts**
   - Find all instances of `storage.` calls
   - Replace with Drizzle ORM queries
   - Example:
     ```typescript
     // Before:
     const cves = await storage.getCVEs();

     // After:
     const cves = await db.select().from(schema.cves).execute();
     ```

4. **Deploy schema to database**
   ```bash
   npm run db:push
   ```

5. **Test all endpoints**
   - Run server: `npm run dev`
   - Test each API endpoint
   - Verify data persistence

**Files to Modify:**
- Create: `server/db.ts`
- Modify: `server/routes.ts` (1,737 lines - replace all storage calls)
- Modify: `server/index.ts` (remove MemStorage initialization)

**Estimated Time**: 2-3 days

---

### **Task 1.2: Authentication System** ⚡ CRITICAL

**Current State**: No auth, but user schema exists
**Goal**: Full JWT-based authentication

**Steps:**

1. **Install dependencies**
   ```bash
   npm install bcrypt jsonwebtoken
   npm install -D @types/bcrypt @types/jsonwebtoken
   ```

2. **Create auth service**
   - File: `server/services/authService.ts`

   ```typescript
   import bcrypt from 'bcrypt';
   import jwt from 'jsonwebtoken';
   import { db } from '../db';
   import { users } from '../../shared/schema';

   const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
   const SALT_ROUNDS = 12;

   export class AuthService {
     async register(email: string, password: string, username: string) {
       // Hash password
       const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

       // Create user
       const [user] = await db.insert(users).values({
         email,
         password: hashedPassword,
         username
       }).returning();

       // Create default subscription (free tier)
       await db.insert(subscriptions).values({
         userId: user.id,
         tier: 'free',
         status: 'active',
         startDate: new Date(),
         endDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) // 1 year
       });

       return { id: user.id, email: user.email, username: user.username };
     }

     async login(email: string, password: string) {
       // Find user
       const [user] = await db.select().from(users).where(eq(users.email, email));
       if (!user) throw new Error('Invalid credentials');

       // Verify password
       const valid = await bcrypt.compare(password, user.password);
       if (!valid) throw new Error('Invalid credentials');

       // Generate JWT
       const token = jwt.sign(
         { userId: user.id, email: user.email },
         JWT_SECRET,
         { expiresIn: '24h' }
       );

       return { token, user: { id: user.id, email: user.email, username: user.username } };
     }

     verifyToken(token: string) {
       return jwt.verify(token, JWT_SECRET) as { userId: number; email: string };
     }
   }
   ```

3. **Create auth middleware**
   - File: `server/middleware/auth.ts`

   ```typescript
   import { Request, Response, NextFunction } from 'express';
   import { AuthService } from '../services/authService';

   const authService = new AuthService();

   export async function requireAuth(req: Request, res: Response, next: NextFunction) {
     const token = req.headers.authorization?.replace('Bearer ', '') || req.cookies?.token;

     if (!token) {
       return res.status(401).json({ error: 'Authentication required' });
     }

     try {
       const payload = authService.verifyToken(token);
       req.user = payload; // Add user to request
       next();
     } catch (error) {
       return res.status(401).json({ error: 'Invalid token' });
     }
   }
   ```

4. **Add auth routes to routes.ts**
   ```typescript
   // Registration
   app.post('/api/auth/register', async (req, res) => {
     const { email, password, username } = req.body;
     const authService = new AuthService();
     const user = await authService.register(email, password, username);
     res.json({ user });
   });

   // Login
   app.post('/api/auth/login', async (req, res) => {
     const { email, password } = req.body;
     const authService = new AuthService();
     const { token, user } = await authService.login(email, password);
     res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
     res.json({ user, token });
   });

   // Logout
   app.post('/api/auth/logout', (req, res) => {
     res.clearCookie('token');
     res.json({ message: 'Logged out' });
   });

   // Get current user
   app.get('/api/auth/me', requireAuth, async (req, res) => {
     const [user] = await db.select().from(users).where(eq(users.id, req.user.userId));
     res.json({ user });
   });
   ```

5. **Protect existing routes**
   ```typescript
   // Add requireAuth middleware to protected routes
   app.get('/api/cves', requireAuth, async (req, res) => { ... });
   app.post('/api/scans', requireAuth, async (req, res) => { ... });
   // etc.
   ```

6. **Create frontend login page**
   - File: `client/src/pages/login.tsx`

   ```typescript
   import { useState } from 'react';
   import { useNavigate } from 'wouter';
   import { Button } from '@/components/ui/button';
   import { Input } from '@/components/ui/input';
   import { Card } from '@/components/ui/card';

   export default function Login() {
     const [email, setEmail] = useState('');
     const [password, setPassword] = useState('');
     const [, setLocation] = useNavigate();

     const handleLogin = async (e: React.FormEvent) => {
       e.preventDefault();
       const res = await fetch('/api/auth/login', {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify({ email, password })
       });
       if (res.ok) {
         const { token } = await res.json();
         localStorage.setItem('token', token);
         setLocation('/dashboard');
       }
     };

     return (
       <div className="flex items-center justify-center min-h-screen">
         <Card className="w-full max-w-md p-8">
           <h1 className="text-2xl font-bold mb-6">Login to CVE Lab</h1>
           <form onSubmit={handleLogin} className="space-y-4">
             <Input
               type="email"
               placeholder="Email"
               value={email}
               onChange={(e) => setEmail(e.target.value)}
             />
             <Input
               type="password"
               placeholder="Password"
               value={password}
               onChange={(e) => setPassword(e.target.value)}
             />
             <Button type="submit" className="w-full">Login</Button>
           </form>
         </Card>
       </div>
     );
   }
   ```

7. **Create frontend register page**
   - File: `client/src/pages/register.tsx`
   - Similar to login page with username field

8. **Update React Query to include auth token**
   - File: `client/src/lib/queryClient.ts`

   ```typescript
   export const queryClient = new QueryClient({
     defaultOptions: {
       queries: {
         queryFn: async ({ queryKey }) => {
           const token = localStorage.getItem('token');
           const res = await fetch(`${queryKey[0]}`, {
             headers: {
               'Authorization': `Bearer ${token}`
             }
           });
           if (!res.ok) throw new Error('Network response was not ok');
           return res.json();
         }
       }
     }
   });
   ```

**Files to Create:**
- `server/services/authService.ts`
- `server/middleware/auth.ts`
- `client/src/pages/login.tsx`
- `client/src/pages/register.tsx`

**Files to Modify:**
- `server/routes.ts` (add auth routes, protect existing routes)
- `client/src/lib/queryClient.ts` (add auth headers)
- `client/src/App.tsx` (add login/register routes)

**Estimated Time**: 3-4 days

---

### **Task 1.3: Subscription System** ⚡ CRITICAL

**Current State**: No subscription model
**Goal**: Multi-tier subscription system with usage tracking

**Steps:**

1. **Update database schema**
   - File: `shared/schema.ts`
   - Add new tables:

   ```typescript
   export const subscriptions = pgTable('subscriptions', {
     id: serial('id').primaryKey(),
     userId: integer('user_id').references(() => users.id).notNull(),
     tier: text('tier', { enum: ['free', 'pro', 'premium', 'enterprise'] }).notNull(),
     status: text('status', { enum: ['active', 'cancelled', 'expired'] }).notNull(),
     startDate: timestamp('start_date').notNull(),
     endDate: timestamp('end_date'),
     stripeSubscriptionId: text('stripe_subscription_id'),
     createdAt: timestamp('created_at').defaultNow(),
     updatedAt: timestamp('updated_at').defaultNow()
   });

   export const usageMetrics = pgTable('usage_metrics', {
     id: serial('id').primaryKey(),
     userId: integer('user_id').references(() => users.id).notNull(),
     date: date('date').notNull(),
     scansRun: integer('scans_run').default(0),
     apiCalls: integer('api_calls').default(0),
     webhooksTriggered: integer('webhooks_triggered').default(0),
     exportsGenerated: integer('exports_generated').default(0),
     createdAt: timestamp('created_at').defaultNow()
   });

   export const userPreferences = pgTable('user_preferences', {
     id: serial('id').primaryKey(),
     userId: integer('user_id').references(() => users.id).notNull(),
     savedSearches: jsonb('saved_searches').$type<any[]>(),
     defaultFilters: jsonb('default_filters').$type<any>(),
     notificationSettings: jsonb('notification_settings').$type<any>(),
     webhookEndpoints: jsonb('webhook_endpoints').$type<any[]>(),
     createdAt: timestamp('created_at').defaultNow(),
     updatedAt: timestamp('updated_at').defaultNow()
   });
   ```

2. **Push schema updates**
   ```bash
   npm run db:push
   ```

3. **Create subscription service**
   - File: `server/services/subscriptionService.ts`

   ```typescript
   import { db } from '../db';
   import { subscriptions, usageMetrics } from '../../shared/schema';

   const TIER_LIMITS = {
     free: { scansPerMonth: 10, apiCallsPerDay: 100, savedSearches: 3, webhooks: 0 },
     pro: { scansPerMonth: 100, apiCallsPerDay: 1000, savedSearches: 20, webhooks: 2 },
     premium: { scansPerMonth: 500, apiCallsPerDay: 10000, savedSearches: 100, webhooks: 10 },
     enterprise: { scansPerMonth: Infinity, apiCallsPerDay: Infinity, savedSearches: Infinity, webhooks: Infinity }
   };

   export class SubscriptionService {
     async getUserSubscription(userId: number) {
       const [sub] = await db.select()
         .from(subscriptions)
         .where(eq(subscriptions.userId, userId))
         .orderBy(desc(subscriptions.createdAt))
         .limit(1);
       return sub;
     }

     async checkLimit(userId: number, limitType: 'scansPerMonth' | 'apiCallsPerDay' | 'savedSearches' | 'webhooks') {
       const sub = await this.getUserSubscription(userId);
       const limits = TIER_LIMITS[sub.tier];

       // Get current usage
       const today = new Date().toISOString().split('T')[0];
       const [usage] = await db.select()
         .from(usageMetrics)
         .where(and(
           eq(usageMetrics.userId, userId),
           eq(usageMetrics.date, today)
         ));

       if (!usage) return true; // No usage yet

       // Check limit
       if (limitType === 'scansPerMonth') {
         // Calculate month usage
         const monthStart = new Date();
         monthStart.setDate(1);
         const monthUsage = await db.select()
           .from(usageMetrics)
           .where(and(
             eq(usageMetrics.userId, userId),
             gte(usageMetrics.date, monthStart.toISOString().split('T')[0])
           ));
         const totalScans = monthUsage.reduce((sum, u) => sum + (u.scansRun || 0), 0);
         return totalScans < limits.scansPerMonth;
       }

       if (limitType === 'apiCallsPerDay') {
         return (usage.apiCalls || 0) < limits.apiCallsPerDay;
       }

       return true;
     }

     async trackUsage(userId: number, metricType: 'scan' | 'apiCall' | 'webhook' | 'export') {
       const today = new Date().toISOString().split('T')[0];

       const [existing] = await db.select()
         .from(usageMetrics)
         .where(and(
           eq(usageMetrics.userId, userId),
           eq(usageMetrics.date, today)
         ));

       if (existing) {
         // Update existing
         const updates: any = {};
         if (metricType === 'scan') updates.scansRun = (existing.scansRun || 0) + 1;
         if (metricType === 'apiCall') updates.apiCalls = (existing.apiCalls || 0) + 1;
         if (metricType === 'webhook') updates.webhooksTriggered = (existing.webhooksTriggered || 0) + 1;
         if (metricType === 'export') updates.exportsGenerated = (existing.exportsGenerated || 0) + 1;

         await db.update(usageMetrics)
           .set(updates)
           .where(eq(usageMetrics.id, existing.id));
       } else {
         // Create new
         const values: any = { userId, date: today };
         if (metricType === 'scan') values.scansRun = 1;
         if (metricType === 'apiCall') values.apiCalls = 1;
         if (metricType === 'webhook') values.webhooksTriggered = 1;
         if (metricType === 'export') values.exportsGenerated = 1;

         await db.insert(usageMetrics).values(values);
       }
     }
   }
   ```

4. **Create subscription middleware**
   - File: `server/middleware/subscription.ts`

   ```typescript
   import { Request, Response, NextFunction } from 'express';
   import { SubscriptionService } from '../services/subscriptionService';

   const subscriptionService = new SubscriptionService();

   export function checkLimit(limitType: 'scansPerMonth' | 'apiCallsPerDay') {
     return async (req: Request, res: Response, next: NextFunction) => {
       const allowed = await subscriptionService.checkLimit(req.user.userId, limitType);
       if (!allowed) {
         return res.status(429).json({
           error: 'Subscription limit reached',
           message: `You've reached your ${limitType} limit. Upgrade your plan to continue.`
         });
       }
       next();
     };
   }

   export function trackUsage(metricType: 'scan' | 'apiCall' | 'webhook' | 'export') {
     return async (req: Request, res: Response, next: NextFunction) => {
       await subscriptionService.trackUsage(req.user.userId, metricType);
       next();
     };
   }
   ```

5. **Apply middleware to routes**
   ```typescript
   import { checkLimit, trackUsage } from './middleware/subscription';

   // Scans
   app.post('/api/scans',
     requireAuth,
     checkLimit('scansPerMonth'),
     trackUsage('scan'),
     async (req, res) => { ... }
   );

   // All API calls
   app.use('/api/*', requireAuth, trackUsage('apiCall'));
   ```

6. **Add subscription routes**
   ```typescript
   // Get user subscription
   app.get('/api/subscription', requireAuth, async (req, res) => {
     const subscriptionService = new SubscriptionService();
     const sub = await subscriptionService.getUserSubscription(req.user.userId);
     res.json({ subscription: sub });
   });

   // Get usage
   app.get('/api/subscription/usage', requireAuth, async (req, res) => {
     const subscriptionService = new SubscriptionService();
     const usage = await subscriptionService.getUserUsage(req.user.userId);
     res.json({ usage });
   });
   ```

**Files to Create:**
- `server/services/subscriptionService.ts`
- `server/middleware/subscription.ts`

**Files to Modify:**
- `shared/schema.ts` (add subscription tables)
- `server/routes.ts` (add middleware, routes)

**Estimated Time**: 2-3 days

---

## Phase 2: Enhanced Discovery (Weeks 4-6)

### **Task 2.1: VulnCheck API Integration** 🔥 HIGH PRIORITY

**Goal**: Add KEV (Known Exploited Vulnerabilities) data

**Steps:**

1. **Store API key in config**
   ```typescript
   // In appConfigs table, add:
   app.post('/api/config', requireAuth, async (req, res) => {
     const { vulncheckApiKey } = req.body;
     await db.insert(appConfigs).values({
       userId: req.user.userId,
       vulncheckApiKey
     });
   });
   ```

2. **Create VulnCheck adapter**
   - File: `server/services/sourceAdapters/vulnCheckAdapter.ts`

   ```typescript
   import axios from 'axios';

   export class VulnCheckAdapter {
     private apiKey: string;
     private baseUrl = 'https://api.vulncheck.com/v3';

     constructor(apiKey: string) {
       this.apiKey = apiKey;
     }

     async getCVEEnrichment(cveId: string) {
       const response = await axios.get(`${this.baseUrl}/index/vulncheck-nvd2`, {
         headers: { 'Authorization': `Bearer ${this.apiKey}` },
         params: { cve: cveId }
       });

       const data = response.data.data[0];
       return {
         kevStatus: data.in_kev || false,
         exploitMaturity: data.exploit_status,
         threatIntel: {
           activelyExploited: data.actively_exploited || false,
           ransomwareUse: data.ransomware_use || false
         },
         vendorAdvisories: data.vendor_advisories || [],
         patchAvailable: data.patch_available || false
       };
     }

     async getKEVList() {
       const response = await axios.get(`${this.baseUrl}/index/vulncheck-kev`, {
         headers: { 'Authorization': `Bearer ${this.apiKey}` }
       });
       return response.data.data;
     }
   }
   ```

3. **Update CVE schema**
   ```typescript
   // In shared/schema.ts, add to cves table:
   kevStatus: boolean('kev_status').default(false),
   exploitMaturity: text('exploit_maturity'),
   activelyExploited: boolean('actively_exploited').default(false),
   ransomwareUse: boolean('ransomware_use').default(false),
   ```

4. **Integrate into enrichment service**
   ```typescript
   // In server/routes.ts, update /api/cves/:id/enrich endpoint
   const vulnCheckAdapter = new VulnCheckAdapter(apiKey);
   const enrichment = await vulnCheckAdapter.getCVEEnrichment(cveId);

   await db.update(cves).set({
     kevStatus: enrichment.kevStatus,
     exploitMaturity: enrichment.exploitMaturity,
     activelyExploited: enrichment.threatIntel.activelyExploited
   }).where(eq(cves.cveId, cveId));
   ```

**Files to Create:**
- `server/services/sourceAdapters/vulnCheckAdapter.ts`

**Files to Modify:**
- `shared/schema.ts` (add KEV fields)
- `server/routes.ts` (integrate adapter)

**Estimated Time**: 2-3 days

---

### **Task 2.2: Nuclei & Metasploit Adapters** 🔥 HIGH PRIORITY

**Goal**: Check for Nuclei templates and Metasploit modules

**Steps:**

1. **Create Nuclei adapter**
   - File: `server/services/sourceAdapters/nucleiAdapter.ts`

   ```typescript
   import axios from 'axios';
   import { Octokit } from '@octokit/rest';

   export class NucleiAdapter {
     private octokit: Octokit;

     constructor(githubToken?: string) {
       this.octokit = new Octokit({ auth: githubToken });
     }

     async findTemplates(cveId: string) {
       // Search Nuclei templates repo
       const { data } = await this.octokit.search.code({
         q: `${cveId} repo:projectdiscovery/nuclei-templates`,
         per_page: 10
       });

       return data.items.map(item => ({
         path: item.path,
         url: item.html_url,
         name: item.name
       }));
     }
   }
   ```

2. **Create Metasploit adapter**
   - File: `server/services/sourceAdapters/metasploitAdapter.ts`

   ```typescript
   import axios from 'axios';

   export class MetasploitAdapter {
     async findModules(cveId: string) {
       // Search Metasploit module DB (GitHub)
       const response = await axios.get(
         `https://api.github.com/search/code`,
         {
           params: {
             q: `${cveId} repo:rapid7/metasploit-framework path:modules`,
             per_page: 10
           }
         }
       );

       return response.data.items.map((item: any) => ({
         path: item.path,
         url: item.html_url,
         name: item.name,
         type: item.path.includes('/exploits/') ? 'exploit' : 'auxiliary'
       }));
     }
   }
   ```

3. **Update CVE schema**
   ```typescript
   // Add to cves table:
   nucleiTemplates: jsonb('nuclei_templates').$type<any[]>(),
   metasploitModules: jsonb('metasploit_modules').$type<any[]>(),
   ```

4. **Integrate into discovery**
   ```typescript
   // In multiSourceDiscoveryService.ts, add:
   const nucleiAdapter = new NucleiAdapter(githubToken);
   const metasploitAdapter = new MetasploitAdapter();

   const [nucleiTemplates, metasploitModules] = await Promise.all([
     nucleiAdapter.findTemplates(cveId),
     metasploitAdapter.findModules(cveId)
   ]);
   ```

**Files to Create:**
- `server/services/sourceAdapters/nucleiAdapter.ts`
- `server/services/sourceAdapters/metasploitAdapter.ts`

**Files to Modify:**
- `shared/schema.ts`
- `server/services/multiSourceDiscoveryService.ts`

**Estimated Time**: 2 days

---

### **Task 2.3: Enhanced Filtering UI** 🔥 HIGH PRIORITY

**Goal**: Add all the custom filters you mentioned

**Steps:**

1. **Update filter panel component**
   - File: `client/src/components/advanced-filter-panel.tsx`

   ```typescript
   import { useState } from 'react';
   import { Select } from '@/components/ui/select';
   import { Checkbox } from '@/components/ui/checkbox';
   import { Label } from '@/components/ui/label';

   export function AdvancedFilterPanel({ onFilterChange }: { onFilterChange: (filters: any) => void }) {
     const [filters, setFilters] = useState({
       vendors: [] as string[],
       products: [] as string[],
       vulnTypes: [] as string[],
       hasPublicPoc: false,
       pocSources: [] as string[],
       isDockerDeployable: false,
       isFingerprintable: false,
       inKEV: false,
       techCategories: [] as string[]
     });

     // Vendor selection
     const vendors = [
       'Apache', 'Microsoft', 'Ivanti', 'Fortinet', 'Palo Alto',
       'WordPress', 'Drupal', 'Joomla', 'Laravel', 'React',
       'F5', 'Citrix', 'VMware', 'Oracle', 'SAP'
     ];

     // Vuln types
     const vulnTypes = [
       'RCE', 'SQL Injection', 'XSS', 'XXE', 'SSRF',
       'Authentication Bypass', 'File Upload', 'Path Traversal',
       'Deserialization', 'Command Injection'
     ];

     // PoC sources
     const pocSources = [
       'GitHub', 'ExploitDB', 'Metasploit', 'Nuclei',
       'PacketStorm', 'Project Zero'
     ];

     // Tech categories
     const techCategories = [
       'CMS', 'Web Server', 'Firewall', 'VPN', 'CRM/ERP',
       'File Transfer', 'Load Balancer', 'Database'
     ];

     return (
       <div className="space-y-6 p-4 border rounded-lg">
         {/* Vendors */}
         <div>
           <Label>Vendors</Label>
           <Select
             multiple
             value={filters.vendors}
             onValueChange={(value) => setFilters({ ...filters, vendors: value })}
           >
             {vendors.map(v => <option key={v} value={v}>{v}</option>)}
           </Select>
         </div>

         {/* Vulnerability Types */}
         <div>
           <Label>Vulnerability Types</Label>
           <div className="grid grid-cols-2 gap-2">
             {vulnTypes.map(type => (
               <div key={type} className="flex items-center space-x-2">
                 <Checkbox
                   checked={filters.vulnTypes.includes(type)}
                   onCheckedChange={(checked) => {
                     const newTypes = checked
                       ? [...filters.vulnTypes, type]
                       : filters.vulnTypes.filter(t => t !== type);
                     setFilters({ ...filters, vulnTypes: newTypes });
                   }}
                 />
                 <label>{type}</label>
               </div>
             ))}
           </div>
         </div>

         {/* Lab Requirements */}
         <div>
           <Label>Lab Requirements</Label>
           <div className="space-y-2">
             <div className="flex items-center space-x-2">
               <Checkbox
                 checked={filters.hasPublicPoc}
                 onCheckedChange={(checked) => setFilters({ ...filters, hasPublicPoc: !!checked })}
               />
               <label>Has Public PoC</label>
             </div>
             <div className="flex items-center space-x-2">
               <Checkbox
                 checked={filters.isDockerDeployable}
                 onCheckedChange={(checked) => setFilters({ ...filters, isDockerDeployable: !!checked })}
               />
               <label>Docker Deployable</label>
             </div>
             <div className="flex items-center space-x-2">
               <Checkbox
                 checked={filters.isFingerprintable}
                 onCheckedChange={(checked) => setFilters({ ...filters, isFingerprintable: !!checked })}
               />
               <label>Fingerprintable (curl/nmap)</label>
             </div>
             <div className="flex items-center space-x-2">
               <Checkbox
                 checked={filters.inKEV}
                 onCheckedChange={(checked) => setFilters({ ...filters, inKEV: !!checked })}
               />
               <label>In CISA KEV</label>
             </div>
           </div>
         </div>

         {/* PoC Sources */}
         <div>
           <Label>PoC Sources</Label>
           <div className="grid grid-cols-2 gap-2">
             {pocSources.map(source => (
               <div key={source} className="flex items-center space-x-2">
                 <Checkbox
                   checked={filters.pocSources.includes(source)}
                   onCheckedChange={(checked) => {
                     const newSources = checked
                       ? [...filters.pocSources, source]
                       : filters.pocSources.filter(s => s !== source);
                     setFilters({ ...filters, pocSources: newSources });
                   }}
                 />
                 <label>{source}</label>
               </div>
             ))}
           </div>
         </div>

         {/* Tech Categories */}
         <div>
           <Label>Technology Categories</Label>
           <Select
             multiple
             value={filters.techCategories}
             onValueChange={(value) => setFilters({ ...filters, techCategories: value })}
           >
             {techCategories.map(cat => <option key={cat} value={cat}>{cat}</option>)}
           </Select>
         </div>

         <Button onClick={() => onFilterChange(filters)}>Apply Filters</Button>
       </div>
     );
   }
   ```

2. **Update API to support new filters**
   - Modify `server/routes.ts` GET /api/cves endpoint

**Files to Create:**
- `client/src/components/advanced-filter-panel.tsx`

**Files to Modify:**
- `server/routes.ts` (support new query params)

**Estimated Time**: 2-3 days

---

## Phase 3: Webhooks & Automation (Weeks 7-8)

### **Task 3.1: Webhook System** 🔥 HIGH PRIORITY

**Goal**: Support webhooks for n8n, Zapier, etc.

**Steps:**

1. **Add webhook tables to schema**
   ```typescript
   // In shared/schema.ts:
   export const webhooks = pgTable('webhooks', {
     id: serial('id').primaryKey(),
     userId: integer('user_id').references(() => users.id).notNull(),
     name: text('name').notNull(),
     url: text('url').notNull(),
     events: jsonb('events').$type<string[]>().notNull(),
     secret: text('secret').notNull(),
     active: boolean('active').default(true),
     lastTriggered: timestamp('last_triggered'),
     createdAt: timestamp('created_at').defaultNow()
   });

   export const webhookLogs = pgTable('webhook_logs', {
     id: serial('id').primaryKey(),
     webhookId: integer('webhook_id').references(() => webhooks.id).notNull(),
     event: text('event').notNull(),
     payload: jsonb('payload'),
     statusCode: integer('status_code'),
     response: text('response'),
     success: boolean('success'),
     createdAt: timestamp('created_at').defaultNow()
   });
   ```

2. **Create webhook service**
   - File: `server/services/webhookService.ts`

   ```typescript
   import axios from 'axios';
   import crypto from 'crypto';
   import { db } from '../db';
   import { webhooks, webhookLogs } from '../../shared/schema';

   export class WebhookService {
     async triggerWebhook(userId: number, event: string, data: any) {
       // Find webhooks for this user and event
       const userWebhooks = await db.select()
         .from(webhooks)
         .where(and(
           eq(webhooks.userId, userId),
           eq(webhooks.active, true)
         ));

       const matchingWebhooks = userWebhooks.filter(wh =>
         wh.events.includes(event)
       );

       // Trigger each webhook
       for (const webhook of matchingWebhooks) {
         await this.sendWebhook(webhook, event, data);
       }
     }

     private async sendWebhook(webhook: any, event: string, data: any) {
       const payload = {
         event,
         timestamp: new Date().toISOString(),
         data
       };

       // Generate signature
       const signature = crypto
         .createHmac('sha256', webhook.secret)
         .update(JSON.stringify(payload))
         .digest('hex');

       try {
         const response = await axios.post(webhook.url, payload, {
           headers: {
             'Content-Type': 'application/json',
             'X-CVELab-Signature': `sha256=${signature}`,
             'X-CVELab-Event': event
           },
           timeout: 10000
         });

         // Log success
         await db.insert(webhookLogs).values({
           webhookId: webhook.id,
           event,
           payload,
           statusCode: response.status,
           response: response.data,
           success: true
         });

         // Update last triggered
         await db.update(webhooks)
           .set({ lastTriggered: new Date() })
           .where(eq(webhooks.id, webhook.id));

       } catch (error: any) {
         // Log failure
         await db.insert(webhookLogs).values({
           webhookId: webhook.id,
           event,
           payload,
           statusCode: error.response?.status || 0,
           response: error.message,
           success: false
         });
       }
     }
   }
   ```

3. **Add webhook routes**
   ```typescript
   // Create webhook
   app.post('/api/webhooks', requireAuth, async (req, res) => {
     const { name, url, events } = req.body;
     const secret = crypto.randomBytes(32).toString('hex');

     const [webhook] = await db.insert(webhooks).values({
       userId: req.user.userId,
       name,
       url,
       events,
       secret
     }).returning();

     res.json({ webhook });
   });

   // List webhooks
   app.get('/api/webhooks', requireAuth, async (req, res) => {
     const userWebhooks = await db.select()
       .from(webhooks)
       .where(eq(webhooks.userId, req.user.userId));
     res.json({ webhooks: userWebhooks });
   });

   // Test webhook
   app.post('/api/webhooks/:id/test', requireAuth, async (req, res) => {
     const webhookService = new WebhookService();
     await webhookService.triggerWebhook(req.user.userId, 'test', { message: 'Test webhook' });
     res.json({ message: 'Webhook triggered' });
   });
   ```

4. **Integrate into CVE discovery**
   ```typescript
   // In routes.ts, after finding new CVEs:
   const webhookService = new WebhookService();
   await webhookService.triggerWebhook(req.user.userId, 'new_cve_match', {
     cveId: newCve.cveId,
     severity: newCve.severity,
     hasDocker: newCve.isDockerDeployable,
     hasPoc: newCve.hasPublicPoc
   });
   ```

**Files to Create:**
- `server/services/webhookService.ts`

**Files to Modify:**
- `shared/schema.ts` (add webhook tables)
- `server/routes.ts` (add routes, integrate)

**Estimated Time**: 3-4 days

---

### **Task 3.2: Saved Searches & Alerts** 🔥 HIGH PRIORITY

**Goal**: Let users save searches and get alerts on new matches

**Steps:**

1. **Add saved search table**
   ```typescript
   // In shared/schema.ts:
   export const savedSearches = pgTable('saved_searches', {
     id: serial('id').primaryKey(),
     userId: integer('user_id').references(() => users.id).notNull(),
     name: text('name').notNull(),
     filters: jsonb('filters').notNull(),
     alertOnMatch: boolean('alert_on_match').default(false),
     webhookId: integer('webhook_id').references(() => webhooks.id),
     lastChecked: timestamp('last_checked'),
     matchCount: integer('match_count').default(0),
     createdAt: timestamp('created_at').defaultNow()
   });
   ```

2. **Create saved search routes**
   ```typescript
   // Save search
   app.post('/api/searches', requireAuth, async (req, res) => {
     const { name, filters, alertOnMatch, webhookId } = req.body;
     const [search] = await db.insert(savedSearches).values({
       userId: req.user.userId,
       name,
       filters,
       alertOnMatch,
       webhookId
     }).returning();
     res.json({ search });
   });

   // List saved searches
   app.get('/api/searches', requireAuth, async (req, res) => {
     const searches = await db.select()
       .from(savedSearches)
       .where(eq(savedSearches.userId, req.user.userId));
     res.json({ searches });
   });

   // Run saved search
   app.post('/api/searches/:id/run', requireAuth, async (req, res) => {
     const [search] = await db.select()
       .from(savedSearches)
       .where(eq(savedSearches.id, parseInt(req.params.id)));

     // Run search with saved filters
     const results = await db.select()
       .from(cves)
       .where(/* apply filters from search.filters */);

     res.json({ results });
   });
   ```

3. **Create background monitoring job**
   ```typescript
   // server/jobs/monitoringSavedSearches.ts
   import cron from 'node-cron';

   export function startMonitoring() {
     // Run every hour
     cron.schedule('0 * * * *', async () => {
       // Get all saved searches with alerts enabled
       const searches = await db.select()
         .from(savedSearches)
         .where(eq(savedSearches.alertOnMatch, true));

       for (const search of searches) {
         // Run search
         const results = await runSearch(search.filters);

         // Check for new matches
         const newMatches = results.filter(r =>
           new Date(r.createdAt) > new Date(search.lastChecked || 0)
         );

         if (newMatches.length > 0) {
           // Trigger webhook
           if (search.webhookId) {
             const webhookService = new WebhookService();
             await webhookService.triggerWebhook(search.userId, 'saved_search_match', {
               searchName: search.name,
               matchCount: newMatches.length,
               matches: newMatches
             });
           }
         }

         // Update last checked
         await db.update(savedSearches)
           .set({
             lastChecked: new Date(),
             matchCount: results.length
           })
           .where(eq(savedSearches.id, search.id));
       }
     });
   }
   ```

**Files to Create:**
- `server/jobs/monitoringSavedSearches.ts`

**Files to Modify:**
- `shared/schema.ts` (add saved searches table)
- `server/routes.ts` (add routes)
- `server/index.ts` (start monitoring job)

**Estimated Time**: 2-3 days

---

## Phase 4: AI Features (Weeks 9-10)

### **Task 4.1: AI Configuration** 🟡 MEDIUM PRIORITY

**Goal**: Let users configure AI API keys

**Steps:**

1. **Add AI config table**
   ```typescript
   // In shared/schema.ts:
   export const aiConfigs = pgTable('ai_configs', {
     id: serial('id').primaryKey(),
     userId: integer('user_id').references(() => users.id).notNull(),
     provider: text('provider', { enum: ['openai', 'anthropic', 'ollama'] }).notNull(),
     apiKey: text('api_key'), // Encrypted
     model: text('model'),
     features: jsonb('features').$type<string[]>(),
     createdAt: timestamp('created_at').defaultNow()
   });
   ```

2. **Create AI config page**
   - File: `client/src/pages/ai-config.tsx`

3. **Create AI config routes**
   ```typescript
   app.post('/api/ai/config', requireAuth, async (req, res) => {
     const { provider, apiKey, model } = req.body;
     // TODO: Encrypt API key before storing
     const [config] = await db.insert(aiConfigs).values({
       userId: req.user.userId,
       provider,
       apiKey,
       model
     }).returning();
     res.json({ config });
   });
   ```

**Estimated Time**: 1-2 days

---

### **Task 4.2: AI Docker Compose Generator** 🟡 MEDIUM PRIORITY

**Goal**: Use AI to generate docker-compose.yml files

**Steps:**

1. **Create AI Docker service**
   - File: `server/services/aiDockerService.ts`

   ```typescript
   import Anthropic from '@anthropic-ai/sdk';
   import OpenAI from 'openai';

   export class AiDockerService {
     async generateDockerCompose(cve: any, userAiConfig: any) {
       const prompt = `
         Generate a complete docker-compose.yml file for setting up a vulnerable lab environment for ${cve.cveId}.

         CVE Details:
         - Product: ${cve.affectedProducts?.join(', ')}
         - Version: ${cve.affectedVersions?.join(', ')}
         - Description: ${cve.description}

         Requirements:
         1. Use vulnerable version of the software
         2. Include any necessary dependencies
         3. Expose appropriate ports
         4. Add comments explaining configuration
         5. Include health checks
         6. Add a README section with setup instructions

         Return ONLY the docker-compose.yml content.
       `;

       if (userAiConfig.provider === 'anthropic') {
         const anthropic = new Anthropic({ apiKey: userAiConfig.apiKey });
         const message = await anthropic.messages.create({
           model: userAiConfig.model || 'claude-3-5-sonnet-20241022',
           max_tokens: 2000,
           messages: [{ role: 'user', content: prompt }]
         });
         return message.content[0].text;
       }

       if (userAiConfig.provider === 'openai') {
         const openai = new OpenAI({ apiKey: userAiConfig.apiKey });
         const completion = await openai.chat.completions.create({
           model: userAiConfig.model || 'gpt-4',
           messages: [{ role: 'user', content: prompt }]
         });
         return completion.choices[0].message.content;
       }

       throw new Error('Unsupported AI provider');
     }
   }
   ```

2. **Add AI generation endpoint**
   ```typescript
   app.post('/api/ai/docker-compose', requireAuth, async (req, res) => {
     const { cveId } = req.body;

     // Get CVE
     const [cve] = await db.select().from(cves).where(eq(cves.cveId, cveId));

     // Get user AI config
     const [aiConfig] = await db.select().from(aiConfigs).where(eq(aiConfigs.userId, req.user.userId));

     if (!aiConfig) {
       return res.status(400).json({ error: 'AI not configured' });
     }

     const aiService = new AiDockerService();
     const dockerCompose = await aiService.generateDockerCompose(cve, aiConfig);

     res.json({ dockerCompose });
   });
   ```

**Files to Create:**
- `server/services/aiDockerService.ts`

**Files to Modify:**
- `server/routes.ts` (add endpoint)

**Estimated Time**: 2 days

---

## Phase 5: Polish & Launch (Weeks 11-12)

### **Task 5.1: API Documentation** 🔥 HIGH PRIORITY

**Goal**: OpenAPI/Swagger documentation

**Steps:**

1. **Install swagger dependencies**
   ```bash
   npm install swagger-ui-express swagger-jsdoc
   ```

2. **Create OpenAPI spec**
   - File: `docs/api/openapi.yaml`

3. **Add swagger route**
   ```typescript
   import swaggerUi from 'swagger-ui-express';
   import swaggerJsdoc from 'swagger-jsdoc';

   const swaggerSpec = swaggerJsdoc({
     definition: {
       openapi: '3.0.0',
       info: {
         title: 'CVE Lab API',
         version: '1.0.0'
       }
     },
     apis: ['./server/routes.ts']
   });

   app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
   ```

**Estimated Time**: 2-3 days

---

### **Task 5.2: Billing Integration** 🔥 HIGH PRIORITY

**Goal**: Stripe subscription management

**Steps:**

1. **Install Stripe**
   ```bash
   npm install stripe
   ```

2. **Create Stripe service**
   - File: `server/services/stripeService.ts`

3. **Add billing routes**
   ```typescript
   app.post('/api/subscription/checkout', requireAuth, async (req, res) => {
     const { tier } = req.body;
     // Create Stripe checkout session
   });

   app.post('/api/subscription/cancel', requireAuth, async (req, res) => {
     // Cancel subscription
   });

   app.post('/api/webhooks/stripe', async (req, res) => {
     // Handle Stripe webhooks (payment success, etc.)
   });
   ```

**Estimated Time**: 3-4 days

---

### **Task 5.3: Production Deployment** 🔥 HIGH PRIORITY

**Goal**: Deploy to production

**Steps:**

1. **Create production Docker files**
2. **Set up CI/CD (GitHub Actions)**
3. **Configure monitoring (Sentry, Prometheus)**
4. **Set up domain & SSL**
5. **Deploy database migrations**

**Estimated Time**: 3-5 days

---

## Summary Timeline

**Total: 8-12 weeks**

- **Weeks 1-3**: Core infrastructure (DB, auth, subscriptions)
- **Weeks 4-6**: Enhanced discovery (VulnCheck, Nuclei, Metasploit)
- **Weeks 7-8**: Webhooks & automation
- **Weeks 9-10**: AI features (optional, can defer)
- **Weeks 11-12**: Polish & launch (docs, billing, deployment)

---

## Priority Order

**Critical (Must have for launch):**
1. Database connection
2. Authentication
3. Subscription system
4. VulnCheck API
5. Webhooks
6. API documentation
7. Billing

**High (Should have):**
8. Saved searches
9. Enhanced filtering UI
10. Nuclei/Metasploit adapters
11. Production deployment

**Medium (Nice to have):**
12. AI features
13. Advanced analytics
14. Additional integrations

---

## Next Actions

1. **Review this plan** - Does it match your vision?
2. **Prioritize features** - What's most important?
3. **Answer questions** from ARCHITECTURE.md
4. **Start Phase 1** - Connect database first!

Let me know what you'd like to tackle first!
