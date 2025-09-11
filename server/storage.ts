import { 
  type User, type InsertUser, 
  type Cve, type InsertCve, 
  type CveScan, type InsertCveScan,
  type MonitoringConfig, type InsertMonitoringConfig,
  type CveAlert, type InsertCveAlert,
  type MonitoringRun, type InsertMonitoringRun
} from "@shared/schema";
import { randomUUID } from "crypto";

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  getCve(id: string): Promise<Cve | undefined>;
  getCveByCveId(cveId: string): Promise<Cve | undefined>;
  getCveByIds(ids: string[]): Promise<Cve[]>;
  getCves(filters?: CveFilters): Promise<Cve[]>;
  createCve(cve: InsertCve): Promise<Cve>;
  updateCve(id: string, updates: Partial<InsertCve>): Promise<Cve | undefined>;
  createOrUpdateCve(cve: InsertCve): Promise<{ cve: Cve; isNew: boolean; changes?: string[] }>;
  deleteCve(id: string): Promise<boolean>;
  
  getCveScan(id: string): Promise<CveScan | undefined>;
  getCveScans(): Promise<CveScan[]>;
  createCveScan(scan: InsertCveScan): Promise<CveScan>;
  updateCveScan(id: string, updates: Partial<InsertCveScan>): Promise<CveScan | undefined>;
  
  // Monitoring functionality
  getMonitoringConfig(): Promise<MonitoringConfig | undefined>;
  createMonitoringConfig(config: InsertMonitoringConfig): Promise<MonitoringConfig>;
  updateMonitoringConfig(id: string, updates: Partial<InsertMonitoringConfig>): Promise<MonitoringConfig | undefined>;
  
  getCveAlert(id: string): Promise<CveAlert | undefined>;
  getCveAlerts(filters?: { isRead?: boolean; isDismissed?: boolean; severity?: string[] }): Promise<CveAlert[]>;
  createCveAlert(alert: InsertCveAlert): Promise<CveAlert>;
  updateCveAlert(id: string, updates: Partial<InsertCveAlert>): Promise<CveAlert | undefined>;
  markAlertAsRead(id: string): Promise<boolean>;
  dismissAlert(id: string): Promise<boolean>;
  getUnreadAlertsCount(): Promise<number>;
  
  getMonitoringRun(id: string): Promise<MonitoringRun | undefined>;
  getMonitoringRuns(limit?: number): Promise<MonitoringRun[]>;
  createMonitoringRun(run: InsertMonitoringRun): Promise<MonitoringRun>;
  updateMonitoringRun(id: string, updates: Partial<InsertMonitoringRun>): Promise<MonitoringRun | undefined>;
  getLastSuccessfulMonitoringRun(): Promise<MonitoringRun | undefined>;
  
  getCveStats(): Promise<CveStats>;
  
  // CVE List Management
  updateCveStatus(id: string, updates: CveStatusUpdate): Promise<Cve | undefined>;
  updateCveStatusBulk(ids: string[], updates: CveStatusUpdate): Promise<Cve[]>;
  getCveLists(): Promise<CveListSummary[]>;
  getCveStatusStats(): Promise<CveStatusStats>;
  getPriorityCves(): Promise<Cve[]>;
}

export interface CveFilters {
  severity?: string[];
  technology?: string[];
  hasPublicPoc?: boolean;
  isDockerDeployable?: boolean;
  isCurlTestable?: boolean;
  minCvssScore?: number;
  maxCvssScore?: number;
  search?: string;
  status?: string[];
  listCategory?: string[];
  isPriority?: boolean;
  hideDone?: boolean;
  limit?: number;
  offset?: number;
}

export interface CveStats {
  totalCves: number;
  deployable: number;
  withPoc: number;
  critical: number;
}

export interface CveStatusUpdate {
  status?: string;
  listCategory?: string;
  isPriority?: boolean;
  userNotes?: string;
}

export interface CveListSummary {
  listCategory: string;
  count: number;
}

export interface CveStatusStats {
  new: number;
  inProgress: number;
  done: number;
  unlisted: number;
  total: number;
}

export class MemStorage implements IStorage {
  private users: Map<string, User>;
  private cves: Map<string, Cve>;
  private cveScans: Map<string, CveScan>;
  private monitoringConfigs: Map<string, MonitoringConfig>;
  private cveAlerts: Map<string, CveAlert>;
  private monitoringRuns: Map<string, MonitoringRun>;

  constructor() {
    this.users = new Map();
    this.cves = new Map();
    this.cveScans = new Map();
    this.monitoringConfigs = new Map();
    this.cveAlerts = new Map();
    this.monitoringRuns = new Map();
    
    // Add some sample CVE data for demonstration
    this.initializeSampleData();
  }

  private initializeSampleData() {
    // Sample data removed - will be populated with real CVEs from NIST scan
  }

  async getUser(id: string): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(
      (user) => user.username === username,
    );
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = randomUUID();
    const user: User = { ...insertUser, id };
    this.users.set(id, user);
    return user;
  }

  async getCve(id: string): Promise<Cve | undefined> {
    return this.cves.get(id);
  }

  async getCveByCveId(cveId: string): Promise<Cve | undefined> {
    return Array.from(this.cves.values()).find(cve => cve.cveId === cveId);
  }

  async getCveByIds(ids: string[]): Promise<Cve[]> {
    return ids.map(id => this.cves.get(id)).filter(Boolean) as Cve[];
  }

  async getCves(filters?: CveFilters): Promise<Cve[]> {
    let results = Array.from(this.cves.values());

    if (filters) {
      if (filters.severity && filters.severity.length > 0) {
        results = results.filter(cve => filters.severity!.includes(cve.severity));
      }
      
      if (filters.technology && filters.technology.length > 0) {
        results = results.filter(cve => 
          filters.technology!.some(tech => 
            cve.technology?.toLowerCase().includes(tech.toLowerCase()) ||
            cve.affectedProduct?.toLowerCase().includes(tech.toLowerCase())
          )
        );
      }
      
      if (filters.hasPublicPoc !== undefined) {
        results = results.filter(cve => cve.hasPublicPoc === filters.hasPublicPoc);
      }
      
      if (filters.isDockerDeployable !== undefined) {
        results = results.filter(cve => cve.isDockerDeployable === filters.isDockerDeployable);
      }
      
      if (filters.isCurlTestable !== undefined) {
        results = results.filter(cve => cve.isCurlTestable === filters.isCurlTestable);
      }
      
      if (filters.minCvssScore !== undefined) {
        results = results.filter(cve => cve.cvssScore && cve.cvssScore >= filters.minCvssScore!);
      }
      
      if (filters.maxCvssScore !== undefined) {
        results = results.filter(cve => cve.cvssScore && cve.cvssScore <= filters.maxCvssScore!);
      }
      
      if (filters.search) {
        const searchLower = filters.search.toLowerCase();
        results = results.filter(cve => 
          cve.cveId.toLowerCase().includes(searchLower) ||
          cve.description.toLowerCase().includes(searchLower) ||
          cve.technology?.toLowerCase().includes(searchLower) ||
          cve.affectedProduct?.toLowerCase().includes(searchLower)
        );
      }
      
      if (filters.status && filters.status.length > 0) {
        results = results.filter(cve => filters.status!.includes(cve.status || 'new'));
      }
      
      if (filters.listCategory && filters.listCategory.length > 0) {
        results = results.filter(cve => 
          cve.listCategory && filters.listCategory!.includes(cve.listCategory)
        );
      }
      
      if (filters.isPriority !== undefined) {
        results = results.filter(cve => cve.isPriority === filters.isPriority);
      }
      
      if (filters.hideDone) {
        results = results.filter(cve => cve.status !== 'done');
      }
      
      if (filters.offset) {
        results = results.slice(filters.offset);
      }
      
      if (filters.limit) {
        results = results.slice(0, filters.limit);
      }
    }

    return results.sort((a, b) => new Date(b.publishedDate).getTime() - new Date(a.publishedDate).getTime());
  }

  async createCve(insertCve: InsertCve): Promise<Cve> {
    const id = randomUUID();
    const now = new Date();
    const cve: Cve = { 
      ...insertCve,
      id,
      createdAt: now,
      updatedAt: now,
      status: insertCve.status ?? "new",
      statusUpdatedAt: now,
      listCategory: insertCve.listCategory ?? null,
      isPriority: insertCve.isPriority ?? null,
      userNotes: insertCve.userNotes ?? null,
      cvssScore: insertCve.cvssScore ?? null,
      cvssVector: insertCve.cvssVector ?? null,
      affectedProduct: insertCve.affectedProduct ?? null,
      affectedVersions: insertCve.affectedVersions ?? null,
      attackVector: insertCve.attackVector ?? null,
      technology: insertCve.technology ?? null,
      category: insertCve.category ?? null,
      pocUrls: insertCve.pocUrls ?? null,
      exploitabilityScore: insertCve.exploitabilityScore ?? null,
      labSuitabilityScore: insertCve.labSuitabilityScore ?? null,
      scoringBreakdown: insertCve.scoringBreakdown ?? null,
      hasPublicPoc: insertCve.hasPublicPoc ?? null,
      isDockerDeployable: insertCve.isDockerDeployable ?? null,
      isCurlTestable: insertCve.isCurlTestable ?? null,
      dockerInfo: insertCve.dockerInfo ?? null,
      fingerprintInfo: insertCve.fingerprintInfo ?? null,
      discoveryMetadata: insertCve.discoveryMetadata ?? null
    };
    this.cves.set(id, cve);
    return cve;
  }

  async updateCve(id: string, updates: Partial<InsertCve>): Promise<Cve | undefined> {
    const existing = this.cves.get(id);
    if (!existing) return undefined;
    
    const updated: Cve = { 
      ...existing, 
      ...updates, 
      updatedAt: new Date() 
    };
    this.cves.set(id, updated);
    return updated;
  }

  async createOrUpdateCve(cve: InsertCve): Promise<{ cve: Cve; isNew: boolean; changes?: string[] }> {
    // Import here to avoid circular dependency
    const { CveDuplicateDetectionService } = await import('./services/cveDuplicateDetectionService');
    
    const existing = await this.getCveByCveId(cve.cveId);
    
    if (!existing) {
      // Create new CVE
      const newCve = await this.createCve(cve);
      return { cve: newCve, isNew: true };
    }
    
    // Check if we should update the existing CVE
    if (!CveDuplicateDetectionService.shouldUpdateCve(existing)) {
      return { cve: existing, isNew: false, changes: [] };
    }
    
    // Merge the CVE data
    const mergeResult = await CveDuplicateDetectionService.checkAndMergeCve(
      cve, [existing]
    );
    
    if (mergeResult.isDuplicate && mergeResult.mergedCve && mergeResult.changes?.length) {
      const updated = await this.updateCve(existing.id, mergeResult.mergedCve);
      return { 
        cve: updated!, 
        isNew: false, 
        changes: mergeResult.changes 
      };
    }
    
    return { cve: existing, isNew: false, changes: [] };
  }

  async deleteCve(id: string): Promise<boolean> {
    return this.cves.delete(id);
  }

  async getCveScan(id: string): Promise<CveScan | undefined> {
    return this.cveScans.get(id);
  }

  async getCveScans(): Promise<CveScan[]> {
    return Array.from(this.cveScans.values())
      .sort((a, b) => {
        const aTime = a.startedAt ? new Date(a.startedAt).getTime() : 0;
        const bTime = b.startedAt ? new Date(b.startedAt).getTime() : 0;
        return bTime - aTime;
      });
  }

  async createCveScan(insertScan: InsertCveScan): Promise<CveScan> {
    const id = randomUUID();
    const now = new Date();
    const scan: CveScan = { 
      timeframeYears: insertScan.timeframeYears || 3,
      status: insertScan.status || 'pending',
      totalFound: insertScan.totalFound ?? 0,
      labDeployable: insertScan.labDeployable ?? 0,
      withPoc: insertScan.withPoc ?? 0,
      criticalSeverity: insertScan.criticalSeverity ?? 0,
      
      // Enhanced enrichment tracking fields
      fingerprintingCompleted: insertScan.fingerprintingCompleted ?? 0,
      dockerAnalysisCompleted: insertScan.dockerAnalysisCompleted ?? 0,
      multiSourceDiscoveryCompleted: insertScan.multiSourceDiscoveryCompleted ?? 0,
      totalSourcesDiscovered: insertScan.totalSourcesDiscovered ?? 0,
      enrichmentFailures: insertScan.enrichmentFailures ?? 0,
      
      currentPhase: insertScan.currentPhase || 'initializing',
      enrichmentMetrics: insertScan.enrichmentMetrics || null,
      errorMessage: insertScan.errorMessage ?? null,
      id,
      startedAt: now,
      completedAt: null
    };
    this.cveScans.set(id, scan);
    return scan;
  }

  async updateCveScan(id: string, updates: Partial<InsertCveScan>): Promise<CveScan | undefined> {
    const existing = this.cveScans.get(id);
    if (!existing) return undefined;
    
    const updated: CveScan = { 
      ...existing, 
      ...updates,
      completedAt: updates.status === 'completed' || updates.status === 'failed' ? new Date() : existing.completedAt
    };
    this.cveScans.set(id, updated);
    return updated;
  }

  async getCveStats(): Promise<CveStats> {
    const allCves = Array.from(this.cves.values());
    
    return {
      totalCves: allCves.length,
      deployable: allCves.filter(cve => cve.isDockerDeployable).length,
      withPoc: allCves.filter(cve => cve.hasPublicPoc).length,
      critical: allCves.filter(cve => cve.severity === 'CRITICAL').length
    };
  }

  // Monitoring Configuration Methods
  async getMonitoringConfig(): Promise<MonitoringConfig | undefined> {
    const configs = Array.from(this.monitoringConfigs.values());
    return configs[0]; // Return the first/default config
  }

  async createMonitoringConfig(config: InsertMonitoringConfig): Promise<MonitoringConfig> {
    const id = randomUUID();
    const newConfig: MonitoringConfig = {
      id,
      isEnabled: config.isEnabled ?? null,
      scanInterval: config.scanInterval ?? 'daily',
      minSeverity: config.minSeverity ?? 'HIGH',
      minCvssScore: config.minCvssScore ?? null,
      technologiesOfInterest: config.technologiesOfInterest ?? null,
      alertMethods: config.alertMethods ?? null,
      webhookUrl: config.webhookUrl ?? null,
      emailRecipients: config.emailRecipients ?? null,
      lastUpdateAt: new Date()
    };
    this.monitoringConfigs.set(id, newConfig);
    return newConfig;
  }

  async updateMonitoringConfig(id: string, updates: Partial<InsertMonitoringConfig>): Promise<MonitoringConfig | undefined> {
    const config = this.monitoringConfigs.get(id);
    if (!config) return undefined;
    
    const updatedConfig = { ...config, ...updates, lastUpdateAt: new Date() };
    this.monitoringConfigs.set(id, updatedConfig);
    return updatedConfig;
  }

  // CVE Alert Methods
  async getCveAlert(id: string): Promise<CveAlert | undefined> {
    return this.cveAlerts.get(id);
  }

  async getCveAlerts(filters?: { isRead?: boolean; isDismissed?: boolean; severity?: string[] }): Promise<CveAlert[]> {
    let alerts = Array.from(this.cveAlerts.values());
    
    if (filters?.isRead !== undefined) {
      alerts = alerts.filter(alert => alert.isRead === filters.isRead);
    }
    if (filters?.isDismissed !== undefined) {
      alerts = alerts.filter(alert => alert.isDismissed === filters.isDismissed);
    }
    if (filters?.severity?.length) {
      alerts = alerts.filter(alert => filters.severity!.includes(alert.severity));
    }
    
    return alerts.sort((a, b) => {
      const aTime = a.detectedAt ? new Date(a.detectedAt).getTime() : 0;
      const bTime = b.detectedAt ? new Date(b.detectedAt).getTime() : 0;
      return bTime - aTime;
    });
  }

  async createCveAlert(alert: InsertCveAlert): Promise<CveAlert> {
    const id = randomUUID();
    const newAlert: CveAlert = {
      id,
      cveId: alert.cveId,
      alertType: alert.alertType ?? 'new_cve',
      severity: alert.severity,
      description: alert.description,
      pocUrls: alert.pocUrls ?? null,
      isDockerDeployable: alert.isDockerDeployable ?? null,
      labSuitabilityScore: alert.labSuitabilityScore ?? null,
      isRead: alert.isRead ?? null,
      isDismissed: alert.isDismissed ?? null,
      metadata: alert.metadata ?? null,
      detectedAt: new Date()
    };
    this.cveAlerts.set(id, newAlert);
    return newAlert;
  }

  async updateCveAlert(id: string, updates: Partial<InsertCveAlert>): Promise<CveAlert | undefined> {
    const alert = this.cveAlerts.get(id);
    if (!alert) return undefined;
    
    const updatedAlert = { ...alert, ...updates };
    this.cveAlerts.set(id, updatedAlert);
    return updatedAlert;
  }

  async markAlertAsRead(id: string): Promise<boolean> {
    const alert = this.cveAlerts.get(id);
    if (!alert) return false;
    
    alert.isRead = true;
    this.cveAlerts.set(id, alert);
    return true;
  }

  async dismissAlert(id: string): Promise<boolean> {
    const alert = this.cveAlerts.get(id);
    if (!alert) return false;
    
    alert.isDismissed = true;
    this.cveAlerts.set(id, alert);
    return true;
  }

  async getUnreadAlertsCount(): Promise<number> {
    const alerts = Array.from(this.cveAlerts.values());
    return alerts.filter(alert => !alert.isRead && !alert.isDismissed).length;
  }

  // Monitoring Run Methods
  async getMonitoringRun(id: string): Promise<MonitoringRun | undefined> {
    return this.monitoringRuns.get(id);
  }

  async getMonitoringRuns(limit?: number): Promise<MonitoringRun[]> {
    let runs = Array.from(this.monitoringRuns.values());
    runs = runs.sort((a, b) => {
      const aTime = a.startedAt ? new Date(a.startedAt).getTime() : 0;
      const bTime = b.startedAt ? new Date(b.startedAt).getTime() : 0;
      return bTime - aTime;
    });
    
    if (limit) {
      runs = runs.slice(0, limit);
    }
    
    return runs;
  }

  async createMonitoringRun(run: InsertMonitoringRun): Promise<MonitoringRun> {
    const id = randomUUID();
    const newRun: MonitoringRun = {
      id,
      runType: run.runType ?? 'scheduled',
      status: run.status ?? 'running',
      newCvesFound: run.newCvesFound ?? null,
      alertsGenerated: run.alertsGenerated ?? null,
      errorMessage: run.errorMessage ?? null,
      lastProcessedDate: run.lastProcessedDate ?? null,
      startedAt: new Date(),
      completedAt: null
    };
    this.monitoringRuns.set(id, newRun);
    return newRun;
  }

  async updateMonitoringRun(id: string, updates: Partial<InsertMonitoringRun>): Promise<MonitoringRun | undefined> {
    const run = this.monitoringRuns.get(id);
    if (!run) return undefined;
    
    const updatedRun = { ...run, ...updates };
    if (updates.status === 'completed' || updates.status === 'failed') {
      updatedRun.completedAt = new Date();
    }
    
    this.monitoringRuns.set(id, updatedRun);
    return updatedRun;
  }

  async getLastSuccessfulMonitoringRun(): Promise<MonitoringRun | undefined> {
    const runs = Array.from(this.monitoringRuns.values());
    const completedRuns = runs
      .filter(run => run.status === 'completed')
      .sort((a, b) => {
        const aTime = a.startedAt ? new Date(a.startedAt).getTime() : 0;
        const bTime = b.startedAt ? new Date(b.startedAt).getTime() : 0;
        return bTime - aTime;
      });
    
    return completedRuns[0];
  }

  // CVE List Management Methods
  async updateCveStatus(id: string, updates: CveStatusUpdate): Promise<Cve | undefined> {
    const existing = this.cves.get(id);
    if (!existing) return undefined;
    
    const updated: Cve = { 
      ...existing, 
      ...updates, 
      statusUpdatedAt: new Date(),
      updatedAt: new Date() 
    };
    this.cves.set(id, updated);
    return updated;
  }

  async updateCveStatusBulk(ids: string[], updates: CveStatusUpdate): Promise<Cve[]> {
    const updatedCves: Cve[] = [];
    
    for (const id of ids) {
      const updated = await this.updateCveStatus(id, updates);
      if (updated) {
        updatedCves.push(updated);
      }
    }
    
    return updatedCves;
  }

  async getCveLists(): Promise<CveListSummary[]> {
    const allCves = Array.from(this.cves.values());
    const listCounts = new Map<string, number>();
    
    allCves.forEach(cve => {
      if (cve.listCategory) {
        const currentCount = listCounts.get(cve.listCategory) || 0;
        listCounts.set(cve.listCategory, currentCount + 1);
      }
    });
    
    return Array.from(listCounts.entries()).map(([listCategory, count]) => ({
      listCategory,
      count
    })).sort((a, b) => a.listCategory.localeCompare(b.listCategory));
  }

  async getCveStatusStats(): Promise<CveStatusStats> {
    const allCves = Array.from(this.cves.values());
    
    const stats = {
      new: 0,
      inProgress: 0,
      done: 0,
      unlisted: 0,
      total: allCves.length
    };
    
    allCves.forEach(cve => {
      const status = cve.status || 'new';
      switch (status) {
        case 'new':
          stats.new++;
          break;
        case 'in_progress':
          stats.inProgress++;
          break;
        case 'done':
          stats.done++;
          break;
        case 'unlisted':
          stats.unlisted++;
          break;
        default:
          stats.new++; // Default unknown statuses to 'new'
          break;
      }
    });
    
    return stats;
  }

  async getPriorityCves(): Promise<Cve[]> {
    const allCves = Array.from(this.cves.values());
    return allCves
      .filter(cve => cve.isPriority === true)
      .sort((a, b) => {
        const aDate = a.statusUpdatedAt || a.updatedAt || new Date(0);
        const bDate = b.statusUpdatedAt || b.updatedAt || new Date(0);
        return new Date(bDate).getTime() - new Date(aDate).getTime();
      });
  }
}

export const storage = new MemStorage();
