import { eq, and, desc, gte, inArray, sql, or, like } from 'drizzle-orm';
import { db } from './db';
import * as schema from '../shared/schema';
import type {
  User, InsertUser,
  Cve, InsertCve,
  CveScan, InsertCveScan,
  MonitoringConfig, InsertMonitoringConfig,
  CveAlert, InsertCveAlert,
  MonitoringRun, InsertMonitoringRun,
  AppConfig, InsertAppConfig
} from '../shared/schema';
import type { IStorage, CveFilters, CveStats, CveStatusUpdate, CveListSummary, CveStatusStats } from './storage';

/**
 * Database-backed storage implementation using Drizzle ORM
 * Implements the same IStorage interface as MemStorage for easy migration
 */
export class DbStorage implements IStorage {

  // ============================================
  // User Methods
  // ============================================

  async getUser(id: string): Promise<User | undefined> {
    const result = await db
      .select()
      .from(schema.users)
      .where(eq(schema.users.id, id))
      .limit(1);
    return result[0];
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const result = await db
      .select()
      .from(schema.users)
      .where(eq(schema.users.username, username))
      .limit(1);
    return result[0];
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const result = await db
      .insert(schema.users)
      .values(insertUser)
      .returning();
    return result[0];
  }

  // ============================================
  // CVE Methods
  // ============================================

  async getCve(id: string): Promise<Cve | undefined> {
    const result = await db
      .select()
      .from(schema.cves)
      .where(eq(schema.cves.id, id))
      .limit(1);
    return result[0];
  }

  async getCveByCveId(cveId: string): Promise<Cve | undefined> {
    const result = await db
      .select()
      .from(schema.cves)
      .where(eq(schema.cves.cveId, cveId))
      .limit(1);
    return result[0];
  }

  async getCveByIds(ids: string[]): Promise<Cve[]> {
    if (ids.length === 0) return [];

    return await db
      .select()
      .from(schema.cves)
      .where(inArray(schema.cves.id, ids));
  }

  async getCves(filters?: CveFilters): Promise<Cve[]> {
    let query = db.select().from(schema.cves);
    const conditions = [];

    if (filters) {
      // Severity filter
      if (filters.severity && filters.severity.length > 0) {
        conditions.push(inArray(schema.cves.severity, filters.severity));
      }

      // Technology filter
      if (filters.technology && filters.technology.length > 0) {
        const techConditions = filters.technology.map(tech =>
          or(
            like(schema.cves.technology, `%${tech}%`),
            like(schema.cves.affectedProduct, `%${tech}%`)
          )
        );
        conditions.push(or(...techConditions));
      }

      // Boolean filters
      if (filters.hasPublicPoc !== undefined) {
        conditions.push(eq(schema.cves.hasPublicPoc, filters.hasPublicPoc));
      }

      if (filters.isDockerDeployable !== undefined) {
        conditions.push(eq(schema.cves.isDockerDeployable, filters.isDockerDeployable));
      }

      if (filters.isCurlTestable !== undefined) {
        conditions.push(eq(schema.cves.isCurlTestable, filters.isCurlTestable));
      }

      // CVSS Score range
      if (filters.minCvssScore !== undefined) {
        conditions.push(gte(schema.cves.cvssScore, filters.minCvssScore));
      }

      if (filters.maxCvssScore !== undefined) {
        conditions.push(sql`${schema.cves.cvssScore} <= ${filters.maxCvssScore}`);
      }

      // Search filter
      if (filters.search) {
        const searchPattern = `%${filters.search}%`;
        conditions.push(
          or(
            like(schema.cves.cveId, searchPattern),
            like(schema.cves.description, searchPattern),
            like(schema.cves.technology, searchPattern),
            like(schema.cves.affectedProduct, searchPattern)
          )
        );
      }

      // Status filter
      if (filters.status && filters.status.length > 0) {
        conditions.push(inArray(schema.cves.status, filters.status));
      }

      // List category filter
      if (filters.listCategory && filters.listCategory.length > 0) {
        conditions.push(inArray(schema.cves.listCategory, filters.listCategory));
      }

      // Priority filter
      if (filters.isPriority !== undefined) {
        conditions.push(eq(schema.cves.isPriority, filters.isPriority));
      }

      // Hide done filter
      if (filters.hideDone) {
        conditions.push(sql`${schema.cves.status} != 'done'`);
      }
    }

    // Apply all conditions
    if (conditions.length > 0) {
      query = query.where(and(...conditions)) as typeof query;
    }

    // Order by published date descending
    query = query.orderBy(desc(schema.cves.publishedDate)) as typeof query;

    // Apply pagination
    if (filters?.offset) {
      query = query.offset(filters.offset) as typeof query;
    }

    if (filters?.limit) {
      query = query.limit(filters.limit) as typeof query;
    }

    return await query;
  }

  async createCve(insertCve: InsertCve): Promise<Cve> {
    const result = await db
      .insert(schema.cves)
      .values(insertCve)
      .returning();
    return result[0];
  }

  async updateCve(id: string, updates: Partial<InsertCve>): Promise<Cve | undefined> {
    const result = await db
      .update(schema.cves)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(schema.cves.id, id))
      .returning();
    return result[0];
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
    const result = await db
      .delete(schema.cves)
      .where(eq(schema.cves.id, id))
      .returning();
    return result.length > 0;
  }

  // ============================================
  // CVE Scan Methods
  // ============================================

  async getCveScan(id: string): Promise<CveScan | undefined> {
    const result = await db
      .select()
      .from(schema.cveScans)
      .where(eq(schema.cveScans.id, id))
      .limit(1);
    return result[0];
  }

  async getCveScans(): Promise<CveScan[]> {
    return await db
      .select()
      .from(schema.cveScans)
      .orderBy(desc(schema.cveScans.startedAt));
  }

  async createCveScan(insertScan: InsertCveScan): Promise<CveScan> {
    const result = await db
      .insert(schema.cveScans)
      .values(insertScan)
      .returning();
    return result[0];
  }

  async updateCveScan(id: string, updates: Partial<InsertCveScan>): Promise<CveScan | undefined> {
    const updateData: any = { ...updates };

    if (updates.status === 'completed' || updates.status === 'failed') {
      updateData.completedAt = new Date();
    }

    const result = await db
      .update(schema.cveScans)
      .set(updateData)
      .where(eq(schema.cveScans.id, id))
      .returning();
    return result[0];
  }

  // ============================================
  // Monitoring Config Methods
  // ============================================

  async getMonitoringConfig(): Promise<MonitoringConfig | undefined> {
    const result = await db
      .select()
      .from(schema.monitoringConfig)
      .limit(1);
    return result[0];
  }

  async createMonitoringConfig(config: InsertMonitoringConfig): Promise<MonitoringConfig> {
    const result = await db
      .insert(schema.monitoringConfig)
      .values(config)
      .returning();
    return result[0];
  }

  async updateMonitoringConfig(id: string, updates: Partial<InsertMonitoringConfig>): Promise<MonitoringConfig | undefined> {
    const result = await db
      .update(schema.monitoringConfig)
      .set({ ...updates, lastUpdateAt: new Date() })
      .where(eq(schema.monitoringConfig.id, id))
      .returning();
    return result[0];
  }

  // ============================================
  // CVE Alert Methods
  // ============================================

  async getCveAlert(id: string): Promise<CveAlert | undefined> {
    const result = await db
      .select()
      .from(schema.cveAlerts)
      .where(eq(schema.cveAlerts.id, id))
      .limit(1);
    return result[0];
  }

  async getCveAlerts(filters?: { isRead?: boolean; isDismissed?: boolean; severity?: string[] }): Promise<CveAlert[]> {
    let query = db.select().from(schema.cveAlerts);
    const conditions = [];

    if (filters) {
      if (filters.isRead !== undefined) {
        conditions.push(eq(schema.cveAlerts.isRead, filters.isRead));
      }
      if (filters.isDismissed !== undefined) {
        conditions.push(eq(schema.cveAlerts.isDismissed, filters.isDismissed));
      }
      if (filters.severity && filters.severity.length > 0) {
        conditions.push(inArray(schema.cveAlerts.severity, filters.severity));
      }
    }

    if (conditions.length > 0) {
      query = query.where(and(...conditions)) as typeof query;
    }

    return await query.orderBy(desc(schema.cveAlerts.detectedAt));
  }

  async createCveAlert(alert: InsertCveAlert): Promise<CveAlert> {
    const result = await db
      .insert(schema.cveAlerts)
      .values(alert)
      .returning();
    return result[0];
  }

  async updateCveAlert(id: string, updates: Partial<InsertCveAlert>): Promise<CveAlert | undefined> {
    const result = await db
      .update(schema.cveAlerts)
      .set(updates)
      .where(eq(schema.cveAlerts.id, id))
      .returning();
    return result[0];
  }

  async markAlertAsRead(id: string): Promise<boolean> {
    const result = await db
      .update(schema.cveAlerts)
      .set({ isRead: true })
      .where(eq(schema.cveAlerts.id, id))
      .returning();
    return result.length > 0;
  }

  async dismissAlert(id: string): Promise<boolean> {
    const result = await db
      .update(schema.cveAlerts)
      .set({ isDismissed: true })
      .where(eq(schema.cveAlerts.id, id))
      .returning();
    return result.length > 0;
  }

  async getUnreadAlertsCount(): Promise<number> {
    const result = await db
      .select({ count: sql<number>`cast(count(*) as integer)` })
      .from(schema.cveAlerts)
      .where(
        and(
          eq(schema.cveAlerts.isRead, false),
          eq(schema.cveAlerts.isDismissed, false)
        )
      );
    return result[0]?.count || 0;
  }

  // ============================================
  // Monitoring Run Methods
  // ============================================

  async getMonitoringRun(id: string): Promise<MonitoringRun | undefined> {
    const result = await db
      .select()
      .from(schema.monitoringRuns)
      .where(eq(schema.monitoringRuns.id, id))
      .limit(1);
    return result[0];
  }

  async getMonitoringRuns(limit?: number): Promise<MonitoringRun[]> {
    let query = db
      .select()
      .from(schema.monitoringRuns)
      .orderBy(desc(schema.monitoringRuns.startedAt));

    if (limit) {
      query = query.limit(limit) as typeof query;
    }

    return await query;
  }

  async createMonitoringRun(run: InsertMonitoringRun): Promise<MonitoringRun> {
    const result = await db
      .insert(schema.monitoringRuns)
      .values(run)
      .returning();
    return result[0];
  }

  async updateMonitoringRun(id: string, updates: Partial<InsertMonitoringRun>): Promise<MonitoringRun | undefined> {
    const updateData: any = { ...updates };

    if (updates.status === 'completed' || updates.status === 'failed') {
      updateData.completedAt = new Date();
    }

    const result = await db
      .update(schema.monitoringRuns)
      .set(updateData)
      .where(eq(schema.monitoringRuns.id, id))
      .returning();
    return result[0];
  }

  async getLastSuccessfulMonitoringRun(): Promise<MonitoringRun | undefined> {
    const result = await db
      .select()
      .from(schema.monitoringRuns)
      .where(eq(schema.monitoringRuns.status, 'completed'))
      .orderBy(desc(schema.monitoringRuns.startedAt))
      .limit(1);
    return result[0];
  }

  // ============================================
  // CVE Statistics Methods
  // ============================================

  async getCveStats(): Promise<CveStats> {
    const result = await db
      .select({
        totalCves: sql<number>`cast(count(*) as integer)`,
        deployable: sql<number>`cast(sum(case when ${schema.cves.isDockerDeployable} then 1 else 0 end) as integer)`,
        withPoc: sql<number>`cast(sum(case when ${schema.cves.hasPublicPoc} then 1 else 0 end) as integer)`,
        critical: sql<number>`cast(sum(case when ${schema.cves.severity} = 'CRITICAL' then 1 else 0 end) as integer)`,
      })
      .from(schema.cves);

    return {
      totalCves: result[0]?.totalCves || 0,
      deployable: result[0]?.deployable || 0,
      withPoc: result[0]?.withPoc || 0,
      critical: result[0]?.critical || 0,
    };
  }

  // ============================================
  // CVE List Management Methods
  // ============================================

  async updateCveStatus(id: string, updates: CveStatusUpdate): Promise<Cve | undefined> {
    const result = await db
      .update(schema.cves)
      .set({
        ...updates,
        statusUpdatedAt: new Date(),
        updatedAt: new Date()
      })
      .where(eq(schema.cves.id, id))
      .returning();
    return result[0];
  }

  async updateCveStatusBulk(ids: string[], updates: CveStatusUpdate): Promise<Cve[]> {
    if (ids.length === 0) return [];

    const result = await db
      .update(schema.cves)
      .set({
        ...updates,
        statusUpdatedAt: new Date(),
        updatedAt: new Date()
      })
      .where(inArray(schema.cves.id, ids))
      .returning();
    return result;
  }

  async getCveLists(): Promise<CveListSummary[]> {
    const result = await db
      .select({
        listCategory: schema.cves.listCategory,
        count: sql<number>`cast(count(*) as integer)`,
      })
      .from(schema.cves)
      .where(sql`${schema.cves.listCategory} IS NOT NULL`)
      .groupBy(schema.cves.listCategory)
      .orderBy(schema.cves.listCategory);

    return result.map(row => ({
      listCategory: row.listCategory!,
      count: row.count,
    }));
  }

  async getCveStatusStats(): Promise<CveStatusStats> {
    const result = await db
      .select({
        status: schema.cves.status,
        count: sql<number>`cast(count(*) as integer)`,
      })
      .from(schema.cves)
      .groupBy(schema.cves.status);

    const stats: CveStatusStats = {
      new: 0,
      inProgress: 0,
      done: 0,
      unlisted: 0,
      total: 0,
    };

    result.forEach(row => {
      const count = row.count;
      stats.total += count;

      switch (row.status) {
        case 'new':
          stats.new = count;
          break;
        case 'in_progress':
          stats.inProgress = count;
          break;
        case 'done':
          stats.done = count;
          break;
        case 'unlisted':
          stats.unlisted = count;
          break;
        default:
          stats.new += count; // Default unknown statuses to 'new'
          break;
      }
    });

    return stats;
  }

  async getPriorityCves(): Promise<Cve[]> {
    return await db
      .select()
      .from(schema.cves)
      .where(eq(schema.cves.isPriority, true))
      .orderBy(desc(schema.cves.statusUpdatedAt));
  }

  // ============================================
  // App Configuration Methods
  // ============================================

  async getAppConfig(): Promise<AppConfig | undefined> {
    const result = await db
      .select()
      .from(schema.appConfigs)
      .limit(1);
    return result[0];
  }

  async createAppConfig(insertConfig: InsertAppConfig): Promise<AppConfig> {
    const result = await db
      .insert(schema.appConfigs)
      .values(insertConfig)
      .returning();
    return result[0];
  }

  async updateAppConfig(id: string, updates: Partial<InsertAppConfig>): Promise<AppConfig | undefined> {
    const result = await db
      .update(schema.appConfigs)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(schema.appConfigs.id, id))
      .returning();
    return result[0];
  }

  async createOrUpdateAppConfig(config: InsertAppConfig): Promise<AppConfig> {
    const existing = await this.getAppConfig();

    if (existing) {
      const updated = await this.updateAppConfig(existing.id, config);
      return updated!;
    } else {
      return await this.createAppConfig(config);
    }
  }
}

// Export singleton instance
export const dbStorage = new DbStorage();
