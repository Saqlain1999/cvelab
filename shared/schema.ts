import { sql } from "drizzle-orm";
import { pgTable, text, varchar, timestamp, real, boolean, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

export const cves = pgTable("cves", {
  id: varchar("id").primaryKey(),
  cveId: text("cve_id").notNull().unique(),
  description: text("description").notNull(),
  publishedDate: timestamp("published_date").notNull(),
  lastModifiedDate: timestamp("last_modified_date").notNull(),
  cvssScore: real("cvss_score"),
  cvssVector: text("cvss_vector"),
  severity: text("severity").notNull(),
  affectedProduct: text("affected_product"),
  affectedVersions: text("affected_versions").array(),
  attackVector: text("attack_vector"),
  technology: text("technology"),
  category: text("category"),
  hasPublicPoc: boolean("has_public_poc").default(false),
  isDockerDeployable: boolean("is_docker_deployable").default(false),
  isCurlTestable: boolean("is_curl_testable").default(false),
  pocUrls: text("poc_urls").array(),
  dockerInfo: jsonb("docker_info"),
  fingerprintInfo: jsonb("fingerprint_info"),
  exploitabilityScore: real("exploitability_score"),
  labSuitabilityScore: real("lab_suitability_score"),
  scoringBreakdown: jsonb("scoring_breakdown"),
  discoveryMetadata: jsonb("discovery_metadata"),
  
  // Multi-Source CVE Discovery
  sources: text("sources").array().notNull().default(sql`'{}'`), // List of sources that provided this CVE (nist, cvedetails, vulners, etc.)
  primarySource: text("primary_source").notNull().default("nist"), // The source considered most authoritative for this CVE
  sourceMetadata: jsonb("source_metadata"), // Metadata from each source with source attribution
  sourceReliabilityScore: real("source_reliability_score").default(1.0), // Weighted score based on source reliability
  deduplicationFingerprint: text("deduplication_fingerprint"), // Hash for deduplication across sources
  duplicateIds: text("duplicate_ids").array(), // List of CVE IDs that are duplicates from other sources
  crossSourceValidation: jsonb("cross_source_validation"), // Validation status across sources
  lastSourceSync: timestamp("last_source_sync").default(sql`now()`), // Last time sources were synchronized
  sourceConflicts: jsonb("source_conflicts"), // Conflicts detected between sources
  
  // CVE Status Management
  status: varchar("status", { length: 20 }).notNull().default("new"), // "new", "in_progress", "done", "unlisted"
  listCategory: varchar("list_category", { length: 50 }), // custom list/category name
  isPriority: boolean("is_priority").default(false), // flagged as priority/interesting
  userNotes: text("user_notes"), // personal notes about the CVE
  statusUpdatedAt: timestamp("status_updated_at").defaultNow(),
  
  createdAt: timestamp("created_at").default(sql`now()`),
  updatedAt: timestamp("updated_at").default(sql`now()`),
});

export const cveScans = pgTable("cve_scans", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  timeframeYears: real("timeframe_years").notNull().default(3),
  startDate: text("start_date"), // Optional date range start (YYYY-MM-DD format)
  endDate: text("end_date"), // Optional date range end (YYYY-MM-DD format)
  totalFound: real("total_found").default(0),
  labDeployable: real("lab_deployable").default(0),
  withPoc: real("with_poc").default(0),
  criticalSeverity: real("critical_severity").default(0),
  
  // Enhanced enrichment tracking
  fingerprintingCompleted: real("fingerprinting_completed").default(0),
  dockerAnalysisCompleted: real("docker_analysis_completed").default(0),
  multiSourceDiscoveryCompleted: real("multi_source_discovery_completed").default(0),
  totalSourcesDiscovered: real("total_sources_discovered").default(0),
  enrichmentFailures: real("enrichment_failures").default(0),
  
  status: text("status").notNull().default("pending"),
  currentPhase: text("current_phase").default("initializing"), // 'initializing', 'fetching', 'enriching', 'finalizing', 'completed'
  enrichmentMetrics: jsonb("enrichment_metrics"), // Detailed breakdown of enrichment results
  startedAt: timestamp("started_at").default(sql`now()`),
  completedAt: timestamp("completed_at"),
  errorMessage: text("error_message"),
});

export const monitoringConfig = pgTable("monitoring_config", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  isEnabled: boolean("is_enabled").default(true),
  scanInterval: text("scan_interval").notNull().default("daily"), // 'hourly', 'daily', 'weekly'
  minSeverity: text("min_severity").notNull().default("HIGH"), // 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
  minCvssScore: real("min_cvss_score").default(7.0),
  technologiesOfInterest: text("technologies_of_interest").array(),
  alertMethods: text("alert_methods").array().default(sql`'{email, dashboard}'`), // 'email', 'webhook', 'dashboard'
  webhookUrl: text("webhook_url"),
  emailRecipients: text("email_recipients").array(),
  lastUpdateAt: timestamp("last_update_at").default(sql`now()`),
});

export const cveAlerts = pgTable("cve_alerts", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  cveId: text("cve_id").notNull(),
  alertType: text("alert_type").notNull().default("new_cve"), // 'new_cve', 'poc_found', 'docker_available'
  severity: text("severity").notNull(),
  description: text("description").notNull(),
  pocUrls: text("poc_urls").array(),
  isDockerDeployable: boolean("is_docker_deployable").default(false),
  labSuitabilityScore: real("lab_suitability_score"),
  isRead: boolean("is_read").default(false),
  isDismissed: boolean("is_dismissed").default(false),
  detectedAt: timestamp("detected_at").default(sql`now()`),
  metadata: jsonb("metadata"),
});

export const monitoringRuns = pgTable("monitoring_runs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  runType: text("run_type").notNull().default("scheduled"), // 'scheduled', 'manual'
  status: text("status").notNull().default("running"), // 'running', 'completed', 'failed'
  newCvesFound: real("new_cves_found").default(0),
  alertsGenerated: real("alerts_generated").default(0),
  startedAt: timestamp("started_at").default(sql`now()`),
  completedAt: timestamp("completed_at"),
  errorMessage: text("error_message"),
  lastProcessedDate: timestamp("last_processed_date"),
});

// Multi-Source CVE Discovery Configuration
export const cveSourceConfigs = pgTable("cve_source_configs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  sourceName: varchar("source_name", { length: 50 }).notNull().unique(), // 'nist', 'cvedetails', 'vulners', 'mitre', etc.
  displayName: text("display_name").notNull(), // Human-readable source name
  baseUrl: text("base_url").notNull(), // Base URL for the source API
  isEnabled: boolean("is_enabled").default(true),
  reliabilityScore: real("reliability_score").default(1.0), // 0.0 to 1.0, weight for deduplication
  priority: real("priority").default(1), // Processing priority (higher = processed first)
  rateLimitPerMinute: real("rate_limit_per_minute").default(60),
  rateLimitPerHour: real("rate_limit_per_hour").default(1000),
  timeout: real("timeout").default(30), // Request timeout in seconds
  retryAttempts: real("retry_attempts").default(3),
  circuitBreakerThreshold: real("circuit_breaker_threshold").default(5),
  lastHealthCheck: timestamp("last_health_check"),
  healthStatus: varchar("health_status", { length: 20 }).default("unknown"), // 'healthy', 'degraded', 'down', 'unknown'
  configuration: jsonb("configuration"), // Source-specific configuration
  apiKeyRequired: boolean("api_key_required").default(false),
  createdAt: timestamp("created_at").default(sql`now()`),
  updatedAt: timestamp("updated_at").default(sql`now()`),
});

// Track CVE discovery operations across sources
export const multiSourceCveScans = pgTable("multi_source_cve_scans", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  timeframeYears: real("timeframe_years").notNull().default(3),
  enabledSources: text("enabled_sources").array().notNull(), // List of source names used in this scan
  
  // Overall discovery metrics
  totalCvesDiscovered: real("total_cves_discovered").default(0),
  uniqueCvesAfterDeduplication: real("unique_cves_after_deduplication").default(0),
  duplicatesDetected: real("duplicates_detected").default(0),
  sourceConflictsDetected: real("source_conflicts_detected").default(0),
  
  // Per-source breakdown
  sourceBreakdown: jsonb("source_breakdown"), // { "nist": 1000, "vulners": 1200, etc. }
  sourcePerformance: jsonb("source_performance"), // Response times, error rates per source
  deduplicationMetrics: jsonb("deduplication_metrics"), // Detailed deduplication statistics
  
  // Scan progress and status
  status: text("status").notNull().default("pending"), // 'pending', 'running', 'completed', 'failed'
  currentPhase: text("current_phase").default("initializing"), // 'initializing', 'fetching', 'deduplicating', 'enriching', 'finalizing'
  progressPercentage: real("progress_percentage").default(0),
  
  startedAt: timestamp("started_at").default(sql`now()`),
  completedAt: timestamp("completed_at"),
  errorMessage: text("error_message"),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

export const insertCveSchema = createInsertSchema(cves).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertCveScanSchema = createInsertSchema(cveScans).omit({
  id: true,
  startedAt: true,
  completedAt: true,
}).extend({
  completedAt: z.date().nullable().optional(),
  startDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Start date must be in YYYY-MM-DD format").optional(),
  endDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "End date must be in YYYY-MM-DD format").optional(),
}).refine(
  (data) => {
    if (!data.startDate || !data.endDate) return true;
    const start = new Date(data.startDate);
    const end = new Date(data.endDate);
    return start <= end;
  },
  {
    message: "Start date must be before or equal to end date",
    path: ["endDate"],
  }
).refine(
  (data) => {
    if (!data.startDate || !data.endDate) return true;
    const start = new Date(data.startDate);
    const end = new Date(data.endDate);
    const maxDate = new Date();
    maxDate.setFullYear(maxDate.getFullYear() - 5);
    return start >= maxDate;
  },
  {
    message: "Date range cannot exceed 5 years from today",
    path: ["startDate"],
  }
);

export const insertMonitoringConfigSchema = createInsertSchema(monitoringConfig).omit({
  id: true,
  lastUpdateAt: true,
});

export const insertCveAlertSchema = createInsertSchema(cveAlerts).omit({
  id: true,
  detectedAt: true,
});

export const insertMonitoringRunSchema = createInsertSchema(monitoringRuns).omit({
  id: true,
  startedAt: true,
  completedAt: true,
});

export const insertCveSourceConfigSchema = createInsertSchema(cveSourceConfigs).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertMultiSourceCveScanSchema = createInsertSchema(multiSourceCveScans).omit({
  id: true,
  startedAt: true,
  completedAt: true,
});

// CVE Status Management Schemas
export const cveStatusUpdateSchema = z.object({
  status: z.enum(["new", "in_progress", "done", "unlisted"]).optional(),
  listCategory: z.string().max(50).optional(),
  isPriority: z.boolean().optional(),
  userNotes: z.string().optional(),
});

export const cveBulkStatusUpdateSchema = z.object({
  cveIds: z.array(z.string()).min(1, "At least one CVE ID is required"),
  updates: cveStatusUpdateSchema,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;
export type InsertCve = z.infer<typeof insertCveSchema>;
export type Cve = typeof cves.$inferSelect;
export type InsertCveScan = z.infer<typeof insertCveScanSchema>;
export type CveScan = typeof cveScans.$inferSelect;
export type InsertMonitoringConfig = z.infer<typeof insertMonitoringConfigSchema>;
export type MonitoringConfig = typeof monitoringConfig.$inferSelect;
export type InsertCveAlert = z.infer<typeof insertCveAlertSchema>;
export type CveAlert = typeof cveAlerts.$inferSelect;
export type InsertMonitoringRun = z.infer<typeof insertMonitoringRunSchema>;
export type MonitoringRun = typeof monitoringRuns.$inferSelect;
export type InsertCveSourceConfig = z.infer<typeof insertCveSourceConfigSchema>;
export type CveSourceConfig = typeof cveSourceConfigs.$inferSelect;
export type InsertMultiSourceCveScan = z.infer<typeof insertMultiSourceCveScanSchema>;
export type MultiSourceCveScan = typeof multiSourceCveScans.$inferSelect;

// Advanced Scoring Configuration Schema
export const advancedScoringConfigSchema = z.object({
  weights: z.object({
    educational: z.number().min(0).max(1),
    deployment: z.number().min(0).max(1),
    technical: z.number().min(0).max(1),
    practical: z.number().min(0).max(1),
    baseline: z.number().min(0).max(1)
  }),
  skillLevelMultipliers: z.object({
    beginner: z.number().min(0),
    intermediate: z.number().min(0),
    advanced: z.number().min(0)
  }),
  complexityPenalties: z.object({
    simple: z.number().min(0).max(1),
    moderate: z.number().min(0).max(1),
    complex: z.number().min(0).max(1)
  })
});

export type AdvancedScoringConfig = z.infer<typeof advancedScoringConfigSchema>;
