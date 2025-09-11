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
  createdAt: timestamp("created_at").default(sql`now()`),
  updatedAt: timestamp("updated_at").default(sql`now()`),
});

export const cveScans = pgTable("cve_scans", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  timeframeYears: real("timeframe_years").notNull().default(3),
  totalFound: real("total_found").default(0),
  labDeployable: real("lab_deployable").default(0),
  withPoc: real("with_poc").default(0),
  criticalSeverity: real("critical_severity").default(0),
  status: text("status").notNull().default("pending"),
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
});

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
