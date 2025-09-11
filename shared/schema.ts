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

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;
export type InsertCve = z.infer<typeof insertCveSchema>;
export type Cve = typeof cves.$inferSelect;
export type InsertCveScan = z.infer<typeof insertCveScanSchema>;
export type CveScan = typeof cveScans.$inferSelect;
