import crypto from 'crypto';
import { Cve } from '@shared/schema';

// Core types for multi-source CVE discovery
export interface CveSourceAdapter {
  readonly sourceName: string;
  readonly displayName: string;
  readonly baseUrl: string;
  readonly reliabilityScore: number;
  readonly isEnabled: boolean;
  
  // Health and rate limiting
  isHealthy(): Promise<boolean>;
  getRateLimitStatus(): Promise<RateLimitStatus>;
  
  // Core CVE discovery methods
  discoverCves(options: CveDiscoveryOptions): Promise<RawCveData[]>;
  getCveDetails(cveId: string): Promise<RawCveData | null>;
  
  // Source-specific capabilities
  supportsHistoricalData(): boolean;
  supportsRealTimeUpdates(): boolean;
  getMaxTimeframeYears(): number;
}

export interface RawCveData {
  cveId: string;
  source: string;
  sourceUrl?: string;
  description: string;
  publishedDate: Date;
  lastModifiedDate: Date;
  cvssScore?: number;
  cvssVector?: string;
  severity: string;
  affectedProducts?: string[];
  affectedVersions?: string[];
  attackVector?: string;
  references?: string[];
  cweIds?: string[];
  sourceMetadata: Record<string, any>;
  rawData?: any; // Original data from source for debugging
}

export interface CveDiscoveryOptions {
  timeframeYears: number;
  startDate?: string; // YYYY-MM-DD format
  endDate?: string; // YYYY-MM-DD format
  severities?: string[];
  keywords?: string[];
  technologies?: string[];
  maxResultsPerSource?: number;
  includeHistorical?: boolean;
  prioritizeSources?: string[];
}

export interface RateLimitStatus {
  isLimited: boolean;
  remainingRequests: number;
  resetTime: Date;
  dailyLimit: number;
}

export interface SourceHealth {
  sourceName: string;
  isHealthy: boolean;
  responseTime: number;
  lastError?: string;
  successRate: number;
  lastChecked: Date;
}

export interface DeduplicationResult {
  uniqueCves: EnrichedCveData[];
  duplicatesDetected: number;
  sourceConflicts: SourceConflict[];
  deduplicationMetrics: DeduplicationMetrics;
}

export interface EnrichedCveData extends RawCveData {
  sources: string[];
  primarySource: string;
  sourceReliabilityScore: number;
  deduplicationFingerprint: string;
  duplicateIds?: string[];
  sourceMetadata: Record<string, any>;
  crossSourceValidation: CrossSourceValidation;
  sourceConflicts?: SourceConflict[];
  consolidatedMetadata: ConsolidatedMetadata;
}

export interface CrossSourceValidation {
  totalSources: number;
  consistentFields: string[];
  conflictingFields: string[];
  confidence: number; // 0.0 to 1.0
  validationStatus: 'validated' | 'partial' | 'conflicted' | 'single_source';
}

export interface SourceConflict {
  field: string;
  values: Record<string, any>; // source -> value mapping
  severity: 'minor' | 'major' | 'critical';
  resolution: 'auto' | 'manual_required';
  resolvedValue?: any;
}

export interface ConsolidatedMetadata {
  // Consolidated fields from all sources
  allReferences: string[];
  allCweIds: string[];
  allAffectedProducts: string[];
  sourceSpecificData: Record<string, any>;
  enrichmentLevel: 'basic' | 'enhanced' | 'comprehensive';
}

export interface DeduplicationMetrics {
  totalRawCves: number;
  uniqueAfterDeduplication: number;
  duplicateGroups: number;
  averageSourcesPerCve: number;
  sourceDistribution: Record<string, number>;
  fingerprintCollisions: number;
  resolutionTime: number;
}

export interface MultiSourceDiscoveryResult {
  discoveredCves: EnrichedCveData[];
  sourceBreakdown: Record<string, number>;
  sourceHealth: SourceHealth[];
  deduplicationResult: DeduplicationResult;
  discoveryMetrics: DiscoveryMetrics;
  errors: SourceError[];
}

export interface DiscoveryMetrics {
  totalDiscoveryTime: number;
  parallelSources: number;
  successfulSources: number;
  failedSources: number;
  averageResponseTime: number;
  rateLimitedSources: string[];
  cacheHitRate: number;
}

export interface SourceError {
  sourceName: string;
  error: string;
  isRetryable: boolean;
  timestamp: Date;
  severity: 'warning' | 'error' | 'critical';
}

/**
 * MultiSourceCveDiscoveryService - Main orchestrator for CVE discovery across multiple platforms
 * 
 * This service coordinates CVE discovery from multiple vulnerability databases,
 * implements intelligent deduplication, and provides comprehensive CVE coverage
 * beyond what any single source can provide.
 */
export class MultiSourceCveDiscoveryService {
  private sourceAdapters: Map<string, CveSourceAdapter> = new Map();
  private cache = new Map<string, { data: any; timestamp: number; ttl: number }>();
  private sourceHealthCache = new Map<string, SourceHealth>();
  
  // Production configuration
  private readonly CONFIG = {
    defaultCacheTtl: 30 * 60 * 1000, // 30 minutes
    healthCheckInterval: 5 * 60 * 1000, // 5 minutes
    maxParallelSources: 8,
    defaultTimeout: 30000, // 30 seconds
    circuitBreakerThreshold: 5,
    maxRetries: 3,
    deduplicationCacheSize: 10000,
    fingerprintAlgorithm: 'sha256'
  };

  constructor() {
    this.initializeSourceAdapters();
  }

  /**
   * Initialize and register all available source adapters
   */
  private async initializeSourceAdapters(): Promise<void> {
    console.log('MultiSourceCveDiscoveryService: Initializing source adapters...');
    
    try {
      // Import and register all available source adapters
      const { createAllSourceAdapters } = await import('./sourceAdapters');
      const adapters = createAllSourceAdapters();
      
      for (const adapter of adapters) {
        this.registerSourceAdapter(adapter);
      }
      
      console.log(`MultiSourceCveDiscoveryService: Registered ${adapters.length} source adapters`);
      
      // Perform initial health checks
      const healthResults = await this.performHealthChecks();
      const healthyCount = healthResults.filter(h => h.isHealthy).length;
      
      console.log(`MultiSourceCveDiscoveryService: ${healthyCount}/${healthResults.length} adapters are healthy and ready`);
      
    } catch (error) {
      console.error('MultiSourceCveDiscoveryService: Failed to initialize source adapters:', error);
    }
  }

  /**
   * Register a new CVE source adapter
   */
  public registerSourceAdapter(adapter: CveSourceAdapter): void {
    this.sourceAdapters.set(adapter.sourceName, adapter);
    console.log(`Registered CVE source adapter: ${adapter.displayName}`);
  }

  /**
   * Main entry point for comprehensive CVE discovery across all sources
   */
  public async discoverCvesFromAllSources(options: CveDiscoveryOptions): Promise<MultiSourceDiscoveryResult> {
    const startTime = Date.now();
    const errors: SourceError[] = [];
    const sourceBreakdown: Record<string, number> = {};
    const allRawCves: RawCveData[] = [];

    console.log(`Starting multi-source CVE discovery with ${options.timeframeYears} year timeframe`);

    // 1. Health check all sources first
    const sourceHealth = await this.performHealthChecks();
    const healthySources = sourceHealth.filter(h => h.isHealthy);
    
    console.log(`${healthySources.length}/${sourceHealth.length} sources are healthy`);

    // 2. Prioritize sources based on reliability and user preferences
    const prioritizedSources = this.prioritizeSources(healthySources, options.prioritizeSources);

    // 3. Discover CVEs from all sources in parallel (with concurrency limits)
    const discoveryTasks = prioritizedSources.map(source => 
      this.discoverFromSingleSource(source.sourceName, options)
        .then(result => ({ source: source.sourceName, result }))
        .catch(error => ({ source: source.sourceName, error }))
    );

    const discoveryResults = await Promise.allSettled(discoveryTasks);

    // 4. Process results and collect successful discoveries
    for (const result of discoveryResults) {
      if (result.status === 'fulfilled' && 'result' in result.value) {
        const { source, result: cves } = result.value;
        allRawCves.push(...cves);
        sourceBreakdown[source] = cves.length;
        console.log(`${source}: discovered ${cves.length} CVEs`);
      } else if (result.status === 'fulfilled' && 'error' in result.value) {
        const { source, error } = result.value;
        errors.push({
          sourceName: source,
          error: String(error),
          isRetryable: this.isRetryableError(error),
          timestamp: new Date(),
          severity: 'error'
        });
        console.error(`${source}: discovery failed:`, error);
      }
    }

    console.log(`Raw discovery complete: ${allRawCves.length} total CVEs from ${Object.keys(sourceBreakdown).length} sources`);

    // 5. Intelligent deduplication and cross-source validation
    const deduplicationResult = await this.performIntelligentDeduplication(allRawCves);

    // 6. Build comprehensive discovery metrics
    const discoveryMetrics: DiscoveryMetrics = {
      totalDiscoveryTime: Date.now() - startTime,
      parallelSources: prioritizedSources.length,
      successfulSources: Object.keys(sourceBreakdown).length,
      failedSources: errors.length,
      averageResponseTime: this.calculateAverageResponseTime(sourceHealth),
      rateLimitedSources: errors.filter(e => e.error.includes('rate limit')).map(e => e.sourceName),
      cacheHitRate: this.calculateCacheHitRate()
    };

    console.log(`Multi-source CVE discovery completed in ${discoveryMetrics.totalDiscoveryTime}ms`);
    console.log(`Deduplication: ${allRawCves.length} → ${deduplicationResult.uniqueCves.length} unique CVEs`);

    return {
      discoveredCves: deduplicationResult.uniqueCves,
      sourceBreakdown,
      sourceHealth,
      deduplicationResult,
      discoveryMetrics,
      errors
    };
  }

  /**
   * Discover CVEs from a single source with error handling and caching
   */
  private async discoverFromSingleSource(sourceName: string, options: CveDiscoveryOptions): Promise<RawCveData[]> {
    const adapter = this.sourceAdapters.get(sourceName);
    if (!adapter || !adapter.isEnabled) {
      throw new Error(`Source adapter ${sourceName} not available or disabled`);
    }

    // Check cache first
    const cacheKey = this.generateCacheKey(sourceName, options);
    const cached = this.getFromCache(cacheKey);
    if (cached) {
      console.log(`Cache hit for ${sourceName}`);
      return cached;
    }

    // Check rate limits
    const rateLimitStatus = await adapter.getRateLimitStatus();
    if (rateLimitStatus.isLimited) {
      throw new Error(`Rate limited: ${rateLimitStatus.remainingRequests} requests remaining, resets at ${rateLimitStatus.resetTime}`);
    }

    try {
      const startTime = Date.now();
      const rawCves = await adapter.discoverCves(options);
      const responseTime = Date.now() - startTime;

      // Update source health metrics
      this.updateSourceHealth(sourceName, true, responseTime);

      // Cache the results
      this.setInCache(cacheKey, rawCves, this.CONFIG.defaultCacheTtl);

      console.log(`${sourceName}: discovered ${rawCves.length} CVEs in ${responseTime}ms`);
      return rawCves;

    } catch (error) {
      this.updateSourceHealth(sourceName, false, 0, String(error));
      throw error;
    }
  }

  /**
   * Perform intelligent deduplication across all sources
   * This is the core logic that identifies and merges duplicate CVEs
   */
  private async performIntelligentDeduplication(rawCves: RawCveData[]): Promise<DeduplicationResult> {
    const startTime = Date.now();
    const duplicateGroups = new Map<string, RawCveData[]>();
    const sourceConflicts: SourceConflict[] = [];
    let fingerprintCollisions = 0;

    console.log(`Starting intelligent deduplication of ${rawCves.length} raw CVEs`);

    // 1. Group CVEs by deduplication fingerprint
    for (const cve of rawCves) {
      const fingerprint = this.generateDeduplicationFingerprint(cve);
      
      if (!duplicateGroups.has(fingerprint)) {
        duplicateGroups.set(fingerprint, []);
      } else {
        fingerprintCollisions++;
      }
      
      duplicateGroups.get(fingerprint)!.push(cve);
    }

    console.log(`Fingerprint analysis: ${duplicateGroups.size} unique groups, ${fingerprintCollisions} collisions detected`);

    // 2. Process each duplicate group and create enriched CVE data
    const uniqueCves: EnrichedCveData[] = [];
    
    for (const [fingerprint, group] of Array.from(duplicateGroups)) {
      if (group.length === 1) {
        // Single source CVE - convert to enriched format
        const enriched = this.createEnrichedCveFromSingle(group[0], fingerprint);
        uniqueCves.push(enriched);
      } else {
        // Multiple sources - merge and detect conflicts
        const { enriched, conflicts } = this.mergeMultiSourceCve(group, fingerprint);
        uniqueCves.push(enriched);
        sourceConflicts.push(...conflicts);
      }
    }

    const deduplicationMetrics: DeduplicationMetrics = {
      totalRawCves: rawCves.length,
      uniqueAfterDeduplication: uniqueCves.length,
      duplicateGroups: duplicateGroups.size,
      averageSourcesPerCve: rawCves.length / uniqueCves.length,
      sourceDistribution: this.calculateSourceDistribution(rawCves),
      fingerprintCollisions,
      resolutionTime: Date.now() - startTime
    };

    console.log(`Deduplication completed in ${deduplicationMetrics.resolutionTime}ms: ${deduplicationMetrics.duplicateGroups} groups, ${sourceConflicts.length} conflicts`);

    return {
      uniqueCves,
      duplicatesDetected: rawCves.length - uniqueCves.length,
      sourceConflicts,
      deduplicationMetrics
    };
  }

  /**
   * Generate a unique fingerprint for CVE deduplication
   * Uses CVE ID as primary key, but falls back to content-based hashing for non-standard CVEs
   */
  private generateDeduplicationFingerprint(cve: RawCveData): string {
    // Primary deduplication: Use CVE ID if available and valid
    if (cve.cveId && /^CVE-\d{4}-\d{4,}$/i.test(cve.cveId)) {
      return cve.cveId.toUpperCase();
    }

    // Secondary deduplication: Content-based fingerprint for non-standard CVEs
    const normalizedDescription = cve.description.toLowerCase()
      .replace(/[^\w\s]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();

    const contentForHashing = [
      normalizedDescription.substring(0, 200), // First 200 chars of description
      cve.publishedDate.getFullYear().toString(),
      cve.publishedDate.getMonth().toString(),
      cve.severity.toLowerCase(),
      (cve.affectedProducts || []).sort().join(',').toLowerCase()
    ].join('|');

    return `CONTENT_${crypto.createHash(this.CONFIG.fingerprintAlgorithm).update(contentForHashing).digest('hex').substring(0, 16)}`;
  }

  /**
   * Create enriched CVE data from a single source
   */
  private createEnrichedCveFromSingle(cve: RawCveData, fingerprint: string): EnrichedCveData {
    const adapter = this.sourceAdapters.get(cve.source);
    const reliabilityScore = adapter?.reliabilityScore || 0.5;

    return {
      ...cve,
      sources: [cve.source],
      primarySource: cve.source,
      sourceReliabilityScore: reliabilityScore,
      deduplicationFingerprint: fingerprint,
      sourceMetadata: {
        [cve.source]: cve.sourceMetadata
      },
      crossSourceValidation: {
        totalSources: 1,
        consistentFields: [],
        conflictingFields: [],
        confidence: reliabilityScore,
        validationStatus: 'single_source'
      },
      consolidatedMetadata: {
        allReferences: cve.references || [],
        allCweIds: cve.cweIds || [],
        allAffectedProducts: cve.affectedProducts || [],
        sourceSpecificData: {
          [cve.source]: cve.sourceMetadata
        },
        enrichmentLevel: 'basic'
      }
    };
  }

  /**
   * Merge multiple CVEs from different sources and detect conflicts
   */
  private mergeMultiSourceCve(group: RawCveData[], fingerprint: string): { enriched: EnrichedCveData; conflicts: SourceConflict[] } {
    const conflicts: SourceConflict[] = [];
    const sources = group.map(cve => cve.source);
    
    // Determine primary source (highest reliability score)
    const primarySource = this.selectPrimarySource(group);
    const primaryCve = group.find(cve => cve.source === primarySource)!;

    // Calculate weighted reliability score
    const totalReliability = group.reduce((sum, cve) => {
      const adapter = this.sourceAdapters.get(cve.source);
      return sum + (adapter?.reliabilityScore || 0.5);
    }, 0);
    const averageReliability = totalReliability / group.length;

    // Detect and resolve conflicts
    const resolvedFields = this.detectAndResolveConflicts(group, conflicts);

    // Build consolidated metadata
    const consolidatedMetadata: ConsolidatedMetadata = {
      allReferences: Array.from(new Set(group.flatMap(cve => cve.references || []))),
      allCweIds: Array.from(new Set(group.flatMap(cve => cve.cweIds || []))),
      allAffectedProducts: Array.from(new Set(group.flatMap(cve => cve.affectedProducts || []))),
      sourceSpecificData: group.reduce((acc, cve) => {
        acc[cve.source] = cve.sourceMetadata;
        return acc;
      }, {} as Record<string, any>),
      enrichmentLevel: group.length >= 3 ? 'comprehensive' : 'enhanced'
    };

    // Cross-source validation
    const crossSourceValidation: CrossSourceValidation = {
      totalSources: group.length,
      consistentFields: this.getConsistentFields(group),
      conflictingFields: conflicts.map(c => c.field),
      confidence: Math.min(0.95, averageReliability * (1 + group.length * 0.1)), // Boost confidence with more sources
      validationStatus: conflicts.length === 0 ? 'validated' : conflicts.length <= 2 ? 'partial' : 'conflicted'
    };

    const enriched: EnrichedCveData = {
      ...primaryCve,
      ...resolvedFields,
      sources,
      primarySource,
      sourceReliabilityScore: averageReliability,
      deduplicationFingerprint: fingerprint,
      duplicateIds: group.map(cve => `${cve.source}:${cve.cveId}`).filter((id, index, arr) => arr.indexOf(id) === index),
      sourceMetadata: group.reduce((acc, cve) => {
        acc[cve.source] = cve.sourceMetadata;
        return acc;
      }, {} as Record<string, any>),
      crossSourceValidation,
      sourceConflicts: conflicts.length > 0 ? conflicts : undefined,
      consolidatedMetadata
    };

    return { enriched, conflicts };
  }

  /**
   * Detect conflicts between sources and resolve them using reliability weighting
   */
  private detectAndResolveConflicts(group: RawCveData[], conflicts: SourceConflict[]): Partial<RawCveData> {
    const resolved: Partial<RawCveData> = {};
    const fields = ['cvssScore', 'severity', 'description', 'publishedDate', 'lastModifiedDate'];

    for (const field of fields) {
      const values = new Map<any, { sources: string[]; totalReliability: number }>();
      
      // Collect all values for this field
      for (const cve of group) {
        const value = (cve as any)[field];
        if (value !== undefined && value !== null) {
          const key = this.normalizeValueForComparison(value);
          const adapter = this.sourceAdapters.get(cve.source);
          const reliability = adapter?.reliabilityScore || 0.5;
          
          if (!values.has(key)) {
            values.set(key, { sources: [], totalReliability: 0 });
          }
          
          const entry = values.get(key)!;
          entry.sources.push(cve.source);
          entry.totalReliability += reliability;
        }
      }

      // Check for conflicts
      if (values.size > 1) {
        const conflict: SourceConflict = {
          field,
          values: {},
          severity: this.assessConflictSeverity(field, Array.from(values.keys())),
          resolution: 'auto'
        };

        // Build values mapping
        for (const [value, entry] of Array.from(values)) {
          for (const source of entry.sources) {
            conflict.values[source] = value;
          }
        }

        // Resolve by highest total reliability
        const bestEntry = Array.from(values.entries())
          .sort((a, b) => b[1].totalReliability - a[1].totalReliability)[0];
        
        conflict.resolvedValue = bestEntry[0];
        (resolved as any)[field] = this.denormalizeValue(bestEntry[0], field);
        
        conflicts.push(conflict);
      } else if (values.size === 1) {
        // No conflict - use the single value
        const value = Array.from(values.keys())[0];
        (resolved as any)[field] = this.denormalizeValue(value, field);
      }
    }

    return resolved;
  }

  /**
   * Perform health checks on all registered sources
   */
  private async performHealthChecks(): Promise<SourceHealth[]> {
    const healthChecks = Array.from(this.sourceAdapters.values()).map(async (adapter) => {
      const startTime = Date.now();
      
      try {
        const isHealthy = await adapter.isHealthy();
        const responseTime = Date.now() - startTime;
        
        const health: SourceHealth = {
          sourceName: adapter.sourceName,
          isHealthy,
          responseTime,
          successRate: this.calculateSuccessRate(adapter.sourceName),
          lastChecked: new Date()
        };
        
        this.sourceHealthCache.set(adapter.sourceName, health);
        return health;
        
      } catch (error) {
        const health: SourceHealth = {
          sourceName: adapter.sourceName,
          isHealthy: false,
          responseTime: Date.now() - startTime,
          lastError: String(error),
          successRate: this.calculateSuccessRate(adapter.sourceName),
          lastChecked: new Date()
        };
        
        this.sourceHealthCache.set(adapter.sourceName, health);
        return health;
      }
    });

    return Promise.all(healthChecks);
  }

  // Utility methods
  private prioritizeSources(healthySources: SourceHealth[], prioritized?: string[]): SourceHealth[] {
    if (!prioritized || prioritized.length === 0) {
      return healthySources.sort((a, b) => b.successRate - a.successRate);
    }

    const prioritizedSet = new Set(prioritized);
    const priority = healthySources.filter(s => prioritizedSet.has(s.sourceName));
    const others = healthySources.filter(s => !prioritizedSet.has(s.sourceName))
      .sort((a, b) => b.successRate - a.successRate);

    return [...priority, ...others];
  }

  private selectPrimarySource(group: RawCveData[]): string {
    return group
      .map(cve => ({
        source: cve.source,
        reliability: this.sourceAdapters.get(cve.source)?.reliabilityScore || 0.5
      }))
      .sort((a, b) => b.reliability - a.reliability)[0].source;
  }

  private getConsistentFields(group: RawCveData[]): string[] {
    const fields = ['cvssScore', 'severity', 'publishedDate'];
    const consistent: string[] = [];

    for (const field of fields) {
      const values = new Set(group.map(cve => this.normalizeValueForComparison((cve as any)[field])));
      if (values.size === 1) {
        consistent.push(field);
      }
    }

    return consistent;
  }

  private normalizeValueForComparison(value: any): any {
    if (value instanceof Date) {
      return value.toISOString().split('T')[0]; // Normalize to date only
    }
    if (typeof value === 'string') {
      return value.toLowerCase().trim();
    }
    return value;
  }

  private denormalizeValue(value: any, field: string): any {
    // Convert back to appropriate type for the field
    if (field.includes('Date') && typeof value === 'string') {
      return new Date(value);
    }
    return value;
  }

  private assessConflictSeverity(field: string, values: any[]): 'minor' | 'major' | 'critical' {
    if (field === 'severity' || field === 'cvssScore') {
      return 'major';
    }
    if (field === 'description' && values.some(v => typeof v === 'string' && v.length > 100)) {
      return 'minor';
    }
    return 'minor';
  }

  private calculateSuccessRate(sourceName: string): number {
    // This would be calculated based on historical data
    // For now, return a default value
    return 0.95;
  }

  private calculateAverageResponseTime(sourceHealth: SourceHealth[]): number {
    const healthySources = sourceHealth.filter(s => s.isHealthy);
    if (healthySources.length === 0) return 0;
    return healthySources.reduce((sum, s) => sum + s.responseTime, 0) / healthySources.length;
  }

  private calculateCacheHitRate(): number {
    // Implementation would track cache hits vs misses
    return 0.75; // Default value
  }

  private calculateSourceDistribution(rawCves: RawCveData[]): Record<string, number> {
    const distribution: Record<string, number> = {};
    for (const cve of rawCves) {
      distribution[cve.source] = (distribution[cve.source] || 0) + 1;
    }
    return distribution;
  }

  private isRetryableError(error: any): boolean {
    const errorStr = String(error).toLowerCase();
    return errorStr.includes('timeout') || 
           errorStr.includes('network') || 
           errorStr.includes('rate limit') ||
           errorStr.includes('503') || 
           errorStr.includes('502');
  }

  private updateSourceHealth(sourceName: string, success: boolean, responseTime: number, error?: string): void {
    // Update source health metrics in cache
    const existing = this.sourceHealthCache.get(sourceName);
    if (existing) {
      existing.isHealthy = success;
      existing.responseTime = responseTime;
      existing.lastError = error;
      existing.lastChecked = new Date();
    }
  }

  // Cache management
  private generateCacheKey(sourceName: string, options: CveDiscoveryOptions): string {
    const optionsHash = crypto.createHash('md5')
      .update(JSON.stringify(options))
      .digest('hex')
      .substring(0, 8);
    return `cve_discovery:${sourceName}:${optionsHash}`;
  }

  private getFromCache(key: string): any | null {
    const cached = this.cache.get(key);
    if (cached && Date.now() - cached.timestamp < cached.ttl) {
      return cached.data;
    }
    this.cache.delete(key);
    return null;
  }

  private setInCache(key: string, data: any, ttl: number): void {
    this.cache.set(key, {
      data,
      timestamp: Date.now(),
      ttl
    });

    // Prevent unlimited cache growth
    if (this.cache.size > this.CONFIG.deduplicationCacheSize) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey) {
        this.cache.delete(oldestKey);
      }
    }
  }
}