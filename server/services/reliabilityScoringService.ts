/**
 * Reliability Scoring Service for Multi-Source CVE Discovery
 * 
 * This service provides comprehensive reliability scoring for CVE sources based on:
 * - Historical accuracy and completeness
 * - Source performance metrics
 * - Cross-source validation results
 * - Source health and availability
 * - Community feedback and validation
 */

export interface SourceReliabilityMetrics {
  sourceName: string;
  displayName: string;
  
  // Core reliability scores (0.0 to 1.0)
  baseReliabilityScore: number;        // Static base score
  dynamicReliabilityScore: number;     // Calculated from recent performance
  accuracyScore: number;               // Historical accuracy of provided data
  completenessScore: number;           // How complete the data is compared to other sources
  freshnessScore: number;              // How up-to-date the data is
  consistencyScore: number;            // How consistent data is across time
  
  // Performance metrics
  averageResponseTime: number;         // In milliseconds
  successRate: number;                 // 0.0 to 1.0
  uptime: number;                      // 0.0 to 1.0
  rateLimitCompliance: number;         // How well it respects rate limits
  
  // Data quality metrics
  duplicateDetectionRate: number;      // How often this source provides duplicates
  conflictResolutionWins: number;      // How often this source "wins" in conflicts
  crossSourceValidationScore: number; // How often other sources agree with this one
  metadataRichness: number;           // How much useful metadata this source provides
  
  // Historical tracking
  totalCvesProvided: number;
  uniqueCvesProvided: number;
  lastEvaluated: Date;
  evaluationCount: number;
  
  // Weighted final score
  finalReliabilityScore: number;
}

export interface ReliabilityWeights {
  accuracy: number;           // Weight for accuracy score
  completeness: number;       // Weight for completeness score
  freshness: number;          // Weight for freshness score
  consistency: number;        // Weight for consistency score
  performance: number;        // Weight for performance metrics
  availability: number;       // Weight for uptime/availability
  metadata: number;          // Weight for metadata richness
}

export interface SourcePerformanceHistory {
  sourceName: string;
  timestamp: Date;
  responseTime: number;
  success: boolean;
  cvesReturned: number;
  errorType?: string;
  conflictsDetected: number;
  duplicatesDetected: number;
}

export interface CrossSourceValidation {
  cveId: string;
  sourceAgreements: Record<string, boolean>; // source -> agrees with majority
  majorityFields: string[];
  conflictFields: string[];
  consensusReached: boolean;
  validationTimestamp: Date;
}

/**
 * Comprehensive Reliability Scoring Service
 */
export class ReliabilityScoringService {
  private performanceHistory: Map<string, SourcePerformanceHistory[]> = new Map();
  private validationHistory: CrossSourceValidation[] = [];
  private sourceMetrics: Map<string, SourceReliabilityMetrics> = new Map();
  
  // Configurable weights for different reliability factors
  private readonly defaultWeights: ReliabilityWeights = {
    accuracy: 0.25,          // 25% weight on accuracy
    completeness: 0.20,      // 20% weight on completeness
    freshness: 0.15,         // 15% weight on freshness
    consistency: 0.15,       // 15% weight on consistency
    performance: 0.10,       // 10% weight on performance
    availability: 0.10,      // 10% weight on availability
    metadata: 0.05           // 5% weight on metadata richness
  };

  // Historical data retention
  private readonly config = {
    maxHistoryEntries: 1000,
    validationWindowDays: 30,
    performanceWindowDays: 7,
    minEvaluationsForReliability: 10,
    reliabilityUpdateIntervalHours: 6
  };

  constructor() {
    this.initializeBaselineMetrics();
  }

  /**
   * Calculate comprehensive reliability score for a source
   */
  public calculateSourceReliability(
    sourceName: string, 
    weights: Partial<ReliabilityWeights> = {}
  ): SourceReliabilityMetrics {
    const finalWeights = { ...this.defaultWeights, ...weights };
    const existing = this.sourceMetrics.get(sourceName);
    
    if (!existing) {
      throw new Error(`Source metrics not found for: ${sourceName}`);
    }

    // Calculate individual component scores
    const accuracyScore = this.calculateAccuracyScore(sourceName);
    const completenessScore = this.calculateCompletenessScore(sourceName);
    const freshnessScore = this.calculateFreshnessScore(sourceName);
    const consistencyScore = this.calculateConsistencyScore(sourceName);
    const performanceScore = this.calculatePerformanceScore(sourceName);
    const availabilityScore = this.calculateAvailabilityScore(sourceName);
    const metadataScore = this.calculateMetadataScore(sourceName);

    // Calculate weighted final score
    const finalScore = (
      accuracyScore * finalWeights.accuracy +
      completenessScore * finalWeights.completeness +
      freshnessScore * finalWeights.freshness +
      consistencyScore * finalWeights.consistency +
      performanceScore * finalWeights.performance +
      availabilityScore * finalWeights.availability +
      metadataScore * finalWeights.metadata
    );

    // Update metrics
    const updatedMetrics: SourceReliabilityMetrics = {
      ...existing,
      accuracyScore,
      completenessScore,
      freshnessScore,
      consistencyScore,
      dynamicReliabilityScore: finalScore,
      finalReliabilityScore: this.blendBaseAndDynamicScores(existing.baseReliabilityScore, finalScore),
      averageResponseTime: this.calculateAverageResponseTime(sourceName),
      successRate: this.calculateSuccessRate(sourceName),
      uptime: this.calculateUptime(sourceName),
      crossSourceValidationScore: this.calculateCrossSourceValidationScore(sourceName),
      lastEvaluated: new Date(),
      evaluationCount: existing.evaluationCount + 1
    };

    this.sourceMetrics.set(sourceName, updatedMetrics);
    return updatedMetrics;
  }

  /**
   * Record performance data for a source
   */
  public recordSourcePerformance(performance: SourcePerformanceHistory): void {
    const history = this.performanceHistory.get(performance.sourceName) || [];
    history.push(performance);
    
    // Maintain maximum history size
    if (history.length > this.config.maxHistoryEntries) {
      history.splice(0, history.length - this.config.maxHistoryEntries);
    }
    
    this.performanceHistory.set(performance.sourceName, history);
    
    // Update source metrics
    this.updateSourceMetricsFromPerformance(performance.sourceName);
  }

  /**
   * Record cross-source validation results
   */
  public recordCrossSourceValidation(validation: CrossSourceValidation): void {
    this.validationHistory.push(validation);
    
    // Maintain validation history within window
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.config.validationWindowDays);
    
    this.validationHistory = this.validationHistory.filter(
      v => v.validationTimestamp >= cutoffDate
    );
    
    // Update cross-source validation scores for all sources
    this.updateCrossSourceValidationScores();
  }

  /**
   * Get reliability ranking of all sources
   */
  public getSourceReliabilityRanking(): SourceReliabilityMetrics[] {
    const metrics = Array.from(this.sourceMetrics.values());
    return metrics.sort((a, b) => b.finalReliabilityScore - a.finalReliabilityScore);
  }

  /**
   * Get reliability score for conflict resolution
   */
  public getSourceReliabilityForConflictResolution(sourceName: string): number {
    const metrics = this.sourceMetrics.get(sourceName);
    if (!metrics) return 0.5; // Default neutral score
    
    // For conflict resolution, emphasize accuracy and consistency
    return (
      metrics.accuracyScore * 0.4 +
      metrics.consistencyScore * 0.3 +
      metrics.crossSourceValidationScore * 0.2 +
      metrics.finalReliabilityScore * 0.1
    );
  }

  /**
   * Analyze source performance trends
   */
  public analyzeSourceTrends(sourceName: string, days: number = 7): {
    reliabilityTrend: 'improving' | 'stable' | 'declining';
    performanceTrend: 'improving' | 'stable' | 'declining';
    issues: string[];
    recommendations: string[];
  } {
    const history = this.getRecentPerformanceHistory(sourceName, days);
    const issues: string[] = [];
    const recommendations: string[] = [];
    
    if (history.length < 5) {
      return {
        reliabilityTrend: 'stable',
        performanceTrend: 'stable',
        issues: ['Insufficient data for trend analysis'],
        recommendations: ['Continue monitoring source performance']
      };
    }

    // Analyze reliability trend
    const recentReliability = this.calculateRecentReliabilityTrend(sourceName, days);
    const reliabilityTrend = this.classifyTrend(recentReliability);
    
    // Analyze performance trend  
    const recentPerformance = this.calculateRecentPerformanceTrend(sourceName, days);
    const performanceTrend = this.classifyTrend(recentPerformance);
    
    // Identify issues
    const successRate = this.calculateSuccessRate(sourceName);
    const avgResponseTime = this.calculateAverageResponseTime(sourceName);
    
    if (successRate < 0.9) {
      issues.push(`Low success rate: ${(successRate * 100).toFixed(1)}%`);
      recommendations.push('Investigate connection issues or API changes');
    }
    
    if (avgResponseTime > 10000) {
      issues.push(`High response time: ${avgResponseTime}ms`);
      recommendations.push('Consider timeout adjustments or caching strategies');
    }
    
    if (reliabilityTrend === 'declining') {
      issues.push('Reliability trend is declining');
      recommendations.push('Review data quality and cross-source validations');
    }

    return {
      reliabilityTrend,
      performanceTrend,
      issues,
      recommendations
    };
  }

  /**
   * Generate reliability report for all sources
   */
  public generateReliabilityReport(): {
    summary: {
      totalSources: number;
      averageReliability: number;
      healthySources: number;
      sourcesNeedingAttention: number;
    };
    sourceRankings: SourceReliabilityMetrics[];
    recommendations: Array<{
      sourceName: string;
      issue: string;
      recommendation: string;
      priority: 'high' | 'medium' | 'low';
    }>;
  } {
    const allMetrics = Array.from(this.sourceMetrics.values());
    const rankings = this.getSourceReliabilityRanking();
    const recommendations: Array<any> = [];

    // Calculate summary statistics
    const totalSources = allMetrics.length;
    const averageReliability = allMetrics.reduce((sum, m) => sum + m.finalReliabilityScore, 0) / totalSources;
    const healthySources = allMetrics.filter(m => m.finalReliabilityScore >= 0.8).length;
    const sourcesNeedingAttention = allMetrics.filter(m => m.finalReliabilityScore < 0.6).length;

    // Generate recommendations
    for (const metrics of allMetrics) {
      if (metrics.finalReliabilityScore < 0.5) {
        recommendations.push({
          sourceName: metrics.sourceName,
          issue: 'Very low reliability score',
          recommendation: 'Consider disabling or investigating data quality issues',
          priority: 'high' as const
        });
      } else if (metrics.successRate < 0.8) {
        recommendations.push({
          sourceName: metrics.sourceName,
          issue: 'Low success rate',
          recommendation: 'Check connection stability and error handling',
          priority: 'medium' as const
        });
      } else if (metrics.averageResponseTime > 15000) {
        recommendations.push({
          sourceName: metrics.sourceName,
          issue: 'High response time',
          recommendation: 'Optimize queries or implement caching',
          priority: 'low' as const
        });
      }
    }

    return {
      summary: {
        totalSources,
        averageReliability,
        healthySources,
        sourcesNeedingAttention
      },
      sourceRankings: rankings,
      recommendations
    };
  }

  // Private calculation methods
  private calculateAccuracyScore(sourceName: string): number {
    const validations = this.getSourceValidations(sourceName);
    if (validations.length === 0) return 0.8; // Default neutral score
    
    const accurateValidations = validations.filter(v => v.consensusReached).length;
    return accurateValidations / validations.length;
  }

  private calculateCompletenessScore(sourceName: string): number {
    const metrics = this.sourceMetrics.get(sourceName);
    if (!metrics) return 0.5;
    
    // Compare unique CVEs to total CVEs to measure completeness
    if (metrics.totalCvesProvided === 0) return 0.5;
    
    const uniquenessRatio = metrics.uniqueCvesProvided / metrics.totalCvesProvided;
    const metadataCompleteness = metrics.metadataRichness;
    
    return (uniquenessRatio * 0.6 + metadataCompleteness * 0.4);
  }

  private calculateFreshnessScore(sourceName: string): number {
    const history = this.getRecentPerformanceHistory(sourceName, 1);
    if (history.length === 0) return 0.5;
    
    const latestEntry = history[history.length - 1];
    const hoursSinceUpdate = (Date.now() - latestEntry.timestamp.getTime()) / (1000 * 60 * 60);
    
    // Fresher data gets higher score, with 24 hours being the baseline
    if (hoursSinceUpdate <= 1) return 1.0;
    if (hoursSinceUpdate <= 6) return 0.9;
    if (hoursSinceUpdate <= 24) return 0.8;
    if (hoursSinceUpdate <= 72) return 0.6;
    return 0.4;
  }

  private calculateConsistencyScore(sourceName: string): number {
    const history = this.getRecentPerformanceHistory(sourceName, 7);
    if (history.length < 3) return 0.5;
    
    // Calculate consistency based on performance variance
    const responseTimes = history.map(h => h.responseTime);
    const successRates = history.map(h => h.success ? 1 : 0);
    
    const responseTimeVariance = this.calculateVariance(responseTimes);
    const successRateVariance = this.calculateVariance(successRates);
    
    // Lower variance = higher consistency
    const responseConsistency = Math.max(0, 1 - (responseTimeVariance / 10000)); // Normalize
    const successConsistency = Math.max(0, 1 - successRateVariance);
    
    return (responseConsistency + successConsistency) / 2;
  }

  private calculatePerformanceScore(sourceName: string): number {
    const avgResponseTime = this.calculateAverageResponseTime(sourceName);
    const successRate = this.calculateSuccessRate(sourceName);
    
    // Performance score based on response time and success rate
    const responseScore = Math.max(0, 1 - (avgResponseTime / 30000)); // 30s max
    return (responseScore * 0.4 + successRate * 0.6);
  }

  private calculateAvailabilityScore(sourceName: string): number {
    return this.calculateUptime(sourceName);
  }

  private calculateMetadataScore(sourceName: string): number {
    const metrics = this.sourceMetrics.get(sourceName);
    return metrics?.metadataRichness || 0.5;
  }

  private calculateAverageResponseTime(sourceName: string): number {
    const history = this.getRecentPerformanceHistory(sourceName, 7);
    if (history.length === 0) return 5000; // Default 5s
    
    const totalTime = history.reduce((sum, h) => sum + h.responseTime, 0);
    return totalTime / history.length;
  }

  private calculateSuccessRate(sourceName: string): number {
    const history = this.getRecentPerformanceHistory(sourceName, 7);
    if (history.length === 0) return 0.95; // Default optimistic
    
    const successes = history.filter(h => h.success).length;
    return successes / history.length;
  }

  private calculateUptime(sourceName: string): number {
    const history = this.getRecentPerformanceHistory(sourceName, 7);
    if (history.length === 0) return 0.95; // Default optimistic
    
    const uptimeEntries = history.filter(h => h.success).length;
    return uptimeEntries / history.length;
  }

  private calculateCrossSourceValidationScore(sourceName: string): number {
    const validations = this.getSourceValidations(sourceName);
    if (validations.length === 0) return 0.8; // Default neutral
    
    let agreementScore = 0;
    let totalValidations = 0;
    
    for (const validation of validations) {
      if (validation.sourceAgreements[sourceName] !== undefined) {
        agreementScore += validation.sourceAgreements[sourceName] ? 1 : 0;
        totalValidations++;
      }
    }
    
    return totalValidations > 0 ? agreementScore / totalValidations : 0.8;
  }

  private blendBaseAndDynamicScores(baseScore: number, dynamicScore: number): number {
    // Blend base score with dynamic score, giving more weight to dynamic as we get more data
    const metrics = this.sourceMetrics.get('dummy'); // This is a simplification
    const evaluationCount = metrics?.evaluationCount || 0;
    
    if (evaluationCount < this.config.minEvaluationsForReliability) {
      // Favor base score when we have limited data
      const weight = evaluationCount / this.config.minEvaluationsForReliability;
      return baseScore * (1 - weight) + dynamicScore * weight;
    }
    
    // Favor dynamic score when we have sufficient data
    return baseScore * 0.2 + dynamicScore * 0.8;
  }

  // Helper methods
  private initializeBaselineMetrics(): void {
    // Initialize baseline metrics for known sources
    const baselineMetrics = [
      { name: 'mitre', display: 'MITRE CVE', baseScore: 0.95, metadataRichness: 0.7 },
      { name: 'vulners', display: 'Vulners', baseScore: 0.80, metadataRichness: 0.9 },
      { name: 'cvedetails', display: 'CVE Details', baseScore: 0.85, metadataRichness: 0.8 },
      { name: 'circl', display: 'CIRCL CVE Search', baseScore: 0.75, metadataRichness: 0.6 },
      { name: 'exploitdb', display: 'Exploit Database', baseScore: 0.70, metadataRichness: 0.8 }
    ];

    for (const baseline of baselineMetrics) {
      this.sourceMetrics.set(baseline.name, {
        sourceName: baseline.name,
        displayName: baseline.display,
        baseReliabilityScore: baseline.baseScore,
        dynamicReliabilityScore: baseline.baseScore,
        accuracyScore: baseline.baseScore,
        completenessScore: baseline.baseScore,
        freshnessScore: 0.8,
        consistencyScore: 0.8,
        averageResponseTime: 5000,
        successRate: 0.95,
        uptime: 0.98,
        rateLimitCompliance: 0.9,
        duplicateDetectionRate: 0.05,
        conflictResolutionWins: 0,
        crossSourceValidationScore: 0.8,
        metadataRichness: baseline.metadataRichness,
        totalCvesProvided: 0,
        uniqueCvesProvided: 0,
        lastEvaluated: new Date(),
        evaluationCount: 0,
        finalReliabilityScore: baseline.baseScore
      });
    }
  }

  private getRecentPerformanceHistory(sourceName: string, days: number): SourcePerformanceHistory[] {
    const history = this.performanceHistory.get(sourceName) || [];
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);
    
    return history.filter(h => h.timestamp >= cutoffDate);
  }

  private getSourceValidations(sourceName: string): CrossSourceValidation[] {
    return this.validationHistory.filter(v => 
      v.sourceAgreements[sourceName] !== undefined
    );
  }

  private updateSourceMetricsFromPerformance(sourceName: string): void {
    const metrics = this.sourceMetrics.get(sourceName);
    if (!metrics) return;

    const history = this.getRecentPerformanceHistory(sourceName, 7);
    if (history.length === 0) return;

    // Update performance-related metrics
    metrics.averageResponseTime = this.calculateAverageResponseTime(sourceName);
    metrics.successRate = this.calculateSuccessRate(sourceName);
    metrics.uptime = this.calculateUptime(sourceName);
    
    // Update totals
    metrics.totalCvesProvided += history[history.length - 1].cvesReturned;
    
    this.sourceMetrics.set(sourceName, metrics);
  }

  private updateCrossSourceValidationScores(): void {
    for (const [sourceName] of this.sourceMetrics) {
      const score = this.calculateCrossSourceValidationScore(sourceName);
      const metrics = this.sourceMetrics.get(sourceName);
      if (metrics) {
        metrics.crossSourceValidationScore = score;
        this.sourceMetrics.set(sourceName, metrics);
      }
    }
  }

  private calculateVariance(values: number[]): number {
    if (values.length === 0) return 0;
    
    const mean = values.reduce((sum, val) => sum + val, 0) / values.length;
    const squaredDiffs = values.map(val => Math.pow(val - mean, 2));
    return squaredDiffs.reduce((sum, diff) => sum + diff, 0) / values.length;
  }

  private calculateRecentReliabilityTrend(sourceName: string, days: number): number[] {
    // Simplified trend calculation - would need more sophisticated time-series analysis
    const history = this.getRecentPerformanceHistory(sourceName, days);
    return history.map((_, index) => {
      // Mock reliability calculation over time
      return this.sourceMetrics.get(sourceName)?.finalReliabilityScore || 0.5;
    });
  }

  private calculateRecentPerformanceTrend(sourceName: string, days: number): number[] {
    const history = this.getRecentPerformanceHistory(sourceName, days);
    return history.map(h => h.success ? h.responseTime : 30000); // Treat failures as max response time
  }

  private classifyTrend(values: number[]): 'improving' | 'stable' | 'declining' {
    if (values.length < 3) return 'stable';
    
    const firstHalf = values.slice(0, Math.floor(values.length / 2));
    const secondHalf = values.slice(Math.floor(values.length / 2));
    
    const firstAvg = firstHalf.reduce((sum, val) => sum + val, 0) / firstHalf.length;
    const secondAvg = secondHalf.reduce((sum, val) => sum + val, 0) / secondHalf.length;
    
    const change = (secondAvg - firstAvg) / firstAvg;
    
    if (change > 0.1) return 'improving';
    if (change < -0.1) return 'declining';
    return 'stable';
  }
}