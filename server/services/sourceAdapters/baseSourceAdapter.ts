import { CveSourceAdapter, RawCveData, CveDiscoveryOptions, RateLimitStatus } from '../multiSourceCveDiscoveryService';

/**
 * Base abstract class for all CVE source adapters
 * Provides common functionality and enforces consistent interface
 */
export abstract class BaseSourceAdapter implements CveSourceAdapter {
  abstract readonly sourceName: string;
  abstract readonly displayName: string;
  abstract readonly baseUrl: string;
  abstract readonly reliabilityScore: number;
  
  public isEnabled: boolean = true;
  
  // Circuit breaker and rate limiting state
  protected circuitBreaker = {
    failures: 0,
    lastFailure: 0,
    isOpen: false,
    threshold: 5,
    resetTime: 5 * 60 * 1000 // 5 minutes
  };
  
  protected rateLimitState = {
    requestCount: 0,
    windowStart: Date.now(),
    windowSize: 60 * 1000, // 1 minute
    maxRequests: 60
  };

  // Production configuration
  protected readonly config = {
    timeout: 30000,
    retryAttempts: 3,
    retryDelay: 1000,
    userAgent: 'CVE-Lab-Hunter/2.0 (+https://github.com/cve-lab-hunter)',
    maxResultsPerPage: 100,
    maxTotalResults: 2000
  };

  /**
   * Health check implementation
   */
  public async isHealthy(): Promise<boolean> {
    if (this.circuitBreaker.isOpen) {
      const timeSinceLastFailure = Date.now() - this.circuitBreaker.lastFailure;
      if (timeSinceLastFailure > this.circuitBreaker.resetTime) {
        this.circuitBreaker.isOpen = false;
        this.circuitBreaker.failures = 0;
      } else {
        return false;
      }
    }

    try {
      const healthCheckResult = await this.performHealthCheck();
      if (healthCheckResult) {
        this.resetCircuitBreaker();
      }
      return healthCheckResult;
    } catch (error) {
      this.recordFailure();
      return false;
    }
  }

  /**
   * Get current rate limit status
   */
  public async getRateLimitStatus(): Promise<RateLimitStatus> {
    this.updateRateLimitWindow();
    
    const remaining = Math.max(0, this.rateLimitState.maxRequests - this.rateLimitState.requestCount);
    const resetTime = new Date(this.rateLimitState.windowStart + this.rateLimitState.windowSize);
    
    return {
      isLimited: remaining === 0,
      remainingRequests: remaining,
      resetTime,
      dailyLimit: this.rateLimitState.maxRequests * 24 * 60 // Estimate daily limit
    };
  }

  /**
   * Main CVE discovery method - must be implemented by subclasses
   */
  public abstract discoverCves(options: CveDiscoveryOptions): Promise<RawCveData[]>;

  /**
   * Get detailed information for a specific CVE - must be implemented by subclasses
   */
  public abstract getCveDetails(cveId: string): Promise<RawCveData | null>;

  /**
   * Source capability methods
   */
  public abstract supportsHistoricalData(): boolean;
  public abstract supportsRealTimeUpdates(): boolean;
  public abstract getMaxTimeframeYears(): number;

  /**
   * Perform source-specific health check - must be implemented by subclasses
   */
  protected abstract performHealthCheck(): Promise<boolean>;

  /**
   * Make a reliable HTTP request with retry logic and circuit breaker protection
   */
  protected async makeReliableRequest(
    url: string, 
    options: RequestInit = {},
    serviceName?: string
  ): Promise<Response> {
    // Check circuit breaker
    if (this.circuitBreaker.isOpen) {
      throw new Error(`Circuit breaker open for ${this.sourceName}`);
    }

    // Check rate limits
    const rateLimitStatus = await this.getRateLimitStatus();
    if (rateLimitStatus.isLimited) {
      throw new Error(`Rate limited: ${rateLimitStatus.remainingRequests} requests remaining`);
    }

    const requestOptions: RequestInit = {
      ...options,
      headers: {
        'User-Agent': this.config.userAgent,
        'Accept': 'application/json',
        ...options.headers
      },
      signal: AbortSignal.timeout(this.config.timeout)
    };

    let lastError: Error | null = null;

    for (let attempt = 0; attempt < this.config.retryAttempts; attempt++) {
      try {
        console.debug(`${this.sourceName}: Request attempt ${attempt + 1}/${this.config.retryAttempts}: ${url}`);
        
        const response = await fetch(url, requestOptions);
        
        // Record successful request for rate limiting
        this.recordRequest();
        
        if (response.ok) {
          this.resetCircuitBreaker();
          return response;
        } else if (response.status === 429) {
          // Rate limiting
          const retryAfter = response.headers.get('retry-after');
          const waitTime = retryAfter ? parseInt(retryAfter) * 1000 : this.config.retryDelay * Math.pow(2, attempt);
          console.warn(`${this.sourceName}: Rate limited, waiting ${waitTime}ms`);
          await this.delay(waitTime);
          continue;
        } else if (response.status >= 500) {
          // Server error - retry
          throw new Error(`Server error: ${response.status} ${response.statusText}`);
        } else {
          // Client error - don't retry
          throw new Error(`Client error: ${response.status} ${response.statusText}`);
        }
      } catch (error) {
        lastError = error as Error;
        console.warn(`${this.sourceName}: Request failed on attempt ${attempt + 1}:`, error);

        if (attempt === this.config.retryAttempts - 1) {
          this.recordFailure();
          throw lastError;
        }

        // Wait before retry with exponential backoff
        const delayMs = this.config.retryDelay * Math.pow(2, attempt);
        await this.delay(delayMs);
      }
    }

    throw lastError || new Error('Request failed after all retry attempts');
  }

  /**
   * Parse date from various formats commonly found in CVE data
   */
  protected parseDate(dateStr: string | null | undefined): Date {
    if (!dateStr) return new Date();
    
    // Handle various date formats
    const formats = [
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/, // ISO format
      /^\d{4}-\d{2}-\d{2}/, // Date only
      /^\d{2}\/\d{2}\/\d{4}/, // MM/DD/YYYY
      /^\d{1,2}-\w{3}-\d{4}/ // DD-MMM-YYYY
    ];

    try {
      return new Date(dateStr);
    } catch (error) {
      console.warn(`Failed to parse date: ${dateStr}, using current date`);
      return new Date();
    }
  }

  /**
   * Normalize severity values from different sources
   */
  protected normalizeSeverity(severity: string | null | undefined): string {
    if (!severity) return 'UNKNOWN';
    
    const normalized = severity.toUpperCase().trim();
    
    // Map various severity formats to standard values
    const severityMap: Record<string, string> = {
      'CRIT': 'CRITICAL',
      'HIGH': 'HIGH',
      'MED': 'MEDIUM',
      'MEDIUM': 'MEDIUM',
      'LOW': 'LOW',
      'INFO': 'LOW',
      'INFORMATIONAL': 'LOW',
      'NONE': 'LOW'
    };

    return severityMap[normalized] || normalized;
  }

  /**
   * Extract CVE ID from text using regex
   */
  protected extractCveId(text: string): string | null {
    const cvePattern = /CVE-\d{4}-\d{4,}/i;
    const match = text.match(cvePattern);
    return match ? match[0].toUpperCase() : null;
  }

  /**
   * Clean and normalize description text
   */
  protected cleanDescription(description: string | null | undefined): string {
    if (!description) return 'No description available';
    
    return description
      .replace(/\s+/g, ' ') // Normalize whitespace
      .replace(/[\r\n\t]/g, ' ') // Remove line breaks and tabs
      .trim()
      .substring(0, 2000); // Limit length
  }

  /**
   * Convert CVSS score string to number
   */
  protected parseCvssScore(score: string | number | null | undefined): number | null {
    if (score === null || score === undefined) return null;
    
    if (typeof score === 'number') {
      return Math.max(0, Math.min(10, score)); // Clamp between 0 and 10
    }
    
    const parsed = parseFloat(String(score));
    return isNaN(parsed) ? null : Math.max(0, Math.min(10, parsed));
  }

  /**
   * Build search query variations for better coverage
   */
  protected buildSearchQueries(options: CveDiscoveryOptions): string[] {
    const queries: string[] = [];
    
    // Base timeframe query
    if (options.timeframeYears) {
      const startYear = new Date().getFullYear() - options.timeframeYears;
      queries.push(`published:${startYear}-*`);
    }

    // Severity-based queries
    if (options.severities && options.severities.length > 0) {
      for (const severity of options.severities) {
        queries.push(`severity:${severity.toLowerCase()}`);
      }
    }

    // Technology-based queries
    if (options.technologies && options.technologies.length > 0) {
      for (const tech of options.technologies) {
        queries.push(`${tech}`);
      }
    }

    // Keyword-based queries
    if (options.keywords && options.keywords.length > 0) {
      queries.push(...options.keywords);
    }

    // Default query if no specific criteria
    if (queries.length === 0) {
      queries.push('CVE-'); // Generic CVE search
    }

    return queries;
  }

  // Circuit breaker methods
  private recordFailure(): void {
    this.circuitBreaker.failures++;
    this.circuitBreaker.lastFailure = Date.now();
    
    if (this.circuitBreaker.failures >= this.circuitBreaker.threshold) {
      this.circuitBreaker.isOpen = true;
      console.warn(`Circuit breaker opened for ${this.sourceName} after ${this.circuitBreaker.failures} failures`);
    }
  }

  private resetCircuitBreaker(): void {
    this.circuitBreaker.failures = 0;
    this.circuitBreaker.isOpen = false;
  }

  // Rate limiting methods
  private updateRateLimitWindow(): void {
    const now = Date.now();
    if (now - this.rateLimitState.windowStart >= this.rateLimitState.windowSize) {
      this.rateLimitState.windowStart = now;
      this.rateLimitState.requestCount = 0;
    }
  }

  private recordRequest(): void {
    this.updateRateLimitWindow();
    this.rateLimitState.requestCount++;
  }

  // Utility methods
  protected delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}