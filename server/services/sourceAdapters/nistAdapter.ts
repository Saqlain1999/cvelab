import { BaseSourceAdapter } from './baseSourceAdapter';
import { RawCveData, CveDiscoveryOptions } from '../multiSourceCveDiscoveryService';
import { startOfDay, endOfDay, addDays } from 'date-fns';

/**
 * NIST NVD Adapter - Direct integration with NIST National Vulnerability Database
 * This is our most reliable source for comprehensive CVE data
 */
export class NistAdapter extends BaseSourceAdapter {
  readonly sourceName = 'nist';
  readonly displayName = 'NIST NVD';
  readonly baseUrl = 'https://services.nvd.nist.gov';
  readonly reliabilityScore = 0.98; // Highest reliability - official source

  private readonly apiBaseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

  constructor() {
    super();
    // NIST specific configuration
    this.config.maxResultsPerPage = 2000; // NIST allows up to 2000 per request
    this.rateLimitState.maxRequests = 50; // Conservative rate limiting
    this.config.timeout = 60000; // Longer timeout for NIST API
  }

  public supportsHistoricalData(): boolean {
    return true; // Complete historical coverage
  }

  public supportsRealTimeUpdates(): boolean {
    return true; // Updated regularly
  }

  public getMaxTimeframeYears(): number {
    return 25; // Covers all CVEs since NVD started
  }

  public async discoverCves(options: CveDiscoveryOptions): Promise<RawCveData[]> {
    console.log(`NIST: Starting discovery with ${options.timeframeYears} year timeframe`);
    
    const allCves: RawCveData[] = [];
    
    try {
      // Use custom dates if provided, else calculate from timeframe
      let endDate: Date;
      let startDate: Date;
      
      if (options.startDate && options.endDate) {
        startDate = startOfDay(new Date(options.startDate));
        endDate = endOfDay(new Date(options.endDate));
        console.log(`NIST: Using custom date range ${startDate.toISOString().split('T')[0]} to ${endDate.toISOString().split('T')[0]}`);
      } else {
        endDate = endOfDay(new Date());
        startDate = startOfDay(new Date());
        startDate.setFullYear(startDate.getFullYear() - options.timeframeYears);
        console.log(`NIST: Calculated date range ${startDate.toISOString().split('T')[0]} to ${endDate.toISOString().split('T')[0]}`);
      }
      
      // NIST API has a 120-day limit per request, so chunk it
      const maxDaysPerRequest = 120;
      let currentStart = startDate;
      
      while (currentStart < endDate) {
        const currentEnd = endOfDay(addDays(currentStart, maxDaysPerRequest));
        if (currentEnd > endDate) {
          currentEnd.setTime(endDate.getTime());
        }
        
        console.log(`NIST: Fetching chunk from ${currentStart.toISOString().split('T')[0]} to ${currentEnd.toISOString().split('T')[0]}`);
        
        try {
          const chunkCves = await this.fetchCveChunk(currentStart, currentEnd, options);
          allCves.push(...chunkCves);
          
          // Small delay between requests to respect rate limits
          await this.delay(2000);
          
        } catch (error) {
          console.warn(`NIST: Failed to fetch chunk ${currentStart.toISOString()} to ${currentEnd.toISOString()}:`, error);
        }
        
        // Move to next chunk (add 1 day overlap to avoid gaps)
        currentStart = addDays(currentEnd, 1);
        if (currentStart >= endDate) break;
      }

      console.log(`NIST: Discovered ${allCves.length} CVEs`);
      return this.filterAndLimitResults(allCves, options);

    } catch (error) {
      console.error('NIST: Discovery failed:', error);
      return [];
    }
  }

  public async getCveDetails(cveId: string): Promise<RawCveData | null> {
    try {
      console.log(`NIST: Fetching details for ${cveId}`);
      
      const params = new URLSearchParams({
        cveId: cveId
      });

      const response = await this.makeReliableRequest(`${this.apiBaseUrl}?${params}`);
      
      if (!response.ok) {
        throw new Error(`NIST API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      
      if (data.vulnerabilities && data.vulnerabilities.length > 0) {
        return this.transformNistVulnerability(data.vulnerabilities[0].cve);
      }

      return null;

    } catch (error) {
      console.error(`NIST: Failed to get details for ${cveId}:`, error);
      return null;
    }
  }

  protected async performHealthCheck(): Promise<boolean> {
    try {
      // Test with a simple query for recent CVEs
      const testDate = new Date();
      testDate.setDate(testDate.getDate() - 7); // Last 7 days
      
      const params = new URLSearchParams({
        pubStartDate: testDate.toISOString(),
        pubEndDate: new Date().toISOString(),
        resultsPerPage: '1'
      });

      const response = await this.makeReliableRequest(`${this.apiBaseUrl}?${params}`);
      return response.status === 200;
    } catch (error) {
      console.warn('NIST: Health check failed:', error);
      return false;
    }
  }

  private async fetchCveChunk(startDate: Date, endDate: Date, options: CveDiscoveryOptions): Promise<RawCveData[]> {
    const params = new URLSearchParams({
        pubStartDate: startDate.toISOString().split('.')[0] + '.000Z',
        pubEndDate: endDate.toISOString().split('.')[0] + '.000Z',
        resultsPerPage: '2000'
      });

    // Start with basic request, then add filters incrementally
    console.log(`NIST: Fetching CVEs from ${params.get('pubStartDate')} to ${params.get('pubEndDate')}`);

    const response = await this.makeReliableRequest(`${this.apiBaseUrl}?${params}`);
    
    if (!response.ok) {
      throw new Error(`NIST API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    console.log(`NIST: Found ${data.totalResults || 0} total results in chunk, returning ${data.vulnerabilities?.length || 0} CVEs`);
    
    if (data.vulnerabilities) {
      let rawCves = data.vulnerabilities.map((vuln: any) => this.transformNistVulnerability(vuln.cve));
      
      // Apply client-side filtering for better control
      return this.applyClientSideFiltering(rawCves, options);
    }

    return [];
  }

  private applyClientSideFiltering(cves: RawCveData[], options: CveDiscoveryOptions): RawCveData[] {
    let filtered = cves;

    // Filter by severity
    if (options.severities && options.severities.length > 0) {
      filtered = filtered.filter(cve => 
        options.severities!.includes(cve.severity.toUpperCase()) ||
        (cve.cvssScore && cve.cvssScore >= 7.0) // High/Critical by score
      );
    }

    // Filter by keywords
    if (options.keywords && options.keywords.length > 0) {
      filtered = filtered.filter(cve => {
        const searchText = `${cve.description} ${cve.affectedProducts?.join(' ') || ''}`.toLowerCase();
        return options.keywords!.some(keyword => 
          searchText.includes(keyword.toLowerCase())
        );
      });
    }

    // Filter by technologies
    if (options.technologies && options.technologies.length > 0) {
      filtered = filtered.filter(cve => {
        const searchText = `${cve.description} ${cve.affectedProducts?.join(' ') || ''}`.toLowerCase();
        return options.technologies!.some(tech => 
          searchText.includes(tech.toLowerCase())
        );
      });
    }

    // Prioritize lab-suitable CVEs
    const labSuitable = filtered.filter(cve => cve.sourceMetadata?.isLabSuitable);
    const others = filtered.filter(cve => !cve.sourceMetadata?.isLabSuitable);
    
    return [...labSuitable, ...others];
  }

  private transformNistVulnerability(cve: any): RawCveData {
    const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV3?.[0] || cve.metrics?.cvssMetricV2?.[0];
    const description = cve.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No description available';
    
    // Extract affected products from CPE configurations
    const affectedProducts = this.extractAffectedProducts(cve);
    
    // Determine if this CVE is lab-suitable based on CPE and description
    const isLabSuitable = this.assessLabSuitability(cve, description, affectedProducts);
    
    return {
      cveId: cve.id,
      source: this.sourceName,
      sourceUrl: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
      description: this.cleanDescription(description),
      publishedDate: this.parseDate(cve.published),
      lastModifiedDate: this.parseDate(cve.lastModified),
      cvssScore: this.parseCvssScore(metrics?.cvssData?.baseScore) ?? undefined,
      cvssVector: metrics?.cvssData?.vectorString || null,
      severity: this.normalizeSeverity(metrics?.cvssData?.baseSeverity) || 'UNKNOWN',
      affectedProducts: affectedProducts.length > 0 ? affectedProducts : undefined,
      references: cve.references?.map((ref: any) => ref.url) || [],
      cweIds: cve.weaknesses?.map((w: any) => w.description?.[0]?.value).filter(Boolean) || [],
      attackVector: metrics?.cvssData?.attackVector || undefined,
      sourceMetadata: {
        nistOfficial: true,
        hasNvdMetrics: !!metrics,
        attackVector: metrics?.cvssData?.attackVector,
        attackComplexity: metrics?.cvssData?.attackComplexity,
        userInteraction: metrics?.cvssData?.userInteraction,
        privilegesRequired: metrics?.cvssData?.privilegesRequired,
        isLabSuitable: isLabSuitable,
        labSuitabilityReasons: this.getLabSuitabilityReasons(cve, description, affectedProducts),
        extractionDate: new Date().toISOString(),
        totalResults: cve.totalResults || 1
      },
      rawData: {
        nistVulnerability: cve
      }
    };
  }

  private extractAffectedProducts(cve: any): string[] {
    const products = new Set<string>();
    
    try {
      if (cve.configurations) {
        for (const config of cve.configurations) {
          if (config.nodes) {
            for (const node of config.nodes) {
              if (node.cpeMatch) {
                for (const cpeMatch of node.cpeMatch) {
                  if (cpeMatch.criteria) {
                    // Parse CPE format: cpe:2.3:a:vendor:product:version
                    const cpeParts = cpeMatch.criteria.split(':');
                    if (cpeParts.length >= 5) {
                      const vendor = cpeParts[3];
                      const product = cpeParts[4];
                      if (vendor && product && vendor !== '*' && product !== '*') {
                        products.add(`${vendor}:${product}`);
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    } catch (error) {
      console.warn('NIST: Failed to extract affected products:', error);
    }
    
    return Array.from(products);
  }

  private assessLabSuitability(cve: any, description: string, affectedProducts: string[]): boolean {
    // Lab-suitable technologies and patterns
    const labTechnologies = [
      'apache', 'nginx', 'wordpress', 'drupal', 'joomla', 'mysql', 'postgresql',
      'php', 'nodejs', 'django', 'laravel', 'tomcat', 'jenkins', 'gitlab',
      'phpmyadmin', 'adminer', 'grafana', 'elasticsearch', 'redis', 'mongodb'
    ];
    
    const labKeywords = [
      'remote code execution', 'sql injection', 'cross-site scripting', 'xss',
      'path traversal', 'file upload', 'arbitrary file', 'command injection',
      'authentication bypass', 'privilege escalation', 'deserialization'
    ];
    
    const descLower = description.toLowerCase();
    
    // Check for lab-suitable technologies
    const hasLabTech = affectedProducts.some(product => 
      labTechnologies.some(tech => product.toLowerCase().includes(tech))
    ) || labTechnologies.some(tech => descLower.includes(tech));
    
    // Check for exploitable vulnerability types
    const hasLabKeywords = labKeywords.some(keyword => descLower.includes(keyword));
    
    // Check CVSS metrics for network accessibility
    const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV3?.[0];
    const isNetworkAccessible = metrics?.cvssData?.attackVector === 'NETWORK';
    const lowComplexity = metrics?.cvssData?.attackComplexity === 'LOW';
    const noUserInteraction = metrics?.cvssData?.userInteraction === 'NONE';
    
    return hasLabTech && (hasLabKeywords || (isNetworkAccessible && lowComplexity && noUserInteraction));
  }

  private getLabSuitabilityReasons(cve: any, description: string, affectedProducts: string[]): string[] {
    const reasons: string[] = [];
    
    // Check what makes this CVE lab-suitable
    const descLower = description.toLowerCase();
    
    if (affectedProducts.some(p => p.includes('apache'))) reasons.push('Affects Apache web server');
    if (affectedProducts.some(p => p.includes('nginx'))) reasons.push('Affects Nginx web server');
    if (affectedProducts.some(p => p.includes('wordpress'))) reasons.push('Affects WordPress CMS');
    if (affectedProducts.some(p => p.includes('mysql'))) reasons.push('Affects MySQL database');
    
    if (descLower.includes('remote code execution')) reasons.push('Remote code execution vulnerability');
    if (descLower.includes('sql injection')) reasons.push('SQL injection vulnerability');
    if (descLower.includes('cross-site scripting') || descLower.includes('xss')) reasons.push('XSS vulnerability');
    if (descLower.includes('path traversal')) reasons.push('Path traversal vulnerability');
    
    const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV3?.[0];
    if (metrics?.cvssData?.attackVector === 'NETWORK') reasons.push('Network accessible');
    if (metrics?.cvssData?.attackComplexity === 'LOW') reasons.push('Low attack complexity');
    if (metrics?.cvssData?.userInteraction === 'NONE') reasons.push('No user interaction required');
    
    return reasons;
  }

  private filterAndLimitResults(cves: RawCveData[], options: CveDiscoveryOptions): RawCveData[] {
    let filtered = cves;
    
    // Filter by severity if specified
    if (options.severities && options.severities.length > 0) {
      filtered = filtered.filter(cve => 
        options.severities!.includes(cve.severity) || cve.severity === 'UNKNOWN'
      );
    }
    
    // Filter by keywords if specified
    if (options.keywords && options.keywords.length > 0) {
      filtered = filtered.filter(cve => {
        const searchText = `${cve.description} ${cve.affectedProducts?.join(' ') || ''}`.toLowerCase();
        return options.keywords!.some(keyword => 
          searchText.includes(keyword.toLowerCase())
        );
      });
    }
    
    // Prioritize lab-suitable CVEs
    filtered.sort((a, b) => {
      const aLabSuitable = a.sourceMetadata?.isLabSuitable ? 1 : 0;
      const bLabSuitable = b.sourceMetadata?.isLabSuitable ? 1 : 0;
      return bLabSuitable - aLabSuitable; // Lab-suitable first
    });
    
    // Limit results
    const maxResults = options.maxResultsPerSource || 500;
    return filtered.slice(0, maxResults);
  }

}