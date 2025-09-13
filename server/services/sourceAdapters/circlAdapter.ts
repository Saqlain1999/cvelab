import { BaseSourceAdapter } from './baseSourceAdapter';
import { RawCveData, CveDiscoveryOptions } from '../multiSourceCveDiscoveryService';

/**
 * CIRCL CVE Search Adapter - Integrates with cve.circl.lu
 * Alternative CVE search API with good performance and free access
 */
export class CirclAdapter extends BaseSourceAdapter {
  readonly sourceName = 'circl';
  readonly displayName = 'CIRCL CVE Search';
  readonly baseUrl = 'https://cve.circl.lu/api';
  readonly reliabilityScore = 0.75; // Good alternative source

  constructor() {
    super();
    // CIRCL API configuration
    this.config.maxResultsPerPage = 100;
    this.rateLimitState.maxRequests = 200; // Generous rate limits
  }

  public supportsHistoricalData(): boolean {
    return true; // Good historical coverage
  }

  public supportsRealTimeUpdates(): boolean {
    return true; // Updated regularly
  }

  public getMaxTimeframeYears(): number {
    return 25; // Excellent historical coverage
  }

  public async discoverCves(options: CveDiscoveryOptions): Promise<RawCveData[]> {
    console.log(`CIRCL: Starting discovery with ${options.timeframeYears} year timeframe`);
    
    const allCves: RawCveData[] = [];
    
    try {
      // CIRCL search by timeframe
      const timeframeCves = await this.searchByTimeframe(options);
      allCves.push(...timeframeCves);

      // Search by specific technologies if provided
      if (options.technologies && options.technologies.length > 0) {
        for (const technology of options.technologies.slice(0, 3)) {
          try {
            const techCves = await this.searchByTechnology(technology, options);
            allCves.push(...techCves);
            await this.delay(500); // Small delay between searches
          } catch (error) {
            console.warn(`CIRCL: Failed to search for technology ${technology}:`, error);
          }
        }
      }

      // Browse latest CVEs for recent coverage
      try {
        const latestCves = await this.browseLatestCves(options);
        allCves.push(...latestCves);
      } catch (error) {
        console.warn('CIRCL: Failed to browse latest CVEs:', error);
      }

      console.log(`CIRCL: Discovered ${allCves.length} CVEs`);
      return this.deduplicateResults(allCves);

    } catch (error) {
      console.error('CIRCL: Discovery failed:', error);
      return [];
    }
  }

  public async getCveDetails(cveId: string): Promise<RawCveData | null> {
    try {
      console.log(`CIRCL: Fetching details for ${cveId}`);
      
      const detailUrl = `${this.baseUrl}/cve/${cveId}`;
      
      const response = await this.makeReliableRequest(detailUrl);
      
      if (!response.ok) {
        if (response.status === 404) {
          console.warn(`CIRCL: CVE ${cveId} not found`);
          return null;
        }
        throw new Error(`CIRCL API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      return this.transformCirclCve(data);

    } catch (error) {
      console.error(`CIRCL: Failed to get details for ${cveId}:`, error);
      return null;
    }
  }

  protected async performHealthCheck(): Promise<boolean> {
    try {
      const response = await this.makeReliableRequest(`${this.baseUrl}/dbInfo`);
      const data = await response.json();
      return response.ok && data.dbversion !== undefined;
    } catch (error) {
      return false;
    }
  }

  private async searchByTimeframe(options: CveDiscoveryOptions): Promise<RawCveData[]> {
    try {
      const endDate = new Date();
      const startDate = new Date();
      startDate.setFullYear(startDate.getFullYear() - options.timeframeYears);

      // CIRCL uses time range in their browse API
      const limit = Math.min(options.maxResultsPerSource || 1000, 1000); // CIRCL has limits
      const searchUrl = `${this.baseUrl}/browse/${Math.floor(limit / 100)}`; // Pages of ~100 items
      
      console.log(`CIRCL: Browsing timeframe CVEs with limit ${limit}`);

      const response = await this.makeReliableRequest(searchUrl);
      
      if (!response.ok) {
        throw new Error(`CIRCL API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      
      if (data && typeof data === 'object') {
        const cves: RawCveData[] = [];
        
        // CIRCL browse returns an object with CVE IDs as keys
        for (const [cveId, cveData] of Object.entries(data)) {
          if (cveId.startsWith('CVE-')) {
            try {
              const transformedCve = this.transformCirclCve(cveData, cveId);
              
              // Filter by timeframe
              if (this.isWithinTimeframe(transformedCve.publishedDate, startDate, endDate)) {
                cves.push(transformedCve);
              }
            } catch (error) {
              console.warn(`CIRCL: Failed to transform CVE ${cveId}:`, error);
            }
          }
        }
        
        console.log(`CIRCL: Found ${cves.length} CVEs in timeframe browse`);
        return cves;
      }

      return [];

    } catch (error) {
      console.error('CIRCL: Timeframe search failed:', error);
      return [];
    }
  }

  private async searchByTechnology(technology: string, options: CveDiscoveryOptions): Promise<RawCveData[]> {
    try {
      // CIRCL search API
      const searchUrl = `${this.baseUrl}/search/${encodeURIComponent(technology)}`;
      
      console.log(`CIRCL: Searching for technology: ${technology}`);

      const response = await this.makeReliableRequest(searchUrl);
      
      if (!response.ok) {
        throw new Error(`CIRCL API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      
      if (data && typeof data === 'object') {
        const cves: RawCveData[] = [];
        
        for (const [cveId, cveData] of Object.entries(data)) {
          if (cveId.startsWith('CVE-')) {
            try {
              const transformedCve = this.transformCirclCve(cveData, cveId);
              cves.push(transformedCve);
            } catch (error) {
              console.warn(`CIRCL: Failed to transform search result ${cveId}:`, error);
            }
          }
        }
        
        console.log(`CIRCL: Found ${cves.length} CVEs for technology ${technology}`);
        return cves.slice(0, 100); // Limit technology search results
      }

      return [];

    } catch (error) {
      console.error(`CIRCL: Technology search failed for ${technology}:`, error);
      return [];
    }
  }

  private async browseLatestCves(options: CveDiscoveryOptions): Promise<RawCveData[]> {
    try {
      const latestUrl = `${this.baseUrl}/last/30`; // Get last 30 CVEs
      
      console.log('CIRCL: Browsing latest CVEs');

      const response = await this.makeReliableRequest(latestUrl);
      
      if (!response.ok) {
        throw new Error(`CIRCL API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      
      if (data && typeof data === 'object') {
        const cves: RawCveData[] = [];
        
        for (const [cveId, cveData] of Object.entries(data)) {
          if (cveId.startsWith('CVE-')) {
            try {
              const transformedCve = this.transformCirclCve(cveData, cveId);
              cves.push(transformedCve);
            } catch (error) {
              console.warn(`CIRCL: Failed to transform latest CVE ${cveId}:`, error);
            }
          }
        }
        
        console.log(`CIRCL: Found ${cves.length} latest CVEs`);
        return cves;
      }

      return [];

    } catch (error) {
      console.error('CIRCL: Latest CVEs browse failed:', error);
      return [];
    }
  }

  private transformCirclCve(cveData: any, cveId?: string): RawCveData {
    // CIRCL CVE data structure
    const id = cveId || cveData.id || 'UNKNOWN';
    
    // Parse CVSS information
    let cvssScore: number | null = null;
    let severity = 'UNKNOWN';
    
    if (cveData.cvss) {
      cvssScore = this.parseCvssScore(cveData.cvss);
      severity = this.deriveSeverityFromScore(cvssScore);
    } else if (cveData.impact) {
      // Some CIRCL entries have impact instead of CVSS
      severity = this.normalizeSeverity(cveData.impact);
    }

    // Extract references
    const references: string[] = [];
    if (cveData.references) {
      if (Array.isArray(cveData.references)) {
        references.push(...cveData.references);
      } else if (typeof cveData.references === 'string') {
        references.push(cveData.references);
      } else if (typeof cveData.references === 'object') {
        // CIRCL sometimes has structured references
        for (const [key, value] of Object.entries(cveData.references)) {
          if (typeof value === 'string' && value.startsWith('http')) {
            references.push(value);
          }
        }
      }
    }

    // Extract affected vendors/products
    const affectedProducts: string[] = [];
    if (cveData.vendors) {
      if (Array.isArray(cveData.vendors)) {
        affectedProducts.push(...cveData.vendors);
      } else if (typeof cveData.vendors === 'object') {
        affectedProducts.push(...Object.keys(cveData.vendors));
      }
    }

    // Parse dates
    const publishedDate = this.parseDate(cveData.Published || cveData.published || cveData.Modified);
    const modifiedDate = this.parseDate(cveData.Modified || cveData.modified || cveData.Published);

    const cve: RawCveData = {
      cveId: id,
      source: this.sourceName,
      sourceUrl: `https://cve.circl.lu/cve/${id}`,
      description: this.cleanDescription(cveData.summary || cveData.Summary || 'No description available'),
      publishedDate: publishedDate || new Date(),
      lastModifiedDate: modifiedDate || publishedDate || new Date(),
      cvssScore: cvssScore,
      severity: severity,
      affectedProducts: affectedProducts.length > 0 ? affectedProducts : undefined,
      references: references.length > 0 ? references : undefined,
      sourceMetadata: {
        circlId: cveData.id,
        hasImpactData: !!cveData.impact,
        hasCvssData: !!cveData.cvss,
        hasVendorData: !!cveData.vendors,
        extractionDate: new Date().toISOString(),
        circlDataStructure: Object.keys(cveData).join(',')
      },
      rawData: {
        circlCveData: cveData
      }
    };

    return cve;
  }

  private deriveSeverityFromScore(score: number | null): string {
    if (!score) return 'UNKNOWN';
    
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    return 'LOW';
  }

  private isWithinTimeframe(date: Date, startDate: Date, endDate: Date): boolean {
    return date >= startDate && date <= endDate;
  }

  private deduplicateResults(cves: RawCveData[]): RawCveData[] {
    const seen = new Set<string>();
    const deduplicated: RawCveData[] = [];
    
    for (const cve of cves) {
      if (!seen.has(cve.cveId)) {
        seen.add(cve.cveId);
        deduplicated.push(cve);
      }
    }
    
    return deduplicated;
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}